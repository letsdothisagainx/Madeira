int ios_store_split_crossing( uint32_t insn, arm_thread_state64_t *st,
                                     const arm_neon_state64_t *neon,
                                     uintptr_t rx, uintptr_t rw, size_t sz )
{
    extern uintptr_t ios_jit_anon_alias_lookup( uintptr_t fault_addr );
    extern void ios_jit_anon_alias_note_write( unsigned long long );
    const unsigned rt = insn & 31, rn = (insn >> 5) & 31, size = insn >> 30, v = (insn >> 26) & 1;
    const unsigned opc = (insn >> 22) & 3;
    const uint64_t base = rn == 31 ? st->__sp : rn == 30 ? st->__lr : rn == 29 ? st->__fp : st->__x[rn];
    const int honor_guest_prot = !ios_jit_pool_pc_is_fex( arm_thread_state64_get_pc( *st ) );
    uint8_t src[32];
    uint64_t ea, a, x0, x1;
    int64_t imm = 0;
    int wb = 0, pair = 0;
    unsigned bytes, elem, rt2 = (insn >> 10) & 31, parts = 0, done = 0, i, part_len[2];
    uintptr_t part_rw[2];

    if ((insn & 0x3a000000u) == 0x28000000u)                    /* STP/STNP and SIMD&FP pairs */
    {
        const unsigned mode = (insn >> 23) & 3;              /* 0 stnp, 1 post, 2 offset, 3 pre */
        if ((insn >> 22) & 1) return 0;                      /* loads */
        if (v) elem = size == 3 ? 0 : 4u << size;            /* S, D, Q */
        else   elem = size == 0 ? 4 : size == 2 ? 8 : 0;     /* W, X (01 is STGP) */
        if (!elem) return 0;
        imm = ((int64_t)((insn >> 15) & 0x7f) - ((insn & (1u << 21)) ? 128 : 0)) * (int64_t)elem;
        ea = mode == 1 ? base : base + (uint64_t)imm;
        wb = mode == 1 || mode == 3;
        bytes = 2 * elem;
        pair = 1;
    }
    else if ((insn & 0x3b000000u) == 0x38000000u || (insn & 0x3b000000u) == 0x39000000u)
    {
        /* single-register LDR/STR families: a store has opc 00 (GPR) or opc<0> = 0 (SIMD&FP) */
        if (v ? (opc & 1) : opc != 0) return 0;
        elem = v && (opc & 2) ? (size == 0 ? 16u : 0u) : 1u << size;
        if (!elem) return 0;
        if ((insn & 0x3b000000u) == 0x39000000u)                 /* unsigned offset */
            ea = base + ((uint64_t)((insn >> 10) & 0xfff) * elem);
        else if ((insn & 0x00200c00u) == 0x00200800u)            /* register offset */
        {
            const unsigned option = (insn >> 13) & 7, rm = (insn >> 16) & 31;
            uint64_t off = rm == 31 ? 0 : rm == 30 ? st->__lr : rm == 29 ? st->__fp : st->__x[rm];
            if (!(option & 2)) return 0;
            if (option == 2) off = (uint32_t)off;
            else if (option == 6) off = (uint64_t)(int64_t)(int32_t)off;
            if (insn & 0x1000) off *= elem;
            ea = base + off;
        }
        else if (!(insn & 0x00200000u))                          /* unscaled, post, pre */
        {
            const unsigned idx = (insn >> 10) & 3;
            if (idx == 2) return 0;                                /* unprivileged */
            imm = (int64_t)((insn >> 12) & 0x1ff) - ((insn & (1u << 20)) ? 512 : 0);
            ea = idx == 1 ? base : base + (uint64_t)imm;
            wb = idx == 1 || idx == 3;
        }
        else return 0;
        bytes = elem;
    }
    else return 0;

    if (ea > UINTPTR_MAX - (bytes - 1)) return -1;
    if (ios_jit_code_guard_contains( (uintptr_t)ea, bytes )) return -1;
    if (((ea ^ (ea + bytes - 1)) & ~(uint64_t)0x3fff) == 0) return 0;   /* within one page */
    if (v && !neon) return 0;

    if (v)
    {
        memcpy( src, &neon->__v[rt], elem );
        if (pair) memcpy( src + elem, &neon->__v[rt2], elem );
    }
    else
    {
        x0 = rt == 31 ? 0 : rt == 30 ? st->__lr : rt == 29 ? st->__fp : st->__x[rt];
        x1 = rt2 == 31 ? 0 : rt2 == 30 ? st->__lr : rt2 == 29 ? st->__fp : st->__x[rt2];
        memcpy( src, &x0, elem );
        if (pair) memcpy( src + elem, &x1, elem );
    }

    while (done < bytes && parts < 2)
    {
        unsigned len = bytes - done;
        a = ea + done;
        if (len > 0x4000 - (a & 0x3fff)) len = 0x4000 - (unsigned)(a & 0x3fff);
        part_rw[parts] = (rx && rw && len <= sz && a >= rx && a - rx <= sz - len)
                         ? rw + (a - rx) : ios_write_alias( (uintptr_t)a );
        if (part_rw[parts] && (ios_write_alias( a + len - 1 ) != part_rw[parts] + len - 1 ||
            (honor_guest_prot && (ios_alias_write_is_trapped( a ) || ios_alias_write_is_trapped( a + len - 1 )))))
            return -1;
        if (!part_rw[parts])
        {
            /* A page with no alias that is plain writable memory (the aliased page is
             * the one that faulted) takes its bytes directly. */
            mach_vm_address_t ra = (mach_vm_address_t)a;
            mach_vm_size_t rs = 0;
            vm_region_basic_info_data_64_t ri;
            mach_msg_type_number_t rc = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t ro = MACH_PORT_NULL;
            if (mach_vm_region( mach_task_self(), &ra, &rs, VM_REGION_BASIC_INFO_64,
                                (vm_region_info_t)&ri, &rc, &ro ) == KERN_SUCCESS &&
                ra <= a && a + len <= ra + rs && (ri.protection & VM_PROT_WRITE))
                part_rw[parts] = (uintptr_t)a;
            if (ro != MACH_PORT_NULL) mach_port_deallocate( mach_task_self(), ro );
        }
        if (!part_rw[parts]) break;
        part_len[parts++] = len;
        done += len;
    }
    /* The recovery caller can hold the writer suspended here. Formatting can
     * acquire a libc allocator/stdio lock owned by that writer; report the
     * returned status only after the caller balances its suspension. */
    if (done != bytes) return -1;
    for (i = 0, done = 0; i < parts; done += part_len[i], i++)
    {
        memcpy( (void *)part_rw[i], src + done, part_len[i] );
        ios_jit_anon_alias_note_write( (unsigned long long)(ea + done) );
    }
    if (wb)
    {
        if (rn == 31) st->__sp = base + (uint64_t)imm;
        else if (rn == 30) st->__lr = base + (uint64_t)imm;
        else if (rn == 29) st->__fp = base + (uint64_t)imm;
        else st->__x[rn] = base + (uint64_t)imm;
    }
    return 1;
}
