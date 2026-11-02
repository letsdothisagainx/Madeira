/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Read-only WoW32 fault provenance. The includer supplies fault-safe
 * ios_g32_read and the guest32_origin helpers. Never call a guest callback
 * from the Mach exception thread or treat the saved frame RIP as current. */
#ifndef MADEIRA_GUEST32_FAULT_H
#define MADEIRA_GUEST32_FAULT_H

struct ios_g32_fault_block {
    uint64_t header, entry, size, saved, exact;
    uint32_t entries, walked;
};

/* Pinned CPUBackend::JITCodeTail is 40 bytes, with these fixed-width fields.
 * The host test checks the actual producer declarations and vl64pair encoder.
 * Reads and work are bounded even when a stale header points at readable data. */
static int ios_g32_fault_block(uint64_t frame, uint64_t pc, uint64_t owner,
                               struct ios_g32_fault_block *b)
{
    uint32_t offset, table_offset;
    uint64_t tail, cursor, end, host, guest, ignored;
    unsigned char bytes[17], raw[40];
    memset(b, 0, sizeof(*b));
    if (!ios_g32_fault_owned(pc,owner) ||
        !ios_g32_read(frame, &b->header, 8) || !b->header || (b->header & 3) ||
        !ios_g32_fault_owned(b->header,owner) ||
        !ios_g32_read(frame + 0x18, &b->saved, 8) ||
        !ios_g32_read(b->header, &offset, 4) || offset < 4 || offset > 0x400000 ||
        b->header > UINT64_MAX - sizeof(raw) ||
        offset > UINT64_MAX - b->header - sizeof(raw) ||
        !ios_g32_fault_owned((tail = b->header + offset) + sizeof(raw)-1,owner) ||
        !ios_g32_read(tail, raw, sizeof(raw))) return 0;
    memcpy(&b->size, raw, 8); memcpy(&b->entry, raw + 8, 8);
    memcpy(&ignored, raw + 16, 8); memcpy(&b->entries, raw + 24, 4);
    memcpy(&table_offset, raw + 28, 4);
    if (b->size > 0x400000 || b->size < offset + sizeof(raw) ||
        b->size > UINT64_MAX - b->header || b->entry > UINT32_MAX ||
        ignored > UINT32_MAX || b->entries > 4096 || table_offset < sizeof(raw) ||
        table_offset > b->size - offset || pc < b->header || pc >= b->header + offset ||
        !ios_g32_fault_owned(b->header+b->size-1,owner)) return 0;
    end = b->header + b->size; cursor = tail + table_offset;
    host = b->header; guest = b->entry;
    for (unsigned i = 0; i < b->entries; i++)
    {
        uint64_t dh, dg, next_host, next_guest;
        size_t n;
        if (cursor >= end || !ios_g32_read(cursor, bytes, 1)) return 0;
        n = !(bytes[0] & 0x80) ? 1 : (bytes[0] & 0xc0) == 0x80 ? 2 : bytes[0] == 0xc0 ? 9 : 17;
        if (n > end - cursor || (n > 1 && !ios_g32_read(cursor, bytes, n))) return 0;
        if (n == 1) { dh = ((bytes[0] & 15) + 1) * 4; dg = ((bytes[0] >> 4) & 7) + 1; }
        else if (n == 2)
        {
            dh = (uint64_t)((int64_t)(int8_t)bytes[1] * 4);
            dg = (uint64_t)((int64_t)(bytes[0] & 63) - ((bytes[0] & 32) ? 64 : 0));
        }
        else if (n == 9)
        {
            int32_t h, g; memcpy(&h, bytes + 1, 4); memcpy(&g, bytes + 5, 4);
            dh = (uint64_t)(int64_t)h; dg = (uint64_t)(int64_t)g;
        }
        else
        {
            if (bytes[0] != 0xe0) return 0;
            memcpy(&dh, bytes + 1, 8); memcpy(&dg, bytes + 9, 8);
        }
        next_host = host + dh; next_guest = guest + dg;
        /* GuestOpcodes is appended in host emission order. Equal PCs are
         * valid for zero-code guest operations; backwards PCs are not. */
        if (next_host < host || next_host >= tail || (next_host & 3) || next_guest > UINT32_MAX) return 0;
        if (pc < next_host) break;
        host = next_host; guest = next_guest; cursor += n; b->walked++;
    }
    b->exact = guest;
    return b->walked != 0;
}

/* The non-EC x32 SRA array in Arm64Emitter.cpp is EAX=x4, ECX=x7,
 * EDX=x5, EBX=x6, ESP=x8, EBP=x9, ESI=x10, EDI=x11. x19/x24 are
 * the explicitly reserved guest base/address registers, not x86 R12/R13. */
static void ios_g32_fault_report(uint64_t teb, uint64_t window, uint64_t frame,
                                uint64_t pc, uint64_t address, const uint64_t *x,
                                const struct ios_g32_fault_block *b, int have_block)
{
    static const unsigned sra[8] = {4,7,5,6,8,9,10,11};
    uint32_t native[7] = {0}, saved[8] = {0}, field = 0;
    uint64_t saved64[8] = {0};
    int native_ok = pc >= 24 && ios_g32_read(pc - 24, native, sizeof(native));
    int saved_ok = ios_g32_read(frame + 0x20, saved64, sizeof(saved64));
    struct ios_g32_origin g;
    for (unsigned i = 0; i < 8; i++) saved[i] = (uint32_t)saved64[i];
    dprintf(2,"[guest32-fault-v1] pc=%#llx fault=%#llx window=%#llx guest-address=%#llx frame=%#llx saved-rip=%#llx exact-rip=%#llx table=%s header=%#llx entry=%#llx walked=%u/%u\n",
            (unsigned long long)pc,(unsigned long long)address,(unsigned long long)window,
            (unsigned long long)(address-window),(unsigned long long)frame,
            (unsigned long long)b->saved,(unsigned long long)b->exact,have_block?"valid":"unavailable",
            (unsigned long long)b->header,(unsigned long long)b->entry,b->walked,b->entries);
    dprintf(2,"[guest32-fault-regs] live eax=%08x ecx=%08x edx=%08x ebx=%08x esp=%08x ebp=%08x esi=%08x edi=%08x base-x19=%#llx address-x24=%#llx saved=%s\n",
            (unsigned)x[sra[0]],(unsigned)x[sra[1]],(unsigned)x[sra[2]],(unsigned)x[sra[3]],
            (unsigned)x[sra[4]],(unsigned)x[sra[5]],(unsigned)x[sra[6]],(unsigned)x[sra[7]],
            (unsigned long long)x[19],(unsigned long long)x[24],saved_ok?"block-boundary":"unavailable");
    if (saved_ok) dprintf(2,"[guest32-fault-saved] eax=%08x ecx=%08x edx=%08x ebx=%08x esp=%08x ebp=%08x esi=%08x edi=%08x\n",
                         saved[0],saved[1],saved[2],saved[3],saved[4],saved[5],saved[6],saved[7]);
    if (native_ok) dprintf(2,"[guest32-fault-host] pc-24=%#llx words=%08x %08x %08x %08x %08x %08x [%08x]\n",
                          (unsigned long long)(pc-24),native[0],native[1],native[2],native[3],native[4],native[5],native[6]);
    /* Only this four-byte pointer field is sampled, never an object payload or
     * string. The predecessor's exact opcodes remain available above; a field
     * sampled after the stop is not misrepresented as an atomic load history. */
    if (x[7] >= 0x10000 && x[7] <= UINT32_MAX-4)
    {
        int ok = ios_g32_read(window+x[7]+4,&field,4);
        dprintf(2,"[guest32-fault-pointer] ecx+4=%#x sampled=%s%#x\n",(unsigned)x[7]+4,ok?"":"unreadable:",field);
    }
    if (ios_g32_capture(&g,teb,window,frame))
    {
        g.esp=(uint32_t)x[8]; g.ebp=(uint32_t)x[9];
        /* An unavailable table is not a substitute exact guest PC. */
        g.rip=have_block?(uint32_t)b->exact:0;
        ios_g32_report(&g,"first-av",0);
        if (have_block) ios_g32_code(&g,"first-av-exact",g.rip);
        uint32_t bp=g.ebp;
        for (unsigned i=0;i<4;i++)
        {
            uint32_t row[2];
            if ((bp&3) || bp<g.esp || (uint64_t)bp+8>g.high ||
                !ios_g32_guest(&g,bp,row,8)) break;
            ios_g32_callsite(&g,"first-av",i,row[1]);
            if (row[0]<=bp || row[0]-bp>0x100000) break;
            bp=row[0];
        }
    }
}
#endif
