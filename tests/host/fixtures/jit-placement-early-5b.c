/* Literal 5b20ed22 early reservation function. Mach calls are supplied by the regression harness. */
__attribute__((constructor(101), used)) static void madeira_early_va_claim(void)
{
    const vm_address_t win = 0x140000000ul, winsz = 0x8000000ul;       /* 128MB, see ml1037 */
    vm_address_t a = win;
    vm_size_t sz;

    if (vm_allocate(mach_task_self(), &a, winsz, VM_FLAGS_FIXED) == KERN_SUCCESS && a == win) {
        vm_protect(mach_task_self(), a, winsz, 0, VM_PROT_NONE);
        madeira_early_window_base = win; madeira_early_window_size = winsz;
    }
    /* Largest no-overwrite run starting at the window's end, 16MB granularity. */
    for (sz = 1024ul << 20; sz >= (256ul << 20); sz -= (16ul << 20)) {
        a = win + winsz;
        if (vm_allocate(mach_task_self(), &a, sz, VM_FLAGS_FIXED) == KERN_SUCCESS && a == win + winsz) {
            vm_protect(mach_task_self(), a, sz, 0, VM_PROT_NONE);
            madeira_early_pool_base = a; madeira_early_pool_size = sz;
            break;
        }
    }
    /* ml1135: NAME what blocked it. ph-rdr90 got no placeholder because a ~31MB
     * mapping already sat at ~0x157d00000 before this constructor ran, leaving
     * 253MB above the window; the pool fell back to a 432MB hole below it and FEX
     * rolled its code cache over 52 times (a ~1 s freeze each). Record the first
     * mapped region above the window so the log can say what it is.
     * madeira-bcd: also when a placeholder was obtained -- it ends where the first
     * mapping above it starts (normally the main thread's stack, VM tag 30; on
     * RDR2's build 470 run a 71MB mapping at 0x159d00000 cut it to 272MB and the
     * pool to 604MB). */
    {
        vm_address_t ra = win + winsz + (vm_address_t)madeira_early_pool_size;
        vm_size_t rs = 0;
        natural_t depth = 0;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
        if (vm_region_recurse_64(mach_task_self(), &ra, &rs, &depth, (vm_region_recurse_info_t)&info, &cnt) == KERN_SUCCESS
            && ra < 0x190000000ul) {
            madeira_early_intruder_base = ra; madeira_early_intruder_size = rs;
            madeira_early_intruder_tag = info.user_tag; madeira_early_intruder_prot = (unsigned)info.protection;
        }
    }
}
