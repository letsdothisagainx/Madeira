/* Actual production NtQueryVirtualMemory before query-specific alias lifetime checks.
 * Repository: letsdothisagainx/Madeira
 * Source: d6d40213695db7b1ab0f7a9b1dd95edbcda0d7ec:build/ntdll-unix/virtual_ios.c
 * Function SHA-256 (without this comment or final newline): 2ecf222e5dc7ead4003ea5446af24f18e29d14b3495e29d93b1a8c010fa1e16d
 * Captured verbatim; the host harness compiles the address-query branches.
 */
NTSTATUS WINAPI NtQueryVirtualMemory( HANDLE process, LPCVOID addr,
                                      MEMORY_INFORMATION_CLASS info_class,
                                      PVOID buffer, SIZE_T len, SIZE_T *res_len )
{
    NTSTATUS status;

#ifdef WINE_IOS
    if (info_class == MemoryWineIosSubfloorWindow)
    {
        extern int ios_subfloor_enum( int idx, unsigned long long *low, unsigned long long *real,
                                      unsigned long long *size, void **owner );
        static int on = -1;
        unsigned long long lo, re, sz;
        ULONG_PTR *out = buffer;
        void *peb = ios_jit_current_peb(), *own;
        int i;

        if (on < 0)
        {
            const char *e = getenv( "MADEIRA_SUBFLOOR_SEH" );   /* ml1203: 0 = no unwind data for code at a fixed-base image's low addresses */
            on = !(e && e[0] == '0');
        }
        if (!on || process != NtCurrentProcess()) return STATUS_INVALID_INFO_CLASS;
        if (len < 3 * sizeof(ULONG_PTR)) return STATUS_INFO_LENGTH_MISMATCH;
        for (i = 0; ios_subfloor_enum( i, &lo, &re, &sz, &own ); i++)
        {
            if (own && own != peb) continue;   /* ml1205 */
            if (!sz || !re || (ULONG_PTR)addr < lo || (ULONG_PTR)addr >= lo + sz) continue;
            out[0] = lo;
            out[1] = re;
            out[2] = sz;
            if (res_len) *res_len = 3 * sizeof(ULONG_PTR);
            return STATUS_SUCCESS;
        }
        return STATUS_INVALID_ADDRESS;
    }
    /* PE code in JIT pool computes addresses via ADRP relative to JIT PC.
     * Translate JIT addresses back to original PE addresses for VM queries. */
    addr = ios_jit_reverse_translate_addr(addr);
    /* ml966: VirtualQuery on a low guest allocation must describe the backing,
     * otherwise the guest sees "free" for memory it holds. */
    {
        unsigned long long lo_real = 0;
        if (ios_lowalloc_translate( (unsigned long long)(ULONG_PTR)addr, 1, &lo_real, NULL ))
        {
            static int lq_n;
            if (lq_n < 16)
            {
                lq_n++;
                dprintf( 2, "ml966: QUERY on low guest %p -> backing %#llx\n", addr, lo_real );
            }
            addr = (LPCVOID)(ULONG_PTR)lo_real;
        }
        else if (ios_subfloor_image_translate( (unsigned long long)(ULONG_PTR)addr, 1, &lo_real ))
        {
            static int sq_n;   /* ml1201: describe the sub-floor image's real mapping */
            if (sq_n++ < 16)
                dprintf( 2, "ml1201: QUERY on sub-floor image %p -> real %#llx\n", addr, lo_real );
            addr = (LPCVOID)(ULONG_PTR)lo_real;
        }
    }
#endif

    TRACE("(%p, %p, info_class=%d, %p, %ld, %p)\n",
          process, addr, info_class, buffer, len, res_len);

    switch(info_class)
    {
        case MemoryBasicInformation:
            return get_basic_memory_info( process, addr, buffer, len, res_len );

        case MemoryWorkingSetExInformation:
            return get_working_set_ex( process, addr, buffer, len, res_len );

        case MemoryMappedFilenameInformation:
            return get_memory_section_name( process, addr, buffer, len, res_len );

        case MemoryRegionInformation:
            return get_memory_region_info( process, addr, buffer, len, res_len );

        case MemoryImageInformation:
            return get_memory_image_info( process, addr, buffer, len, res_len );

        case MemoryWineLoadUnixLib:
        case MemoryWineLoadUnixLibWow64:
            if (len != sizeof(unixlib_handle_t)) return STATUS_INFO_LENGTH_MISMATCH;
            if (process == GetCurrentProcess())
            {
                void *module = (void *)addr;
                const void *funcs = NULL;

                status = load_builtin_unixlib( module, info_class == MemoryWineLoadUnixLibWow64, &funcs );
                if (!status) *(unixlib_handle_t *)buffer = (UINT_PTR)funcs;
                return status;
            }
            return STATUS_INVALID_HANDLE;

        case MemoryWineLoadUnixLibByName:
        case MemoryWineLoadUnixLibByNameWow64:
            if (process == GetCurrentProcess())
            {
                UINT64 res[2];
                const UNICODE_STRING *name = addr;
                NTSTATUS (*entry)(void);
                const void *funcs;
                void *handle;

                if ((status = load_unixlib_by_name( name, &handle )))
                {
#ifdef WINE_IOS
                    /* iOS-Madeira 2026-05-13: no .so files on iOS for audio
                     * drivers; provide static unix tables for wineios.drv
                     * (silent audio backend). Match by name; success path
                     * returns a magic non-NULL handle so subsequent
                     * MemoryWineUnloadUnixLib doesn't crash. */
                    char ascii[64] = {0};
                    unsigned int nlen = name->Length / sizeof(WCHAR);
                    if (nlen > 0 && nlen < sizeof(ascii))
                    {
                        for (unsigned int i = 0; i < nlen; i++)
                            ascii[i] = (char)(name->Buffer[i] & 0x7f);
                        ascii[nlen] = 0;
                        /* lowercase for substr matching */
                        for (char *p = ascii; *p; p++)
                            if (*p >= 'A' && *p <= 'Z') *p += 'a' - 'A';
                        if (strstr(ascii, "wineios") || strstr(ascii, "winecoreaudio") ||
                            strstr(ascii, "winealsa") || strstr(ascii, "winepulse") ||
                            strstr(ascii, "wineoss"))
                        {
                            /* a 32-bit mmdevapi reaches this as ...ByNameWow64 and
                             * gets the table that reads 32-bit argument blocks */
                            BOOL wow = (info_class == MemoryWineLoadUnixLibByNameWow64);
                            ERR("iOS: MemoryWineLoadUnixLibByName %s -> audio_null_ios %s table\n",
                                ascii, wow ? "wow64" : "64-bit");
                            res[0] = (UINT64)(UINT_PTR)1; /* magic non-NULL handle */
                            res[1] = (UINT64)(UINT_PTR)(wow ? (const void *)audio_null_ios_unix_call_wow64_funcs
                                                            : (const void *)audio_null_ios_unix_call_funcs);
                            memcpy( buffer, res, min( len, sizeof(res) ));
                            return STATUS_SUCCESS;
                        }
                    }
#endif
                    return status;
                }
                res[0] = (UINT_PTR)handle;
                if (!(status = get_unixlib_funcs( handle, info_class == MemoryWineLoadUnixLibByNameWow64,
                                                  &funcs, &entry )))
                {
                    res[1] = (UINT_PTR)funcs;
                    if (entry) status = entry();
                }
                if (status) dlclose( handle );
                else memcpy( buffer, res, min( len, sizeof(res) ));
                return status;
            }
            return STATUS_INVALID_HANDLE;

        case MemoryWineUnloadUnixLib:
            if (process == GetCurrentProcess())
            {
                const unixlib_module_t *handle = addr;

                if (!dlclose( (void *)(UINT_PTR)*handle )) return STATUS_SUCCESS;
            }
            return STATUS_INVALID_HANDLE;

#ifdef WINE_IOS
        /* PE VA -> executable JIT-pool copy.
         *
         * PE code cannot execute at its mapped address here, so every image's
         * code is copied into the dual-mapped pool and a Mach exception
         * redirects a PC that lands on the PE address.  Pointer tables that
         * PE code branches through are normally repaired in bulk — the
         * NtProtect-time [iat-sync] sweep for pointers living inside a pool
         * copy, the [stale-heal] escalation for the rest — but neither can
         * reach a table that is READ from the PE view of a read-only section
         * (the pool copy of that section is already correct, so the heal's
         * exact-value scan finds nothing and the same VA keeps costing one
         * Mach exception per call).  wow64.dll's copy of wow64win.dll's
         * ServiceTable is exactly that case.
         *
         * This class lets PE code ask for the pool address of a function it
         * is about to store in a private dispatch table, so the branch never
         * faults in the first place.  Returns `addr` unchanged when it is not
         * inside a pool-copied image (already-pool addresses included, which
         * makes the call idempotent). */
        case MemoryWineIosJitPoolAddress:
            if (len < sizeof(ULONG_PTR)) return STATUS_INFO_LENGTH_MISMATCH;
            if (process != GetCurrentProcess()) return STATUS_INVALID_HANDLE;
            *(ULONG_PTR *)buffer = (ULONG_PTR)ios_jit_translate_addr( (void *)addr );
            if (res_len) *res_len = sizeof(ULONG_PTR);
            return STATUS_SUCCESS;
#endif

        default:
            FIXME("(%p,%p,info_class=%d,%p,%ld,%p) Unknown information class\n",
                  process, addr, info_class, buffer, len, res_len);
            return STATUS_INVALID_INFO_CLASS;
    }
}
