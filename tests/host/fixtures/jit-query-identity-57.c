/* Actual self-only query identity implementation before remote-target correction.
 * Source: letsdothisagainx/Madeira 57c5b127:build/ntdll-unix/virtual_ios.c
 * SHA-256 of helper block + entry point (without this comment/final newline): e37a9585c60eafac402e735848899d5450e6a40b2d04418ffd19a2b73cd6d4eb
 * Verbatim native code; no VM backend or alias algorithm is recreated here.
 */
#ifdef WINE_IOS
/* VM identity queries must not use the permissive reverse translation used
 * by unwind/late-return paths. A retained RX copy can outlive its PE view,
 * and that PE address can already describe a different file. This proves
 * address identity only, not a publisher or cryptographic trust level; the
 * underlying query still supplies its ordinary metadata. Keep a snapshot
 * across wineserver IPC without holding either allocator lock. */
struct ios_jit_query_identity
{
    struct ios_jit_mapping *mapping;
    unsigned long long generation, lease;
    void *process_owner, *image_owner, *mapped_by, *pe_base, *rx_base;
    size_t size;
};

/* OpenProcess(self) is a real handle, not necessarily the pseudo-handle.
 * Resolve only its logical process identity; keep that original handle for
 * every VM query so wineserver/APC still checks its actual access rights. */
static int ios_jit_query_self_process( HANDLE process )
{
    TEB *teb = NtCurrentTeb();
    PROCESS_BASIC_INFORMATION pbi;

    if (!teb || !teb->ClientId.UniqueProcess) return 0;
    if (process == NtCurrentProcess()) return 1;
    if (NtQueryInformationProcess( process, ProcessBasicInformation, &pbi, sizeof(pbi), NULL )) return 0;
    return pbi.UniqueProcessId == (ULONG_PTR)teb->ClientId.UniqueProcess;
}

static int ios_jit_query_identity_valid( const struct ios_jit_query_identity *identity )
{
    const struct ios_jit_mapping *m = identity->mapping;
    if (!m || !identity->generation || !identity->lease ||
        ios_jit_current_peb() != identity->process_owner ||
        ios_thread_process_lease( identity->process_owner, 0 ) != identity->lease ||
        ios_thread_process_quiescent_lease( identity->process_owner ) == identity->lease ||
        __atomic_load_n( &m->generation, __ATOMIC_ACQUIRE ) != identity->generation ||
        __atomic_load_n( &m->unmapped, __ATOMIC_RELAXED ) ||
        __atomic_load_n( &m->pe_base, __ATOMIC_RELAXED ) != identity->pe_base ||
        __atomic_load_n( &m->jit_base, __ATOMIC_RELAXED ) != identity->rx_base ||
        __atomic_load_n( &m->size, __ATOMIC_RELAXED ) != identity->size ||
        __atomic_load_n( &m->owner_peb, __ATOMIC_RELAXED ) != identity->image_owner ||
        __atomic_load_n( &m->map_peb, __ATOMIC_RELAXED ) != identity->mapped_by) return 0;
    return __atomic_load_n( &m->generation, __ATOMIC_ACQUIRE ) == identity->generation &&
           ios_thread_process_lease( identity->process_owner, 0 ) == identity->lease;
}

static LPCVOID ios_jit_query_identity_begin( int self_process, LPCVOID address,
                                            struct ios_jit_query_identity *identity )
{
    uintptr_t a = (uintptr_t)address;
    int i, count;
    memset( identity, 0, sizeof(*identity) );
    /* Legacy reload mode deliberately disables unload invalidation. Without
     * that lifetime evidence, a pool address cannot supply PE file identity. */
    if (!self_process || !ios_image_reload_mode() ||
        ios_jit_code_guard_contains( a, 1 )) return address;
    identity->process_owner = ios_jit_current_peb();
    if (!identity->process_owner ||
        !(identity->lease = ios_thread_process_lease( identity->process_owner, 0 ))) return address;
    count = __atomic_load_n( &ios_jit_mapping_count, __ATOMIC_ACQUIRE );
    if (count < 0 || count > IOS_JIT_MAX_MAPPINGS) return address;
    for (i = 0; i < count; i++)
    {
        struct ios_jit_mapping *m = &ios_jit_mappings[i];
        uintptr_t rx, pe;
        identity->generation = __atomic_load_n( &m->generation, __ATOMIC_ACQUIRE );
        identity->rx_base = __atomic_load_n( &m->jit_base, __ATOMIC_RELAXED );
        identity->pe_base = __atomic_load_n( &m->pe_base, __ATOMIC_RELAXED );
        identity->size = __atomic_load_n( &m->size, __ATOMIC_RELAXED );
        identity->image_owner = __atomic_load_n( &m->owner_peb, __ATOMIC_RELAXED );
        identity->mapped_by = __atomic_load_n( &m->map_peb, __ATOMIC_RELAXED );
        rx = (uintptr_t)identity->rx_base;
        pe = (uintptr_t)identity->pe_base;
        if (!identity->generation || !rx || !pe || !identity->size ||
            a < rx || a - rx >= identity->size || pe > UINTPTR_MAX - (a - rx) ||
            (identity->image_owner && (identity->image_owner != identity->process_owner ||
                                       identity->mapped_by != identity->process_owner))) continue;
        /* NULL ownership explicitly denotes the default/shared copy. It is
         * not a private foreign-owner fallback; the real current-process VM
         * query still decides whether its original PE view is mapped. */
        identity->mapping = m;
        if (ios_jit_query_identity_valid( identity )) return (LPCVOID)(pe + (a - rx));
        identity->mapping = NULL;
    }
    return address;
}

static NTSTATUS ios_jit_query_identity_finish( const struct ios_jit_query_identity *identity,
                                              NTSTATUS status )
{
    /* Preserve real access/length/server errors. A successful reply from a
     * changed mapping is not evidence about the old executable copy. Slot
     * generations also reject unload/reload ABA at the same PE/RX addresses. */
    if (identity->mapping && (!status || status == STATUS_BUFFER_OVERFLOW) &&
        !ios_jit_query_identity_valid( identity )) return STATUS_INVALID_ADDRESS;
    return status;
}
#endif

NTSTATUS WINAPI NtQueryVirtualMemory( HANDLE process, LPCVOID addr,
                                      MEMORY_INFORMATION_CLASS info_class,
                                      PVOID buffer, SIZE_T len, SIZE_T *res_len )
{
    NTSTATUS status;

#ifdef WINE_IOS
    struct ios_jit_query_identity query_identity = {0};
    int image_query = info_class == MemoryBasicInformation || info_class == MemoryMappedFilenameInformation ||
                      info_class == MemoryRegionInformation || info_class == MemoryImageInformation;
    int self_query = image_query && ios_jit_query_self_process( process );
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
    /* Public identity queries require a live current-process alias. Working-
     * set queries carry addresses in their buffer, not the addr argument.
     * Preserve the separate private Wine loader protocols' legacy address
     * translation; their pointer contracts are outside this identity query. */
    if (image_query || (info_class >= MemoryWineLoadUnixLib && info_class <= MemoryWineIosJitPoolAddress))
    {
        unsigned long long lo_real = 0;
        int local_aliases = image_query ? self_query : process == NtCurrentProcess();

        if (image_query) addr = ios_jit_query_identity_begin( self_query, addr, &query_identity );
        else if (process == NtCurrentProcess()) addr = ios_jit_reverse_translate_addr( addr );
        /* ml966: VirtualQuery on a low guest allocation must describe the
         * backing, otherwise the guest sees "free" for memory it holds. */
        if (local_aliases &&
            ios_lowalloc_translate( (unsigned long long)(ULONG_PTR)addr, 1, &lo_real, NULL ))
        {
            static int lq_n;
            if (lq_n < 16)
            {
                lq_n++;
                dprintf( 2, "ml966: QUERY on low guest %p -> backing %#llx\n", addr, lo_real );
            }
            addr = (LPCVOID)(ULONG_PTR)lo_real;
        }
        else if (local_aliases &&
                 ios_subfloor_image_translate( (unsigned long long)(ULONG_PTR)addr, 1, &lo_real ))
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
            status = get_basic_memory_info( process, addr, buffer, len, res_len );
#ifdef WINE_IOS
            status = ios_jit_query_identity_finish( &query_identity, status );
#endif
            return status;

        case MemoryWorkingSetExInformation:
            return get_working_set_ex( process, addr, buffer, len, res_len );

        case MemoryMappedFilenameInformation:
            status = get_memory_section_name( process, addr, buffer, len, res_len );
#ifdef WINE_IOS
            status = ios_jit_query_identity_finish( &query_identity, status );
#endif
            return status;

        case MemoryRegionInformation:
            status = get_memory_region_info( process, addr, buffer, len, res_len );
#ifdef WINE_IOS
            status = ios_jit_query_identity_finish( &query_identity, status );
#endif
            return status;

        case MemoryImageInformation:
            status = get_memory_image_info( process, addr, buffer, len, res_len );
#ifdef WINE_IOS
            status = ios_jit_query_identity_finish( &query_identity, status );
#endif
            return status;

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
