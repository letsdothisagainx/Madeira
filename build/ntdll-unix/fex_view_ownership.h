/* Native FEX reservations belong to the private CPU image/process lease.
 * Included after create_view/delete_view; all *_locked helpers require VM lock. */
#define IOS_FEX_OWNERS 64
static struct ios_fex_owner_record
{
    void *owner, *image;
    unsigned long long lease;
} ios_fex_owners[IOS_FEX_OWNERS];
extern unsigned long long ios_thread_process_lease(void *, int);
extern unsigned long long ios_thread_process_quiescent_lease(void *);

static int ios_fex_range_ok(size_t size, size_t offset, size_t bytes)
{
    return offset <= size && bytes <= size-offset;
}

/* The producer exports DATA, not a function, forwarder or shared section.
 * Validate before touching it while the image is still RW, before JIT copy. */
static ULONG_PTR *ios_fex_private_export(char *base, size_t size, const IMAGE_NT_HEADERS64 *nt,
                                        const IMAGE_SECTION_HEADER *sections, const char *name)
{
    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    const IMAGE_EXPORT_DIRECTORY *exports;
    const DWORD *names, *functions;
    const WORD *ordinals;
    unsigned i, j;
    if (!dir.Size || !ios_fex_range_ok(size,dir.VirtualAddress,dir.Size) || dir.Size < sizeof(*exports)) return NULL;
    exports = (void *)(base+dir.VirtualAddress);
    if (!ios_fex_range_ok(size,exports->AddressOfNames,(size_t)exports->NumberOfNames*sizeof(DWORD)) ||
        !ios_fex_range_ok(size,exports->AddressOfNameOrdinals,(size_t)exports->NumberOfNames*sizeof(WORD)) ||
        !ios_fex_range_ok(size,exports->AddressOfFunctions,(size_t)exports->NumberOfFunctions*sizeof(DWORD))) return NULL;
    names = (void *)(base+exports->AddressOfNames); ordinals = (void *)(base+exports->AddressOfNameOrdinals);
    functions = (void *)(base+exports->AddressOfFunctions);
    for (i = 0; i < exports->NumberOfNames; i++)
    {
        size_t rva;
        if (!ios_fex_range_ok(size,names[i],1) || !memchr(base+names[i],0,size-names[i])) return NULL;
        if (strcmp(base+names[i],name)) continue;
        if (ordinals[i] >= exports->NumberOfFunctions) return NULL;
        rva = functions[ordinals[i]];
        if (!ios_fex_range_ok(size,rva,sizeof(ULONG_PTR)) || (rva & (sizeof(ULONG_PTR)-1)) ||
            (rva >= dir.VirtualAddress && rva-dir.VirtualAddress < dir.Size)) return NULL;
        for (j = 0; j < nt->FileHeader.NumberOfSections; j++)
        {
            size_t bytes = sections[j].Misc.VirtualSize ? sections[j].Misc.VirtualSize : sections[j].SizeOfRawData;
            if (rva < sections[j].VirtualAddress || rva-sections[j].VirtualAddress > bytes ||
                sizeof(ULONG_PTR) > bytes-(rva-sections[j].VirtualAddress)) continue;
            if (!(sections[j].Characteristics & IMAGE_SCN_MEM_WRITE) ||
                (sections[j].Characteristics & (IMAGE_SCN_MEM_SHARED | IMAGE_SCN_MEM_EXECUTE))) return NULL;
            return (ULONG_PTR *)(base+rva);
        }
        return NULL;
    }
    return NULL;
}

static NTSTATUS ios_fex_prepare_image(char *base, size_t size, const IMAGE_NT_HEADERS64 *nt,
                                     const IMAGE_SECTION_HEADER *sections, int hybrid)
{
    const char *name = ios_pe_module_name(base,size);
    ULONG_PTR *first, *last, lo = ios_fex_arena_base_unix, hi = ios_fex_arena_end_unix;
    void *owner;
    unsigned long long lease;
    unsigned i, free_slot = IOS_FEX_OWNERS;
    static unsigned reports;
    if (strcasecmp(name,"libwow64fex.dll") && strcasecmp(name,"libarm64ecfex.dll")) return STATUS_SUCCESS;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_ARM64 && nt->FileHeader.Machine != IMAGE_FILE_MACHINE_ARM64EC &&
         !(nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 && hybrid)) ||
        nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) return STATUS_INVALID_IMAGE_FORMAT;
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
        if ((sections[i].Characteristics & (IMAGE_SCN_MEM_SHARED | IMAGE_SCN_MEM_WRITE)) ==
            (IMAGE_SCN_MEM_SHARED | IMAGE_SCN_MEM_WRITE)) return STATUS_INVALID_IMAGE_FORMAT;
    first = ios_fex_private_export(base,size,nt,sections,"ios_fex_band_base");
    last = ios_fex_private_export(base,size,nt,sections,"ios_fex_band_end");
    /* Older unrelated CPU backends retain their original behavior; ownership
     * remains unknown, so this reaper can never reclaim their allocations. */
    if (!first || !last || first == last) return STATUS_SUCCESS;
    if (lo || hi)
    {
        if (!lo || hi <= lo || (lo & 0xffff) || (hi & 0xffff) || hi-lo < 0x40000000) return STATUS_INVALID_PARAMETER;
        if ((*first || *last) && (*first != lo || *last != hi-1)) return STATUS_CONFLICTING_ADDRESSES;
        *first = lo; *last = hi-1; /* existing inclusive FEX band ABI */
    }
    owner = ios_jit_current_peb(); lease = ios_thread_process_lease(owner,1);
    if (!owner || !lease) return STATUS_SUCCESS;
    for (i = 0; i < IOS_FEX_OWNERS; i++)
    {
        if (ios_fex_owners[i].owner == owner && ios_fex_owners[i].lease == lease) { free_slot=i; break; }
        if (!ios_fex_owners[i].owner && free_slot == IOS_FEX_OWNERS) free_slot=i;
    }
    if (free_slot < IOS_FEX_OWNERS) ios_fex_owners[free_slot] = (struct ios_fex_owner_record){owner,base,lease};
    if (reports++ < 32)
        dprintf(2,"[fex-owner-v1] pre-crt image=%s module=%p owner=%p lease=%llu arena=%p..%p band=%p..%p private=1 tracked=%u\n",
                name,base,owner,lease,(void *)lo,(void *)hi,(void *)*first,(void *)*last,free_slot < IOS_FEX_OWNERS);
    return STATUS_SUCCESS;
}

static void ios_fex_tag_view(struct file_view *view, ULONG_PTR low, ULONG_PTR high)
{
    void *owner;
    unsigned long long lease;
    unsigned i;
    static unsigned reports;
    ULONG_PTR address = (ULONG_PTR)view->base;
    int legacy = low == 0xc00000000ULL && (high == 0xeffffffffULL || high == 0xf00000000ULL);
    if (!low || !high || !view->size || address < low || address > high || view->size-1 > high-address ||
        view->ios_fex_owner || view->ios_fex_lease || !is_view_valloc(view) ||
        (view->protect & (SEC_IMAGE | VPROT_SYSTEM | VPROT_PLACEHOLDER | VPROT_FREE_PLACEHOLDER | VPROT_EXEC | VPROT_ARM64EC)) ||
        (view->ios_flags & IOS_VIEW_QUARANTINED) || (!legacy && !fex_arena_covers((void *)low,(void *)high))) return;
    owner = ios_jit_current_peb(); lease = ios_thread_process_lease(owner,0);
    if (!owner || !lease) return;
    for (i = 0; i < IOS_FEX_OWNERS; i++)
        if (ios_fex_owners[i].owner == owner && ios_fex_owners[i].lease == lease)
        {
            view->ios_fex_owner=owner; view->ios_fex_lease=lease;
            if (reports++ < 24)
                dprintf(2,"[fex-owner-v1] allocate owner=%p lease=%llu base=%p size=0x%llx flags=0x%x requirement=%p..%p anonymous=1\n",
                        owner,lease,view->base,(unsigned long long)view->size,view->protect,(void *)low,(void *)high);
            return;
        }
}

void ios_fex_reclaim_process_views(void *owner)
{
    unsigned long long lease = ios_thread_process_quiescent_lease(owner);
    struct file_view *batch[128], *view;
    size_t bytes = 0, committed = 0;
    unsigned count = 0, n, i;
    sigset_t sigset;
    static unsigned reports;
    if (!owner || !lease) return; /* unknown, live, non-exiting or incomplete cleanup */
    server_enter_uninterrupted_section(&virtual_mutex,&sigset);
    if (ios_thread_process_quiescent_lease(owner) != lease)
    {
        server_leave_uninterrupted_section(&virtual_mutex,&sigset);
        return; /* PEB reused between the ownership snapshot and VM lock */
    }
    do
    {
        n=0;
        WINE_RB_FOR_EACH_ENTRY(view,&views_tree,struct file_view,entry)
        {
            if (view->ios_fex_owner != owner || view->ios_fex_lease != lease || !is_view_valloc(view) ||
                (view->protect & (SEC_IMAGE | VPROT_SYSTEM | VPROT_PLACEHOLDER | VPROT_FREE_PLACEHOLDER | VPROT_EXEC | VPROT_ARM64EC)) ||
                (view->ios_flags & IOS_VIEW_QUARANTINED)) continue;
            batch[n++]=view;
            if (n == ARRAY_SIZE(batch)) break;
        }
        for (i=0; i<n; i++)
        {
            ULONG_PTR p = (ULONG_PTR)batch[i]->base, end = p+batch[i]->size;
            bytes += batch[i]->size;
            for (; p<end; p+=page_size) if (get_page_vprot((void *)p) & VPROT_COMMITTED) committed += page_size;
            delete_view(batch[i]); /* reserved arena returns to PROT_NONE; free_ranges kept */
            count++;
        }
    } while (n == ARRAY_SIZE(batch));
    for (i=0; i<IOS_FEX_OWNERS; i++)
        if (ios_fex_owners[i].owner == owner && ios_fex_owners[i].lease == lease)
            memset(&ios_fex_owners[i],0,sizeof(ios_fex_owners[i]));
    /* Owner-dependent callbacks completed before the final count retirement. */
    ios_hold_release_drop(owner);
    server_leave_uninterrupted_section(&virtual_mutex,&sigset);
    if (__atomic_fetch_add(&reports,1,__ATOMIC_RELAXED) < 64)
        dprintf(2,"[fex-owner-v1] retired owner=%p lease=%llu native-threads=0 views=%u reserved=0x%llx logical-committed=0x%llx (not physical residency) arena-held=1\n",
                owner,lease,count,(unsigned long long)bytes,(unsigned long long)committed);
}
