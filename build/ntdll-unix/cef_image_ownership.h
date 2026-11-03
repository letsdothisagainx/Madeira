/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Private native Steam CEF image backing follows the process lease.
 * Included after delete_view; all view mutations require virtual_mutex.
 * This does not replace the JIT or native FEX reapers. */
#ifndef MADEIRA_CEF_IMAGE_OWNERSHIP_H
#define MADEIRA_CEF_IMAGE_OWNERSHIP_H

static int ios_cef_name_is(const UNICODE_STRING *name, const char *wanted)
{
    WCHAR tail[64];
    size_t length, n = strlen(wanted), first, i;
    if (!name || !name->Buffer || (name->Length & 1) || name->Length > name->MaximumLength ||
        n + 1 > ARRAY_SIZE(tail)) return 0;
    length = name->Length / sizeof(WCHAR);
    if (length < n) return 0;
    first = length > n ? length-n-1 : 0;
    if ((uintptr_t)name->Buffer > UINTPTR_MAX-first*sizeof(WCHAR) ||
        !ios_io_trace_read((const void *)((uintptr_t)name->Buffer+first*sizeof(WCHAR)),
                           tail,(length-first)*sizeof(WCHAR))) return 0;
    if (length > n && tail[0] != '\\' && tail[0] != '/') return 0;
    for (i=0; i<n; i++)
    {
        WCHAR c = tail[(length > n)+i];
        if (c >= 'A' && c <= 'Z') c += 'a'-'A';
        if (c != (unsigned char)wanted[i]) return 0;
    }
    return 1;
}

static int ios_cef_native_browser(void *owner)
{
    RTL_USER_PROCESS_PARAMETERS *params = NULL;
    UNICODE_STRING image;
    if (!owner || ios_wow_base() ||
        !ios_io_trace_read((char *)owner+offsetof(PEB,ProcessParameters),&params,sizeof(params)) || !params ||
        !ios_io_trace_read((char *)params+offsetof(RTL_USER_PROCESS_PARAMETERS,ImagePathName),&image,sizeof(image)))
        return 0;
    return ios_cef_name_is(&image,"steamwebhelper.exe");
}

/* These two private DLLs account for the measured retained dirty backing.
 * Builtins, resources, partial images, other applications and any image with
 * shared sections are intentionally outside this narrowly proven lifetime. */
static void ios_cef_tag_private_image(struct file_view *view, const UNICODE_STRING *name)
{
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    IMAGE_SECTION_HEADER section;
    size_t sections, bytes;
    unsigned i;
    void *owner = ios_jit_current_peb();
    unsigned long long lease;
    static unsigned reports;
    if (view->ios_cef_owner || view->ios_cef_lease ||
        (view->protect & (SEC_IMAGE | VPROT_SYSTEM | VPROT_ARM64EC)) != SEC_IMAGE ||
        (view->ios_flags & IOS_VIEW_QUARANTINED) ||
        (!ios_cef_name_is(name,"libcef.dll") && !ios_cef_name_is(name,"chrome_elf.dll")) ||
        !ios_cef_native_browser(owner)) return;
    lease = ios_thread_process_lease(owner,0);
    if (!lease || ios_thread_process_quiescent_lease(owner) == lease ||
        view->size < sizeof(dos) || !ios_io_trace_read(view->base,&dos,sizeof(dos)) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < (LONG)sizeof(dos) ||
        (size_t)dos.e_lfanew > view->size || sizeof(nt) > view->size-(size_t)dos.e_lfanew ||
        !ios_io_trace_read((char *)view->base+dos.e_lfanew,&nt,sizeof(nt)) ||
        nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.OptionalHeader.SizeOfImage != view->size ||
        nt.FileHeader.SizeOfOptionalHeader < sizeof(nt.OptionalHeader) ||
        !nt.FileHeader.NumberOfSections || nt.FileHeader.NumberOfSections > 96) return;
    sections = (size_t)dos.e_lfanew + offsetof(IMAGE_NT_HEADERS64,OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader;
    bytes = (size_t)nt.FileHeader.NumberOfSections * sizeof(section);
    if (sections > view->size || bytes > view->size-sections) return;
    for (i=0; i<nt.FileHeader.NumberOfSections; i++)
        if (!ios_io_trace_read((char *)view->base+sections+i*sizeof(section),&section,sizeof(section)) ||
            (section.Characteristics & IMAGE_SCN_MEM_SHARED)) return;
    view->ios_cef_owner=owner;
    view->ios_cef_lease=lease;
    if (__atomic_fetch_add(&reports,1,__ATOMIC_RELAXED) < 32)
        dprintf(2,"[cef-image-owner-v1] map owner=%p lease=%llu image=%p size=%#lx private-native=1\n",
                owner,lease,view->base,(unsigned long)view->size);
}

/* Any remaining pool entry, including an unattributed or foreign one, retains
 * the original image. virtual_mutex excludes new image/protection mutations;
 * the pool lock protects this snapshot in the established VM->pool order. */
static int ios_cef_image_has_jit_reference(const struct file_view *view)
{
    uintptr_t lo = (uintptr_t)view->base;
    int i, found = 0;
    pthread_mutex_lock(&ios_pool_lock);
    for (i=0; i<ios_jit_mapping_count; i++)
    {
        uintptr_t at = (uintptr_t)ios_jit_mappings[i].pe_base;
        size_t size = ios_jit_mappings[i].size;
        if (!at || !size) continue;
        if (at >= lo ? at-lo < view->size : lo-at < size) { found=1; break; }
    }
    pthread_mutex_unlock(&ios_pool_lock);
    return found;
}

/* Wine images use 4 KiB metadata while unmap_area and alias retirement round
 * to the iOS host page. Never erase a neighbour or an unattributed tail alias. */
static int ios_cef_image_host_span_exclusive(const struct file_view *view)
{
    struct file_view *other;
    uintptr_t base = (uintptr_t)view->base, ignored_base = 0, ignored_end = 0;
    size_t span;
    if ((base & host_page_mask) || !view->size || view->size > SIZE_MAX-host_page_mask) return 0;
    span = (view->size+host_page_mask) & ~host_page_mask;
    if (base > UINTPTR_MAX-span) return 0;
    WINE_RB_FOR_EACH_ENTRY(other,&views_tree,struct file_view,entry)
    {
        uintptr_t at = (uintptr_t)other->base;
        if (other == view || !other->size) continue;
        if (at >= base ? at-base < span : base-at < other->size) return 0;
    }
    return !ios_jit_anon_alias_overlaps(view->base,span,&ignored_base,&ignored_end);
}

void ios_cef_reclaim_process_images(void *owner)
{
    unsigned long long lease = ios_thread_process_quiescent_lease(owner);
    struct file_view *batch[32], *view;
    sigset_t sigset;
    size_t bytes = 0;
    unsigned count = 0, retained = 0, i, n;
    static unsigned reports;
    if (!owner || !lease) return;
    server_enter_uninterrupted_section(&virtual_mutex,&sigset);
    if (ios_thread_process_quiescent_lease(owner) != lease)
    {
        server_leave_uninterrupted_section(&virtual_mutex,&sigset);
        return; /* A reused PEB must not reclaim its successor's images. */
    }
    do
    {
        n=0;
        WINE_RB_FOR_EACH_ENTRY(view,&views_tree,struct file_view,entry)
        {
            if (view->ios_cef_owner != owner || view->ios_cef_lease != lease ||
                (view->protect & (SEC_IMAGE | VPROT_SYSTEM | VPROT_ARM64EC)) != SEC_IMAGE ||
                (view->ios_flags & IOS_VIEW_QUARANTINED) || !ios_cef_image_host_span_exclusive(view) ||
                ios_cef_image_has_jit_reference(view)) continue;
            batch[n++]=view;
            if (n == ARRAY_SIZE(batch)) break;
        }
        for (i=0; i<n; i++)
        {
            bytes += batch[i]->size;
            delete_view(batch[i]); /* Existing alias, swap, vprot and view-tree cleanup. */
            count++;
        }
    } while (n == ARRAY_SIZE(batch));
    WINE_RB_FOR_EACH_ENTRY(view,&views_tree,struct file_view,entry)
        if (view->ios_cef_owner == owner && view->ios_cef_lease == lease) retained++;
    server_leave_uninterrupted_section(&virtual_mutex,&sigset);
    if ((count || retained) && __atomic_fetch_add(&reports,1,__ATOMIC_RELAXED) < 64)
        dprintf(2,"[cef-image-owner-v1] retire owner=%p lease=%llu native-threads=0 images=%u image-bytes=%#lx retained=%u "
                  "(Wine image bytes, not measured physical residency)\n",owner,lease,count,(unsigned long)bytes,retained);
}
#endif
