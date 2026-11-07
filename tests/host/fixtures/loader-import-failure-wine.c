/*
 * Fixtures for check-loader-import-failure-retention.py. The production
 * functions are injected unchanged at the marker below. Only boundary APIs
 * and fixture construction are implemented here; no loader failure decisions
 * are mirrored. ASan/UBSan execute the resulting production control flow.
 */
#define WINE_UNIX_LIB
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "ntstatus.h"
#include "windef.h"
#include "winnt.h"
#include "winternl.h"

#define TRACE(...) ((void)0)
#define TRACE_(channel) TRACE
#define TRACE_ON(channel) 0

struct file_id { BYTE ObjectId[16]; };
typedef struct _wine_modref {
    LDR_DATA_TABLE_ENTRY ldr;
    struct file_id id;
    ULONG CheckSum;
    BOOL system;
} WINE_MODREF;
static RTL_RB_TREE base_address_index_tree;
static LDR_DDAG_NODE *node_ntdll, *node_kernel32;
static const SIZE_T page_size = 4096;
static LIST_ENTRY load_list, hash_list;
#define memory_list (ldr_fixture.InMemoryOrderModuleList)
static unsigned char image_fixture[4096] __attribute__((aligned(16)));
static unsigned char retry_image_fixture[4096] __attribute__((aligned(16)));
static void *next_map_base;
static int live_mappings[2];
static WINE_MODREF *allocated_modules[2];
static unsigned allocated_count;
static TEB teb_fixture;
static PEB peb_fixture;
static PEB_LDR_DATA ldr_fixture;
#define NtCurrentTeb() (&teb_fixture)
static IMAGE_IMPORT_DESCRIPTOR import_fixture[3];
static WINE_MODREF dependency_fixture;
static WINE_MODREF *allocated_module;
static NTSTATUS map_status, relocation_status, import_status[2];
static int invalid_header, allocation_fail, import_present;
static unsigned map_calls, unmap_calls, relocation_calls, allocation_calls;
static unsigned import_calls, dependency_calls, rb_remove_calls;
static unsigned tls_calls, activation_calls, deactivation_calls;
static void *mapped_base;

static IMAGE_NT_HEADERS *fixture_header(void)
{
    return (IMAGE_NT_HEADERS *)((unsigned char *)next_map_base + 256);
}
PIMAGE_NT_HEADERS WINAPI RtlImageNtHeader(HMODULE base)
{
    assert((void *)base == image_fixture || (void *)base == retry_image_fixture);
    return invalid_header ? NULL : (IMAGE_NT_HEADERS *)((unsigned char *)base + 256);
}
PVOID WINAPI RtlImageDirectoryEntryToData(HMODULE base, BOOL mapped, WORD directory, ULONG *size)
{
    assert((void *)base == next_map_base && mapped && directory == IMAGE_DIRECTORY_ENTRY_IMPORT);
    *size = sizeof(import_fixture);
    return import_present ? import_fixture : NULL;
}
NTSTATUS WINAPI NtMapViewOfSection(HANDLE section, HANDLE process, PVOID *base,
                                  ULONG_PTR zero, SIZE_T commit, const LARGE_INTEGER *offset,
                                  SIZE_T *size, SECTION_INHERIT inherit, ULONG type, ULONG protect)
{
    (void)section; (void)zero; (void)commit; (void)offset; (void)size;
    (void)inherit; (void)type; (void)protect;
    assert(process == NtCurrentProcess());
    map_calls++;
    if (NT_SUCCESS(map_status))
    {
        *base = mapped_base = next_map_base;
        live_mappings[next_map_base == (void *)retry_image_fixture] = 1;
    }
    return map_status;
}
NTSTATUS WINAPI NtUnmapViewOfSection(HANDLE process, PVOID base)
{
    assert(process == NtCurrentProcess() && base == mapped_base);
    unmap_calls++;
    live_mappings[base == (void *)retry_image_fixture] = 0;
    mapped_base = NULL;
    return STATUS_SUCCESS;
}
/* get_modref's address index is a fixture; production find_existing_module
 * below also performs its real full InMemoryOrderModuleList traversal. */
static WINE_MODREF *get_modref(HMODULE base)
{
    LIST_ENTRY *entry;
    for (entry = memory_list.Flink; entry != &memory_list; entry = entry->Flink)
    {
        LDR_DATA_TABLE_ENTRY *mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (mod->DllBase == (void *)base) return CONTAINING_RECORD(mod, WINE_MODREF, ldr);
    }
    return NULL;
}
NTSTATUS WINAPI NtAreMappedFilesTheSame(PVOID first, PVOID second)
{
    assert(first && second); return STATUS_SUCCESS;
}
static BOOL convert_to_pe64(HMODULE base, const SECTION_IMAGE_INFORMATION *info)
{
    (void)base; (void)info; assert(!"unexpected machine mismatch"); return FALSE;
}
static NTSTATUS perform_relocations(void *base, IMAGE_NT_HEADERS *nt, SIZE_T size)
{
    assert(base == next_map_base && nt == fixture_header() && size == 4096);
    relocation_calls++;
    return relocation_status;
}
static WINE_MODREF *alloc_module(HMODULE base, const UNICODE_STRING *name, BOOL builtin)
{
    (void)name; assert((void *)base == next_map_base && !builtin);
    allocation_calls++;
    if (allocation_fail) return NULL;
    assert(allocated_count < 2);
    allocated_module = calloc(1, sizeof(*allocated_module));
    assert(allocated_module);
    allocated_modules[allocated_count++] = allocated_module;
    allocated_module->ldr.DdagNode = calloc(1, sizeof(LDR_DDAG_NODE));
    assert(allocated_module->ldr.DdagNode);
    allocated_module->ldr.DllBase = base;
    allocated_module->ldr.TimeDateStamp = fixture_header()->FileHeader.TimeDateStamp;
    allocated_module->CheckSum = fixture_header()->OptionalHeader.CheckSum;
    allocated_module->ldr.Flags = LDR_DONT_RESOLVE_REFS;
    allocated_module->ldr.LoadCount = 1;
    InitializeListHead(&allocated_module->ldr.DdagNode->Modules);
    InsertTailList(&allocated_module->ldr.DdagNode->Modules, &allocated_module->ldr.NodeModuleLink);
    InsertTailList(&load_list, &allocated_module->ldr.InLoadOrderLinks);
    InsertTailList(&memory_list, &allocated_module->ldr.InMemoryOrderLinks);
    InsertTailList(&hash_list, &allocated_module->ldr.HashLinks);
    base_address_index_tree.root = &allocated_module->ldr.BaseAddressIndexNode;
    return allocated_module;
}
static void update_load_config(void *base) { assert(base == next_map_base); }
static NTSTATUS fixup_imports_ilonly(WINE_MODREF *wm, LPCWSTR path, void **entry)
{
    (void)wm; (void)path; (void)entry; assert(!"unexpected IL-only path"); return STATUS_SUCCESS;
}
static BOOL alloc_tls_slot(LDR_DATA_TABLE_ENTRY *ldr)
{
    assert(allocated_module && ldr == &allocated_module->ldr); tls_calls++; return TRUE;
}
static NTSTATUS create_module_activation_context(LDR_DATA_TABLE_ENTRY *ldr)
{
    ldr->ActivationContext = (void *)(uintptr_t)1; return STATUS_SUCCESS;
}
NTSTATUS WINAPI RtlActivateActivationContext(DWORD flags, struct _ACTIVATION_CONTEXT *ctx, ULONG_PTR *cookie)
{
    assert(!flags && ctx == (void *)(uintptr_t)1); activation_calls++; *cookie=123; return STATUS_SUCCESS;
}
void WINAPI RtlDeactivateActivationContext(DWORD flags, ULONG_PTR cookie)
{
    assert(!flags && cookie == 123); deactivation_calls++;
}
static BOOL import_dll(WINE_MODREF *wm, const IMAGE_IMPORT_DESCRIPTOR *desc,
                       LPCWSTR path, WINE_MODREF **dependency)
{
    (void)path;
    size_t index = desc - import_fixture;
    assert(wm == allocated_module && index < 2);
    import_calls++;
    *dependency = NT_SUCCESS(import_status[index]) ? &dependency_fixture : NULL;
    return NT_SUCCESS(import_status[index]);
}
static void add_module_dependency_after(LDR_DDAG_NODE *from, LDR_DDAG_NODE *to, SINGLE_LIST_ENTRY *after)
{
    (void)after;
    assert(allocated_module && from == allocated_module->ldr.DdagNode && to == dependency_fixture.ldr.DdagNode);
    dependency_calls++;
}
void WINAPI RtlRbRemoveNode(RTL_RB_TREE *tree, RTL_BALANCED_NODE *node)
{
    assert(tree == &base_address_index_tree && tree->root == node);
    rb_remove_calls++;
    tree->root = NULL;
}
static void RELAY_SetupDLL(void *base) { (void)base; assert(!"disabled relay"); }
static void SNOOP_SetupDLL(void *base) { (void)base; assert(!"disabled snoop"); }

/* INSERT_UNMODIFIED_PRODUCTION_CODE */

static void reset_fixture(void)
{
    for (unsigned i = 0; i < allocated_count; i++)
    {
        free(allocated_modules[i]->ldr.DdagNode);
        free(allocated_modules[i]);
    }
    allocated_count = 0;
    memset(allocated_modules, 0, sizeof(allocated_modules));
    memset(live_mappings, 0, sizeof(live_mappings));
    memset(&teb_fixture, 0, sizeof(teb_fixture));
    memset(&peb_fixture, 0, sizeof(peb_fixture));
    memset(&ldr_fixture, 0, sizeof(ldr_fixture));
    next_map_base = image_fixture;
    teb_fixture.Peb = &peb_fixture;
    peb_fixture.LdrData = &ldr_fixture;
    allocated_module=NULL;
    memset(image_fixture, 0, sizeof(image_fixture));
    memset(import_fixture, 0, sizeof(import_fixture));
    memset(&dependency_fixture, 0, sizeof(dependency_fixture));
    memset(&base_address_index_tree, 0, sizeof(base_address_index_tree));
    static LDR_DDAG_NODE dependency_node;
    dependency_fixture.ldr.DdagNode = &dependency_node;
    InitializeListHead(&load_list); InitializeListHead(&memory_list); InitializeListHead(&hash_list);
    IMAGE_NT_HEADERS *nt=fixture_header();
    nt->OptionalHeader.SizeOfImage=4096;
    nt->FileHeader.Characteristics=IMAGE_FILE_DLL;
    import_fixture[0].Name=1; import_fixture[0].FirstThunk=1;
    import_fixture[1].Name=2; import_fixture[1].FirstThunk=2;
    import_status[0]=import_status[1]=STATUS_SUCCESS;
    map_status=relocation_status=STATUS_SUCCESS;
    invalid_header=allocation_fail=0; import_present=1;
    map_calls=unmap_calls=relocation_calls=allocation_calls=0;
    import_calls=dependency_calls=rb_remove_calls=0;
    tls_calls=activation_calls=deactivation_calls=0;
    mapped_base=NULL;
}
static NTSTATUS run_load(WINE_MODREF **wm)
{
    UNICODE_STRING name={0};
    SECTION_IMAGE_INFORMATION info={0};
    struct file_id id={{0x42}};
    *wm=(void *)(uintptr_t)0xdead;
    return load_native_dll(NULL, &name, (HANDLE)(uintptr_t)5, &info, &id, 0, FALSE, FALSE, wm);
}
static void assert_lists_empty(void)
{
    assert(IsListEmpty(&load_list)); assert(IsListEmpty(&memory_list)); assert(IsListEmpty(&hash_list));
}
int main(void)
{
    WINE_MODREF *wm;
    reset_fixture();
    import_status[0]=STATUS_NO_MEMORY;
    assert(run_load(&wm)==STATUS_DLL_NOT_FOUND);
    assert(map_calls==1 && unmap_calls==0 && mapped_base==image_fixture);
    assert(allocated_module && wm==NULL && allocated_module->ldr.DllBase==image_fixture);
    assert(allocated_module->ldr.LoadCount==1 && allocated_module->ldr.TlsIndex==-1);
    assert(!(allocated_module->ldr.Flags & LDR_DONT_RESOLVE_REFS));
    assert_lists_empty(); assert(rb_remove_calls==1 && !base_address_index_tree.root);
    assert(!IsListEmpty(&allocated_module->ldr.DdagNode->Modules));
    assert(import_calls==2 && dependency_calls==1);
    assert(tls_calls==1 && activation_calls==1 && deactivation_calls==1);
    puts("PASS dependency NO_MEMORY -> parent DLL_NOT_FOUND; mapping and modref retained; public indices removed; later import processed");

    WINE_MODREF *retained = allocated_module;
    memcpy(retry_image_fixture, image_fixture, sizeof(image_fixture));
    next_map_base = retry_image_fixture;
    import_status[0] = STATUS_SUCCESS;
    assert(find_existing_module((HMODULE)retry_image_fixture) == NULL);
    assert(run_load(&wm) == STATUS_SUCCESS);
    assert(map_calls == 2 && unmap_calls == 0 && live_mappings[0] && live_mappings[1]);
    assert(allocated_count == 2 && retained != wm && wm == allocated_module);
    assert(retained->ldr.DllBase == image_fixture && wm->ldr.DllBase == retry_image_fixture);
    assert(retained->ldr.InMemoryOrderLinks.Flink == NULL);
    assert(get_modref((HMODULE)image_fixture) == NULL);
    assert(get_modref((HMODULE)retry_image_fixture) == wm);
    assert(find_existing_module((HMODULE)image_fixture) == wm);
    puts("PASS retry maps distinct PE; retained first modref is undiscoverable; production lookup finds only the new public module");

    reset_fixture(); invalid_header=1;
    assert(run_load(&wm)==STATUS_INVALID_IMAGE_FORMAT);
    assert(unmap_calls==1 && !mapped_base && allocation_calls==0 && import_calls==0);
    puts("PASS invalid PE header before module allocation unmaps parent");

    reset_fixture(); relocation_status=STATUS_CONFLICTING_ADDRESSES;
    assert(run_load(&wm)==STATUS_CONFLICTING_ADDRESSES);
    assert(unmap_calls==1 && !mapped_base && relocation_calls==1 && allocation_calls==0 && import_calls==0);
    puts("PASS relocation failure before module allocation unmaps parent");

    reset_fixture(); allocation_fail=1;
    assert(run_load(&wm)==STATUS_NO_MEMORY);
    assert(unmap_calls==1 && !mapped_base && allocation_calls==1 && !allocated_module && import_calls==0);
    puts("PASS modref allocation failure before imports unmaps parent");

    reset_fixture();
    assert(run_load(&wm)==STATUS_SUCCESS);
    assert(unmap_calls==0 && mapped_base==image_fixture && wm==allocated_module);
    assert(!IsListEmpty(&load_list) && !IsListEmpty(&memory_list) && !IsListEmpty(&hash_list));
    assert(rb_remove_calls==0 && base_address_index_tree.root==&wm->ldr.BaseAddressIndexNode);
    assert(import_calls==2 && dependency_calls==2 && wm->id.ObjectId[0]==0x42);
    puts("PASS successful imports retain mapping and public modref");

    reset_fixture(); map_status=STATUS_NO_MEMORY;
    assert(run_load(&wm)==STATUS_NO_MEMORY);
    assert(map_calls==1 && unmap_calls==0 && !mapped_base && allocation_calls==0);
    puts("PASS failed map returns original status and does not unmap absent mapping");
    reset_fixture();
    return 0;
}
