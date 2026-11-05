#!/usr/bin/env python3
"""Compile the real main-image placement diagnostic with Wine PE headers.

This checks evidence, bounds, privacy and unchanged load results. It does not
claim that a stripped executable can run away from its preferred address.
"""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / "build/ntdll-unix/virtual_ios.c").read_text()


def function(signature):
    start = source.index(signature)
    return source[start:source.index("\n}\n", start) + 3]


trace = function("static void ios_trace_fixed_main_placement(")
mapper = function("NTSTATUS virtual_map_module(")
assert mapper.index("preferred = image_info->base;") < mapper.index("virtual_map_image(")
assert mapper.index("ios_trace_fixed_main_placement(") > mapper.index("virtual_fill_image_information(")
assert mapper.index("ios_trace_fixed_main_placement(") < mapper.index("free( image_info );")
assert mapper.count("ios_trace_fixed_main_placement(") == 1

prefix = r'''
#define _GNU_SOURCE
#define WINE_IOS 1
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "windef.h"
#include "winnt.h"
#include "ntstatus.h"
typedef LONG NTSTATUS;
typedef uint64_t mem_size_t;
typedef struct { USHORT Length, MaximumLength; WCHAR *Buffer; } UNICODE_STRING;
typedef struct { int unused; } ANSI_STRING, SECTION_IMAGE_INFORMATION;
typedef struct { struct { void *UniqueProcess; } ClientId; } TEB;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
static TEB teb = {{(void *)0x03d0}};
#define NtCurrentTeb fake_current_teb
static TEB *NtCurrentTeb(void) { return &teb; }
static void *ios_jit_current_peb(void) { errno = EDOM; return (void *)0x500310000; }
static const unsigned int page_size = 0x1000;
static unsigned floor_calls, lines, fills, closes, maps;
static char last_line[2048];
static uintptr_t floor_value = UINT64_C(0x1021b4000);
static char *ios_query_map_floor(void) { __atomic_fetch_add(&floor_calls, 1, __ATOMIC_RELAXED); errno = ERANGE; return (char *)floor_value; }
static char basename_text[256];
static const char *debugstr_us(const UNICODE_STRING *name)
{
    size_t n = name->Length / sizeof(WCHAR);
    assert(n <= 80 && name->MaximumLength == name->Length);
    for (size_t i = 0; i < n; i++) basename_text[i] = (char)name->Buffer[i];
    basename_text[n] = 0;
    errno = EIO;
    return basename_text;
}
static pthread_mutex_t output_lock = PTHREAD_MUTEX_INITIALIZER;
static int capture(int fd, const char *format, ...)
{
    va_list args;
    assert(fd == 2);
    pthread_mutex_lock(&output_lock);
    va_start(args, format);
    vsnprintf(last_line, sizeof(last_line), format, args);
    va_end(args);
    lines++;
    pthread_mutex_unlock(&output_lock);
    errno = EPIPE;
    return 0;
}
#define dprintf capture
struct pe_image_info { ULONGLONG base; };
static unsigned char *image;
static size_t image_size = 0x10000;
static ULONGLONG source_preferred = UINT64_C(0x100000000);
static NTSTATUS map_status = STATUS_IMAGE_NOT_AT_BASE;
static NTSTATUS builtin_status = STATUS_IMAGE_ALREADY_LOADED;
static WCHAR path[] = {'C',':','\\','U','s','e','r','s','\\','P','r','i','v','a','t','e',
    '\\','T','e','m','p','\\','D','X','1','0','3','c','.','t','m','p','\\',
    'i','n','f','i','n','s','t','.','e','x','e',0};
static UNICODE_STRING input_name = {sizeof(path) - sizeof(WCHAR), sizeof(path), path};
static NTSTATUS get_mapping_info(HANDLE mapping, unsigned access, unsigned *flags,
    mem_size_t *full_size, HANDLE *shared, struct pe_image_info **info,
    UNICODE_STRING *name, ANSI_STRING *exports)
{
    (void)mapping; (void)flags; (void)full_size; (void)exports;
    assert(access == SECTION_MAP_READ);
    *info = malloc(sizeof(**info)); assert(*info);
    (*info)->base = source_preferred;
    *shared = (void *)7; *name = input_name;
    return 0;
}
static NTSTATUS load_builtin(const struct pe_image_info *image_info, UNICODE_STRING *name,
    ANSI_STRING *exports, USHORT machine, SECTION_IMAGE_INFORMATION *info,
    void **module, SIZE_T *size, ULONG_PTR low, ULONG_PTR high, off_t offset)
{
    (void)image_info; (void)name; (void)exports; (void)machine; (void)info;
    (void)module; (void)size; (void)low; (void)high; (void)offset;
    return builtin_status;
}
static void ios_exe_win_wait_for_handoff(const struct pe_image_info *info) { (void)info; }
static NTSTATUS virtual_map_image(HANDLE mapping, void **module, SIZE_T *size, HANDLE shared,
    ULONG_PTR low, ULONG_PTR high, ULONG flags, USHORT machine, struct pe_image_info *info,
    UNICODE_STRING *name, BOOL builtin, off_t offset)
{
    (void)mapping; (void)low; (void)high; (void)flags; (void)machine; (void)name;
    assert(shared == (void *)7 && !builtin && !offset);
    maps++;
    if (NT_SUCCESS(map_status)) { *module = image; *size = image_size; info->base = (uintptr_t)image; }
    return map_status;
}
static void virtual_fill_image_information(const struct pe_image_info *info, SECTION_IMAGE_INFORMATION *out)
{ (void)out; if (NT_SUCCESS(map_status)) assert(info->base == (uintptr_t)image); fills++; }
static void NtClose(HANDLE handle) { assert(handle == (void *)7); closes++; }
'''

main = r'''
static IMAGE_NT_HEADERS64 *header(void) { return (void *)(image + 0x80); }
static void reset_image(void)
{
    memset(image, 0, image_size);
    IMAGE_DOS_HEADER *dos = (void *)image;
    IMAGE_NT_HEADERS64 *nt = header();
    dos->e_magic = IMAGE_DOS_SIGNATURE; dos->e_lfanew = 0x80;
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.Characteristics = 0x23;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(nt->OptionalHeader);
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.ImageBase = UINT64_C(0x100000000);
    nt->OptionalHeader.SectionAlignment = 0x1000;
    nt->OptionalHeader.SizeOfImage = image_size;
    nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
}
static void trace_image(SIZE_T size)
{
    unsigned char before[0x10000];
    memcpy(before, image, sizeof(before)); errno = E2BIG;
    ios_trace_fixed_main_placement(image, size, source_preferred, map_status, &input_name);
    assert(errno == E2BIG && !memcmp(before, image, sizeof(before)));
}
static void *thread_run(void *unused)
{
    (void)unused;
    for (unsigned i = 0; i < 100; i++) {
        errno = E2BIG;
        ios_trace_fixed_main_placement(image, image_size, source_preferred, map_status, NULL);
        assert(errno == E2BIG);
    }
    return NULL;
}
int main(int argc, char **argv)
{
    assert(argc == 2);
    image = mmap(NULL, image_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(image != MAP_FAILED);
    reset_image();
    if (!strcmp(argv[1], "threads")) {
        pthread_t threads[16];
        for (unsigned i = 0; i < 16; i++) assert(!pthread_create(&threads[i], NULL, thread_run, NULL));
        for (unsigned i = 0; i < 16; i++) assert(!pthread_join(threads[i], NULL));
        assert(lines == 32 && floor_calls == 32);
        return 0;
    }
    if (!strcmp(argv[1], "cap")) {
        for (unsigned i = 0; i < 100; i++) { teb.ClientId.UniqueProcess = (void *)(uintptr_t)(0x3d0 + i); trace_image(image_size); }
        assert(lines == 32 && floor_calls == 32);
        return 0;
    }
    /* This synthetic header matches the architecture/flags/size of the log;
     * its 4GiB base is a fixture, not proof of the unavailable user binary. */
    void *module = NULL; SIZE_T mapped_size = 0; SECTION_IMAGE_INFORMATION info;
    assert(virtual_map_module(NULL, &module, &mapped_size, &info, 0, 0, 0) == STATUS_IMAGE_NOT_AT_BASE);
    assert(module == image && mapped_size == image_size && maps == 1 && fills == 1 && closes == 1);
    assert(lines == 1 && floor_calls == 1);
    assert(strstr(last_line, "pid=03d0 owner=0x500310000 image=infinst.exe"));
    assert(strstr(last_line, "map_status=40000003 machine=8664 chars=0023 preferred=0x100000000 header_base=0x100000000"));
    assert(strstr(last_line, "reloc_fields=1 reloc_rva=0 reloc_size=0 task_floor=0x1021b4000 preferred_below_floor=1 cannot_relocate=1"));
    assert(!strstr(last_line, "Private") && !strstr(last_line, "DX103c"));
    assert(header()->OptionalHeader.ImageBase == UINT64_C(0x100000000));
    header()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = (IMAGE_DATA_DIRECTORY){0xfffffff0, 0x200};
    trace_image(image_size);
    assert(strstr(last_line, "reloc_rva=0xfffffff0 reloc_size=0x200"));
    header()->OptionalHeader.NumberOfRvaAndSizes = IMAGE_DIRECTORY_ENTRY_BASERELOC;
    trace_image(image_size); assert(strstr(last_line, "reloc_fields=0 reloc_rva=0 reloc_size=0"));
    reset_image(); header()->FileHeader.SizeOfOptionalHeader = offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
    trace_image(image_size); assert(strstr(last_line, "reloc_fields=0 reloc_rva=0 reloc_size=0"));
    reset_image(); floor_value = UINT64_C(0x100010000); source_preferred = UINT64_C(0x140000000);
    header()->OptionalHeader.ImageBase = source_preferred; trace_image(image_size);
    assert(strstr(last_line, "preferred_below_floor=0 cannot_relocate=1"));
    WCHAR long_path[256];
    for (unsigned i = 0; i < 256; i++) long_path[i] = 'x';
    long_path[0] = 'C'; long_path[1] = ':'; long_path[2] = '\\'; long_path[8] = '/';
    UNICODE_STRING saved_name = input_name;
    input_name = (UNICODE_STRING){sizeof(long_path), sizeof(long_path), long_path};
    trace_image(image_size);
    assert(strlen(basename_text) == 80 && !strstr(last_line, "C:"));
    input_name = saved_name;
    unsigned before = lines;
    reset_image(); header()->OptionalHeader.ImageBase = (uintptr_t)image; trace_image(image_size); /* Existing supported subfloor rewrite. */
    reset_image(); source_preferred = (uintptr_t)image; trace_image(image_size); source_preferred = UINT64_C(0x100000000);
    reset_image(); header()->FileHeader.Characteristics &= ~IMAGE_FILE_RELOCS_STRIPPED; trace_image(image_size);
    reset_image(); header()->FileHeader.Characteristics |= IMAGE_FILE_DLL; trace_image(image_size);
    reset_image(); header()->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC; trace_image(image_size);
    reset_image(); header()->OptionalHeader.SectionAlignment = 0x200; trace_image(image_size);
    reset_image(); map_status = STATUS_CONFLICTING_ADDRESSES; trace_image(image_size); map_status = STATUS_IMAGE_NOT_AT_BASE;
    reset_image(); header()->Signature = 0; trace_image(image_size);
    reset_image(); header()->FileHeader.SizeOfOptionalHeader = 0xffff; trace_image(image_size);
    reset_image(); header()->FileHeader.SizeOfOptionalHeader = 4; trace_image(image_size);
    reset_image(); trace_image(sizeof(IMAGE_DOS_HEADER) - 1);
    ((IMAGE_DOS_HEADER *)image)->e_lfanew = -1; trace_image(image_size);
    ((IMAGE_DOS_HEADER *)image)->e_lfanew = 0x7fffffff; trace_image(image_size);
    ((IMAGE_DOS_HEADER *)image)->e_lfanew = image_size - 4; trace_image(image_size);
    assert(lines == before && floor_calls == before);
    /* A header exactly at the readable page end must not read missing dirs. */
    long host_page = sysconf(_SC_PAGESIZE);
    assert(!mprotect(image + host_page, image_size - host_page, PROT_NONE));
    ((IMAGE_DOS_HEADER *)image)->e_lfanew = host_page - offsetof(IMAGE_NT_HEADERS64, OptionalHeader) - offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
    IMAGE_NT_HEADERS64 *edge = (void *)(image + ((IMAGE_DOS_HEADER *)image)->e_lfanew);
    memcpy(edge, header(), offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory));
    edge->FileHeader.SizeOfOptionalHeader = offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
    ios_trace_fixed_main_placement(image, host_page, source_preferred, map_status, NULL);
    assert(lines == before + 1);
    assert(!mprotect(image + host_page, image_size - host_page, PROT_READ | PROT_WRITE));
    reset_image(); builtin_status = STATUS_DLL_NOT_FOUND;
    assert(virtual_map_module(NULL, &module, &mapped_size, &info, 0, 0, 0) == STATUS_DLL_NOT_FOUND);
    assert(!module && !mapped_size && maps == 1 && lines == before + 1);
    puts("PASS fixed main placement: raw PE evidence, preserved load results/header/errno, privacy, header bounds and dedicated concurrent cap");
}
'''

with tempfile.TemporaryDirectory(prefix="madeira-fixed-main-") as directory:
    path = Path(directory)
    (path / "main.c").write_text(prefix + trace + mapper + main)
    subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-Wall", "-Wextra", "-Werror", "-Wno-sign-compare",
                    "-pthread", "-I" + str(root / "wine/include"), str(path / "main.c"),
                    "-o", str(path / "check")], check=True)
    for mode in ("evidence", "cap", "threads"):
        subprocess.run([str(path / "check"), mode], check=True)
