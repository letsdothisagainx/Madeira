#!/usr/bin/env python3
"""Run production builtin selection with a hybrid system32 and native children."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / 'build/ntdll-unix/loader_ios.c').read_text()
start = source.index('NTSTATUS load_builtin(')
end = source.index('\n\n/***********************************************************************', start)
body = source[start:end]
code = r'''
#define _GNU_SOURCE
#define WINE_IOS
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
typedef uint16_t USHORT;
typedef uintptr_t ULONG_PTR;
typedef size_t SIZE_T;
typedef int NTSTATUS;
typedef int BOOL;
typedef struct { int unused; } UNICODE_STRING, ANSI_STRING, SECTION_IMAGE_INFORMATION;
struct pe_image_info { USHORT machine; int is_hybrid, wine_builtin; };
enum loadorder { LO_DEFAULT, LO_NATIVE, LO_DISABLED };
#define IMAGE_FILE_MACHINE_ARM64 0xaa64
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define STATUS_DLL_NOT_FOUND ((int)0xc0000135)
#define STATUS_NOT_SUPPORTED ((int)0xc00000bb)
#define STATUS_IMAGE_ALREADY_LOADED ((int)0x4000001d)
#define FALSE 0
#define TRACE(...) ((void)0)
static USHORT current_machine = IMAGE_FILE_MACHINE_ARM64;
static int ec, calls, result;
static enum loadorder order;
static enum loadorder get_load_order(UNICODE_STRING *n) { (void)n; return order; }
static int ios_is_arm64ec_cur(void) { return ec; }
static void *ios_jit_current_peb(void) { return (void *)0x500310000; }
static NTSTATUS find_builtin_dll(UNICODE_STRING *n, ANSI_STRING *e, void **m,
    SIZE_T *s, SECTION_IMAGE_INFORMATION *i, ULONG_PTR lo, ULONG_PTR hi,
    USHORT search, USHORT load, BOOL prefer, off_t off)
{
    assert(n && e && m && s && i);
    assert(lo == 0x10000 && hi == 0xfc0000000 && off == 0);
    assert(search == IMAGE_FILE_MACHINE_ARM64 && load == IMAGE_FILE_MACHINE_ARM64 && !prefer);
    calls++;
    if (!result) { *m = (void *)0x3fe6a0000; *s = 0x200000; }
    return result;
}
'''
code += body
code += r'''
static int run(struct pe_image_info image, USHORT machine)
{
    UNICODE_STRING n; ANSI_STRING e; SECTION_IMAGE_INFORMATION i;
    void *m = NULL; SIZE_T size = 0;
    int status = load_builtin(&image, &n, &e, machine, &i, &m, &size,
                              0x10000, 0xfc0000000, 0);
    if (!status) assert(m == (void *)0x3fe6a0000 && size == 0x200000);
    else assert(!m && !size);
    return status;
}
int main(void)
{
    struct pe_image_info hybrid = {0x8664, 1, 1};
    for (int child = 0; child < 64; child++) {
        ec = 0; assert(!run(hybrid, 0));
        ec = 1; assert(run(hybrid, 0) == STATUS_IMAGE_ALREADY_LOADED);
        ec = 0; assert(!run(hybrid, IMAGE_FILE_MACHINE_ARM64));
    }
    assert(calls == 128);
    assert(run(hybrid, IMAGE_FILE_MACHINE_AMD64) == STATUS_IMAGE_ALREADY_LOADED);
    struct pe_image_info native = {0xaa64, 0, 1}, guest = {0x14c, 0, 1};
    struct pe_image_info app = {0x8664, 1, 0}, x64 = {0x8664, 0, 1};
    assert(run(native, 0) == STATUS_IMAGE_ALREADY_LOADED);
    assert(run(guest, 0) == STATUS_IMAGE_ALREADY_LOADED);
    assert(run(app, 0) == STATUS_IMAGE_ALREADY_LOADED);
    assert(run(x64, 0) == STATUS_IMAGE_ALREADY_LOADED);
    assert(calls == 128);
    order = LO_DISABLED; assert(run(hybrid, 0) == STATUS_DLL_NOT_FOUND);
    order = LO_NATIVE; assert(run(hybrid, 0) == STATUS_NOT_SUPPORTED);
    assert(calls == 128);
    order = LO_DEFAULT;
    const int failures[] = {STATUS_DLL_NOT_FOUND, STATUS_NOT_SUPPORTED, (int)0xc0000017};
    for (unsigned j = 0; j < sizeof(failures)/sizeof(*failures); j++) {
        result = failures[j]; assert(run(hybrid, 0) == result);
    }
    assert(calls == 131);
    puts("PASS production builtin resolver: native child imports use ARM64, hybrid siblings/application DLLs unchanged, missing/mismatched/OOM replacements fail closed");
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-child-native-') as directory:
    path = Path(directory)
    (path / 'check.c').write_text(code)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra',
                    '-Werror', '-fsanitize=address,undefined', '-g', '-O1',
                    str(path / 'check.c'), '-o', str(path / 'check')], check=True)
    subprocess.run([str(path / 'check')], check=True)
