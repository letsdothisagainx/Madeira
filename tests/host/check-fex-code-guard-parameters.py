#!/usr/bin/env python3
"""Compile the real private CodeBuffer parameter parser and allocation gate.

This checks the owned wire contract and rejects requests that cannot become a
guarded local CodeBuffer. Physical RX/RW guards and producer fallback are tested
separately by check-fex-guarded-code-producer.py.
"""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
native = (root / 'build/ntdll-unix/virtual_ios.c').read_text()
winnt = (root / 'wine/include/winnt.h').read_text()


def function(signature):
    start = native.index(signature)
    brace = native.index('{', start)
    depth, end = 1, brace + 1
    while depth:
        depth += (native[end] == '{') - (native[end] == '}')
        end += 1
    return native[start:end] + '\n'


types_start = winnt.index('typedef struct _MEM_ADDRESS_REQUIREMENTS')
types_end = winnt.index('} MEM_EXTENDED_PARAMETER, *PMEM_EXTENDED_PARAMETER;', types_start)
types = winnt[types_start:types_end + len('} MEM_EXTENDED_PARAMETER, *PMEM_EXTENDED_PARAMETER;')]
gate_start = native.index('    /* The private request is accepted only by the local, address-free,')
gate_end = native.index('    /* iOS-Madeira: For FEX-style EC_CODE RWX allocations,', gate_start)
gate = native[gate_start:gate_end]
map_start = native.index('NTSTATUS WINAPI NtMapViewOfSectionEx(')
map_check = '    if (attributes & IOS_FEX_CODE_GUARDED_ATTRIBUTE) return STATUS_INVALID_PARAMETER;'
assert map_check in native[map_start:]
assert native.index(map_check, map_start) < native.index('    if (align) return STATUS_INVALID_PARAMETER;', map_start)

code = r'''
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define WINE_IOS 1
#define DECLSPEC_ALIGN(n) __attribute__((aligned(n)))
#define DUMMYSTRUCTNAME
#define DUMMYUNIONNAME
typedef size_t SIZE_T;
typedef uintptr_t ULONG_PTR;
typedef uint64_t DWORD64;
typedef uint32_t DWORD, ULONG;
typedef unsigned short USHORT;
typedef void *PVOID, *HANDLE;
typedef int NTSTATUS;
#define STATUS_SUCCESS 0
#define STATUS_INVALID_PARAMETER -1
#define PAGE_EXECUTE_READWRITE 0x40
#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define MEM_TOP_DOWN 0x100000
#define WARN(...) ((void)0)
#define FIXME(...) ((void)0)
#define IOS_WOW_WINDOW_SIZE (UINT64_C(1) << 32)
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"line %d: %s\n",__LINE__,#c); abort(); } } while (0)
static const ULONG_PTR granularity_mask = 0xffff, page_mask = 0xfff;
static void *user_space_limit = (void *)(UINT64_C(1) << 48);
static int ios_wow_limit_by_window = 1, ios_pool_code_guards = 1;
static uintptr_t ios_wow_base(void) { return 0; }
static int is_wow64(void) { return 0; }
static ULONG_PTR get_wow_user_space_limit(void) { return UINT64_C(1) << 32; }
static HANDLE NtCurrentProcess(void) { return (HANDLE)(intptr_t)-1; }
#include "fex_code_buffer_abi.h"
''' + types + '\n'
code += function('static NTSTATUS get_extended_params(')
code += r'''
static NTSTATUS allocation_gate(HANDLE process, PVOID *ret, SIZE_T *size_ptr, ULONG type,
                                ULONG protect, ULONG attributes, ULONG_PTR limit_low,
                                ULONG_PTR limit_high, ULONG_PTR align, USHORT machine)
{
''' + gate + r'''
    return STATUS_SUCCESS;
}
static NTSTATUS map_gate(ULONG attributes)
{
''' + map_check + r'''
    return STATUS_SUCCESS;
}
static NTSTATUS parse(const MEM_EXTENDED_PARAMETER *parameters, ULONG count, ULONG *attributes)
{
    ULONG_PTR low = 0, high = 0, alignment = 0;
    USHORT machine = 0;
    *attributes = 0;
    return get_extended_params(parameters,count,&low,&high,&alignment,attributes,&machine);
}
int main(void)
{
    MEM_EXTENDED_PARAMETER p[3] = {0}, swapped[2];
    ULONG attributes = 0;
    SIZE_T size = 16u << 20;
    PVOID base = NULL;
    const ULONG tagged = IOS_FEX_CODE_GUARDED_ATTRIBUTE | 0x40;
    const ULONG type = MEM_RESERVE | MEM_COMMIT;
    HANDLE local = NtCurrentProcess();
    CHECK(!unsetenv(MADEIRA_FEX_CODE_GUARD_ENV));
    CHECK(!madeira_fex_code_guard_enabled());
    const char *disabled[] = {"", "0", "01", "true", "2"};
    for (unsigned i=0;i<sizeof(disabled)/sizeof(disabled[0]);i++) {
        CHECK(!setenv(MADEIRA_FEX_CODE_GUARD_ENV,disabled[i],1));
        CHECK(!madeira_fex_code_guard_enabled());
    }
    CHECK(!setenv(MADEIRA_FEX_CODE_GUARD_ENV,"1",1));
    CHECK(madeira_fex_code_guard_enabled());
    CHECK(!unsetenv(MADEIRA_FEX_CODE_GUARD_ENV));
    CHECK(!madeira_fex_code_guard_enabled());
    CHECK(madeira_fex_code_buffer_next_size(0)==16u<<20);
    CHECK(madeira_fex_code_buffer_next_size(1u<<20)==16u<<20);
    CHECK(madeira_fex_code_buffer_next_size(8u<<20)==16u<<20);
    CHECK(madeira_fex_code_buffer_next_size(16u<<20)==32u<<20);
    CHECK(madeira_fex_code_buffer_next_size(32u<<20)==64u<<20);
    CHECK(madeira_fex_code_buffer_next_size(64u<<20)==128u<<20);
    CHECK(madeira_fex_code_buffer_next_size(128u<<20)==128u<<20);
    CHECK(madeira_fex_code_buffer_next_size(SIZE_MAX)==128u<<20);
    CHECK(sizeof(MEM_EXTENDED_PARAMETER) == 16);
    p[0].Type = MemExtendedParameterAttributeFlags; p[0].ULong64 = 0x40;
    p[1].Type = MADEIRA_FEX_CODE_PARAMETER_TYPE; p[1].ULong64 = MADEIRA_FEX_CODE_GUARD_ABI_V1;
    CHECK(parse(p,2,&attributes) == 0 && attributes == tagged);
    swapped[0] = p[1]; swapped[1] = p[0];
    CHECK(parse(swapped,2,&attributes) == 0 && attributes == tagged);
    CHECK(allocation_gate(local,&base,&size,type,PAGE_EXECUTE_READWRITE,tagged,0,0,0,0) == 0);
    CHECK(map_gate(tagged) == STATUS_INVALID_PARAMETER);
    CHECK(map_gate(0x40) == 0);
    CHECK(parse(p,1,&attributes) == 0 && attributes == 0x40); /* ordinary legacy request */
    CHECK(parse(NULL,0,&attributes) == 0 && attributes == 0);
    CHECK(parse(NULL,1,&attributes) == STATUS_INVALID_PARAMETER);
    p[2] = p[1]; CHECK(parse(p,3,&attributes) == STATUS_INVALID_PARAMETER);
    p[1].ULong64 ^= 1; CHECK(parse(p,2,&attributes) == STATUS_INVALID_PARAMETER);
    p[1].ULong64 ^= 1;
    p[1].Reserved = 1; CHECK(parse(p,2,&attributes) == STATUS_INVALID_PARAMETER); p[1].Reserved = 0;
    p[1].Type = 32; CHECK(parse(p,2,&attributes) == STATUS_INVALID_PARAMETER); p[1].Type = 31;
    p[0].ULong64 = tagged; CHECK(parse(p,1,&attributes) == STATUS_INVALID_PARAMETER); p[0].ULong64 = 0x40;
    for (size = 1u << 20; size <= 128u << 20; size *= 2)
        CHECK(allocation_gate(local,&base,&size,type,PAGE_EXECUTE_READWRITE,tagged,0,0,0,0) == 0);
    const SIZE_T invalid[] = {0,0x4000,0x180000,256u<<20,SIZE_MAX};
    for (unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++) {
        size=invalid[i]; CHECK(allocation_gate(local,&base,&size,type,PAGE_EXECUTE_READWRITE,tagged,0,0,0,0) == STATUS_INVALID_PARAMETER);
    }
    size = 16u << 20;
    CHECK(allocation_gate((HANDLE)7,&base,&size,type,PAGE_EXECUTE_READWRITE,tagged,0,0,0,0) == STATUS_INVALID_PARAMETER);
    CHECK(allocation_gate(local,&base,&size,type,4,tagged,0,0,0,0) == STATUS_INVALID_PARAMETER);
    CHECK(allocation_gate(local,&base,&size,type,PAGE_EXECUTE_READWRITE,tagged^0x40,0,0,0,0) == STATUS_INVALID_PARAMETER);
    CHECK(allocation_gate(local,&base,&size,type,PAGE_EXECUTE_READWRITE,tagged|1,0,0,0,0) == STATUS_INVALID_PARAMETER);
    CHECK(allocation_gate(local,&base,&size,type|MEM_TOP_DOWN,PAGE_EXECUTE_READWRITE,tagged,0,0,0,0) == STATUS_INVALID_PARAMETER);
    CHECK(allocation_gate(local,&base,&size,MEM_RESERVE,PAGE_EXECUTE_READWRITE,tagged,0,0,0,0) == STATUS_INVALID_PARAMETER);
    CHECK(allocation_gate(local,&base,&size,type,PAGE_EXECUTE_READWRITE,tagged,1,0,0,0) == STATUS_INVALID_PARAMETER);
    CHECK(allocation_gate(local,&base,&size,type,PAGE_EXECUTE_READWRITE,tagged,0,1,0,0) == STATUS_INVALID_PARAMETER);
    CHECK(allocation_gate(local,&base,&size,type,PAGE_EXECUTE_READWRITE,tagged,0,0,0x10000,0) == STATUS_INVALID_PARAMETER);
    CHECK(allocation_gate(local,&base,&size,type,PAGE_EXECUTE_READWRITE,tagged,0,0,0,0xaa64) == STATUS_INVALID_PARAMETER);
    base=(void *)0x10000;
    CHECK(allocation_gate(local,&base,&size,type,PAGE_EXECUTE_READWRITE,tagged,0,0,0,0) == STATUS_INVALID_PARAMETER);
    base=NULL; ios_pool_code_guards=0;
    CHECK(allocation_gate(local,&base,&size,type,PAGE_EXECUTE_READWRITE,tagged,0,0,0,0) == STATUS_INVALID_PARAMETER);
    CHECK(allocation_gate(local,&base,&size,type,PAGE_EXECUTE_READWRITE,0x40,0,0,0,0) == 0);
    puts("PASS: actual private guard parser rejects forged, duplicate, malformed and out-of-context requests; legacy allocations remain untagged");
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-fex-guard-parameters-') as temporary:
    directory = Path(temporary)
    cfile = directory / 'guard-parameters.c'
    binary = directory / 'guard-parameters'
    cfile.write_text(code)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    '-I' + str(root / 'build/ntdll-unix'), str(cfile), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
