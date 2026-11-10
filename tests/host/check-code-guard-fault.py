#!/usr/bin/env python3
"""Production permanent-guard lookup, alias refusal and BSD exception delivery.

The only platform adapters are Mach protection -> mprotect and exception
delivery -> a captured EXCEPTION_RECORD. No store/decoder/guard algorithm is
reimplemented. The native producer suite separately executes the guarded code.
"""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
source = (ROOT / 'build/ntdll-unix/signal_arm64_ios.c').read_text()


def function(signature):
    start = source.index(signature)
    return source[start:source.index('\n}', start) + 2] + '\n'


# The Mach path must bypass every recovery that could remove the real guard.
early = source.index('goto ios_deliver_code_guard_exception;')
label = source.index('\nios_deliver_code_guard_exception:')
assert early < source.index('/* --- Section 4') if '/* --- Section 4' in source else early < label
assert source.index('if (req->exception == EXC_BAD_ACCESS && ios_jit_code_guard_contains( fault_addr, 1 ))') < early
inner = function('static int ios_mach_deliver_guest_exception_inner(')
assert 'const int is_code_guard = exception == EXC_BAD_ACCESS && ios_jit_code_guard_contains' in inner
assert inner.count('!is_code_guard') >= 4, 'guard must skip alignment, page repair and transient/replay recovery'
for handler in ('static void segv_handler(', 'static void bus_handler('):
    block = function(handler)
    call = block.index('if (ios_deliver_code_guard_signal(')
    for recovery in ('ios_store_split_crossing(', 'emulate_atomics(', 'virtual_handle_fault('):
        if recovery in block:
            assert call < block.index(recovery)

code = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
typedef struct { uint64_t __x[29], __fp, __lr, __sp, __pc; } arm_thread_state64_t;
typedef struct { __uint128_t __v[32]; } arm_neon_state64_t;
#define arm_thread_state64_get_pc(s) ((s).__pc)
void *ios_jit_rx_base_global, *ios_jit_rw_base_global;
size_t ios_jit_pool_size_global;
#define KERN_SUCCESS 0
#define VM_PROT_NONE PROT_NONE
#define VM_PROT_WRITE PROT_WRITE
#define VM_REGION_BASIC_INFO_COUNT_64 1
#define VM_REGION_BASIC_INFO_64 1
#define MACH_PORT_NULL 0
typedef uintptr_t mach_vm_address_t;
typedef size_t mach_vm_size_t;
typedef unsigned mach_msg_type_number_t;
typedef int mach_port_t;
typedef int *vm_region_info_t;
typedef struct { int protection; } vm_region_basic_info_data_64_t;
static int mach_task_self(void) { return 0; }
static int mach_vm_region(int task, uintptr_t *address, size_t *size, int flavor,
                          int *info, unsigned *count, int *object)
{ (void)task; (void)address; (void)size; (void)flavor; (void)info; (void)count; (void)object; return 1; }
static int mach_port_deallocate(int task, int object) { (void)task; (void)object; return 0; }
static int mach_vm_protect(int task, uintptr_t address, size_t size, int maximum, int prot)
{ (void)task; (void)maximum; return mprotect((void *)address, size, prot); }
#include "fex_code_guards.h"
int ios_jit_low_contains(uintptr_t address) { (void)address; return 0; }
int ios_jit_pool_pc_is_fex(uintptr_t address) { (void)address; return 1; }
uintptr_t ios_jit_anon_alias_lookup(uintptr_t address) { (void)address; return 0; }
void ios_jit_anon_alias_note_write(unsigned long long address) { (void)address; }
int ios_page_expected_prot(const void *address) { (void)address; return PROT_READ|PROT_WRITE; }
typedef uint64_t DWORD64;
typedef uintptr_t ULONG_PTR;
/* Darwin's mman headers already expose its real ucontext_t. This explicit OS
 * adapter substitutes only the context boundary used by the extracted helper. */
#define ucontext_t guard_test_context
typedef struct { uint64_t pc, esr, regs[32]; } ucontext_t;
typedef struct { unsigned ExceptionCode; void *ExceptionAddress; unsigned NumberParameters;
                 uintptr_t ExceptionInformation[2]; } EXCEPTION_RECORD;
#define EXCEPTION_ACCESS_VIOLATION 0xc0000005u
#define EXCEPTION_READ_FAULT 0
#define EXCEPTION_WRITE_FAULT 1
#define EXCEPTION_EXECUTE_FAULT 8
#define PC_sig(c) ((c)->pc)
static DWORD64 get_fault_esr(ucontext_t *context) { return context->esr; }
static EXCEPTION_RECORD delivered;
static unsigned deliveries;
static void setup_exception(ucontext_t *context, EXCEPTION_RECORD *record)
{ (void)context; delivered = *record; deliveries++; }
'''
for signature in (
    'static uintptr_t ios_write_alias( uintptr_t addr )',
    'static int ios_alias_write_is_trapped( uintptr_t addr )',
    'static int ios_alias_write( uintptr_t addr, const void *source, size_t size, uintptr_t *blocked,\n                            int honor_guest_prot )',
    'static int ios_alias_store_immediate( uint32_t insn, uintptr_t addr, uint64_t gpr[32], uintptr_t *blocked,\n                                      int honor_guest_prot )',
    'int ios_store_split_crossing( uint32_t insn, arm_thread_state64_t *st,',
    'static int ios_deliver_code_guard_signal( ucontext_t *context, void *address )',
):
    code += function(signature)
code += r'''
/* Linux guarantees only its 4 KiB native alignment. Model the actual iOS pool
 * contract with two separately owned 16 KiB-aligned reservations; replace only
 * our own reserved span, then trim its unused prefix/suffix. */
static unsigned char *aligned_alias(int fd, size_t size, int protection)
{
    const size_t alignment = 0x4000;
    unsigned char *reservation = mmap(0, size + alignment, PROT_NONE,
                                      MAP_PRIVATE | MAP_ANON, -1, 0);
    assert(reservation != MAP_FAILED);
    uintptr_t start = ((uintptr_t)reservation + alignment - 1) & ~(uintptr_t)(alignment - 1);
    size_t prefix = start - (uintptr_t)reservation, suffix = alignment - prefix;
    unsigned char *mapped = mmap((void *)start, size, protection, MAP_SHARED | MAP_FIXED, fd, 0);
    assert(mapped == (void *)start);
    if (prefix) assert(!munmap(reservation, prefix));
    if (suffix) assert(!munmap(mapped + size, suffix));
    return mapped;
}
int main(void)
{
    const size_t size = 0x100000, guard = size - 0x4000;
    FILE *file = tmpfile(); assert(file && !ftruncate(fileno(file), size));
    unsigned char *rw = aligned_alias(fileno(file), size, PROT_READ|PROT_WRITE);
    unsigned char *rx = aligned_alias(fileno(file), size, PROT_READ|PROT_EXEC);
    assert(!(((uintptr_t)rw | (uintptr_t)rx) & 0x3fff));
    assert((uintptr_t)rw + size <= (uintptr_t)rx || (uintptr_t)rx + size <= (uintptr_t)rw);
    ios_jit_rx_base_global = rx; ios_jit_rw_base_global = rw; ios_jit_pool_size_global = size;
    memset(rw, 0x55, size);
    assert(ios_fex_code_guard_arm(0, size));
    assert(ios_fex_code_guard_is_armed(guard));
    assert(!ios_jit_code_guard_contains((uintptr_t)rx, guard));
    assert(ios_jit_code_guard_contains((uintptr_t)rx + guard, 1));
    assert(ios_jit_code_guard_contains((uintptr_t)rw + size - 1, 1));
    assert(ios_jit_code_guard_contains((uintptr_t)rx + guard - 8, 16));
    assert(ios_jit_code_guard_contains(UINTPTR_MAX - 2, 4));
    assert(!ios_jit_code_guard_contains((uintptr_t)rx + size, 1));
    assert(!ios_write_alias((uintptr_t)rx + guard));
    assert(!ios_write_alias((uintptr_t)rw + guard));
    assert(ios_alias_write_is_trapped((uintptr_t)rx + guard));
    uintptr_t blocked;
    const uint64_t value = 0x1122334455667788ull;
    assert(ios_alias_write((uintptr_t)rx + 24, &value, 8, &blocked, 0));
    assert(!memcmp(rx + 24, &value, 8));
    unsigned char old[32], bytes[32]; memset(bytes, 0xff, 32);
    memcpy(old, rx + guard - 32, 32);
    for (int honor = 0; honor < 2; honor++)
    {
        assert(!ios_alias_write((uintptr_t)rx + guard - 8, bytes, 16, &blocked, honor));
        assert(!ios_alias_write((uintptr_t)rw + guard, bytes, 8, &blocked, honor));
    }
    assert(!memcmp(old, rx + guard - 32, 32));
    uint64_t regs[32] = {0}, saved[32];
    regs[8] = (uintptr_t)rx + guard - 16; memcpy(saved, regs, sizeof(regs));
    /* Exact previously fixed pre-index STR XZR,[X8,#16]! must refuse a guard
       without changing its base register or any neighboring bytes. */
    assert(!ios_alias_store_immediate(0xf8010d1f, (uintptr_t)rx + guard, regs, &blocked, 0));
    assert(!memcmp(regs, saved, sizeof(regs)));
    arm_thread_state64_t state = {0}, before;
    state.__x[8] = (uintptr_t)rx + guard - 16; state.__pc = 0x123400;
    before = state;
    assert(ios_store_split_crossing(0xf8010d1f, &state, NULL, (uintptr_t)rx, (uintptr_t)rw, size) == -1);
    assert(!memcmp(&before, &state, sizeof(state)));
    ucontext_t context = { .pc = 0x123400 }, original;
    for (unsigned kind = 0; kind < 3; kind++)
    {
        context.esr = kind == 0 ? (UINT64_C(0x24) << 26) :
                      kind == 1 ? (UINT64_C(0x24) << 26) | 0x40 : (UINT64_C(0x20) << 26);
        original = context;
        assert(ios_deliver_code_guard_signal(&context, rx + guard));
        assert(delivered.ExceptionCode == EXCEPTION_ACCESS_VIOLATION);
        assert(delivered.ExceptionAddress == (void *)context.pc && delivered.NumberParameters == 2);
        assert(delivered.ExceptionInformation[0] == (kind == 2 ? 8 : kind));
        assert(delivered.ExceptionInformation[1] == (uintptr_t)rx + guard);
        assert(!memcmp(&context, &original, sizeof(context)));
    }
    assert(deliveries == 3);
    assert(!ios_deliver_code_guard_signal(&context, rx + 24) && deliveries == 3);
    munmap(rx, size); munmap(rw, size); fclose(file);
    puts("PASS: production guard bitmap, alias/span/pre-index refusal and real AV record; PC/registers preserved");
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-code-guard-fault-') as tmp:
    src, exe = Path(tmp) / 'guard.c', Path(tmp) / 'guard'
    src.write_text(code)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    '-Wno-missing-field-initializers', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', '-I', str(ROOT / 'build/ntdll-unix'),
                    str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
