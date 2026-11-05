#!/usr/bin/env python3
"""Compile the actual pool classification and opt-in alias-demotion block."""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
signal = (root / 'build/ntdll-unix/signal_arm64_ios.c').read_text()
start = signal.index('enum { WX_SLOTS = 256, WX_THRESHOLD = 32 };')
end = signal.index('wx_done: ;', start) + len('wx_done: ;')
block = signal[start:end]
assert 'if (ios_wx_enabled() && !watch_hit && !in_jit)' in block
control = block.replace(' && !in_jit)', ')', 1)
start = signal.index('#define IOS_WX_MAX 256')
decl = signal[start:signal.index('static volatile unsigned ios_wx_repromotes;', start)]
start = signal.index('int in_low = rx && rw && sz && ios_jit_low_contains(')
classification = signal[start:signal.index('if (in_jit) {', start)]

code = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define PROT_READ 1
#define PROT_WRITE 2
#define STDERR_FILENO 2
DECL
static int enabled = 1;
static unsigned int transitions;
static unsigned max_prot = 7;
static uintptr_t rx = UINT64_C(0x300000000), rw = UINT64_C(0x348000000);
static size_t sz = 1152ULL << 20;
static uintptr_t low = UINT64_C(0x140000000), low_size = 64ULL << 20;
static int ios_jit_low_contains(uintptr_t a) { return a >= low && a - low < low_size; }
int ios_wx_enabled(void) { return enabled; }
static int capture(int fd, const char *format, ...)
{ assert(fd == STDERR_FILENO); (void)format; return 0; }
#define dprintf capture
static int mprotect(void *a, size_t size, int prot)
{
    assert(((uintptr_t)a & 0x3fff) == 0 && size == 0x4000 && prot == 3);
    transitions++; max_prot = 3; return 0;
}
static int is_pool(uint64_t fault_addr)
{
    CLASSIFY
    (void)watch_hit; (void)watch_prot; return in_jit;
}
static void actual(uint64_t fault_addr, int watch_hit)
{
    int in_jit = is_pool(fault_addr);
    BLOCK
}
static void previous(uint64_t fault_addr, int watch_hit)
{
    CONTROL
}
static void repeat(uintptr_t a, int watched)
{ for(unsigned int i = 0; i < 80; i++) actual(a, watched); }
int main(void)
{
    assert(is_pool(rx) && is_pool(rx + sz - 1) && !is_pool(rx - 1) && !is_pool(rx + sz));
    assert(is_pool(low) && is_pool(low + low_size - 1) && !is_pool(low - 1) && !is_pool(low + low_size));
    /* Control reproduces the irreversible lowering even on a data-only page
     * of the original debugger pool when its opt-in demoter sees hot stores. */
    for(unsigned int i = 0; i < 32; i++) previous(rx + 0xd0000, 0);
    assert(transitions == 1 && max_prot == 3);
    transitions = 0; max_prot = 7; memset(ios_wx_pages, 0, sizeof(ios_wx_pages));
    repeat(rx + 0xd0000, 0); repeat(rx + sz - 8, 0);
    repeat(low + 0x8000, 0); repeat(low + low_size - 8, 0);
    assert(!transitions && max_prot == 7);
    /* The fix protects the pool mapping, without disabling the existing
     * experimental policy for ordinary user aliases or bypassing watches. */
    repeat(UINT64_C(0x660004000), 1); assert(!transitions);
    enabled = 0; repeat(UINT64_C(0x660008000), 0); assert(!transitions);
    enabled = 1; repeat(UINT64_C(0x66000c000), 0); assert(transitions == 1);
    puts("PASS production demotion block: old pool poison reproduced; main/low RX remain executable; watched, disabled and ordinary alias behavior preserved");
}
'''.replace('DECL', decl).replace('CLASSIFY', classification).replace('BLOCK', block).replace('CONTROL', control)
with tempfile.TemporaryDirectory() as temp:
    source, exe = Path(temp) / 'check.c', Path(temp) / 'check'
    source.write_text(code)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all', str(source), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
