#!/usr/bin/env python3
"""Run the production ProcessWow64Information case with concurrent owners.

The AMD64 session's wow_peb is deliberately NULL/foreign while i386 children
query their own native PEB32. No Wine prefix or device files are touched.
"""
import os
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[2]
source = (root / 'build/ntdll-unix/process_ios.c').read_text()
start = source.index('    case ProcessWow64Information:')
case = source[start:source.index('    /* iOS-Madeira the single source of truth', start)]
assert '#ifdef WINE_IOS' in case and '[process-wow64-v1]' in case
assert 'is_old_wow64() ? (ULONG_PTR)peb : (ULONG_PTR)wow_peb' in case

code = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>
#include <pthread.h>
typedef uintptr_t ULONG_PTR;
typedef uint32_t NTSTATUS, ULONG;
typedef uint16_t WORD;
typedef void *HANDLE;
typedef struct { void *Peb; long WowTebOffset; } TEB;
typedef struct { uint32_t Peb; } WOW_TEB;
#define WINE_IOS 1
#define ProcessWow64Information 26
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004u
#define STATUS_INVALID_HANDLE 0xc0000008u
#define STATUS_ACCESS_DENIED 0xc0000022u
#define IMAGE_FILE_MACHINE_I386 0x014c
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_FILE_MACHINE_ARM64 0xaa64
static const ULONG_PTR page_size = 0x1000;
static const WORD native_machine = IMAGE_FILE_MACHINE_ARM64;
static _Thread_local TEB current_teb;
static _Atomic(ULONG_PTR) wow_peb;
static _Atomic unsigned logs;
static TEB *NtCurrentTeb(void) { return &current_teb; }
static WOW_TEB *get_wow_teb(TEB *teb) {
    return teb->WowTebOffset ? (WOW_TEB *)((char *)teb + teb->WowTebOffset) : NULL;
}
static HANDLE GetCurrentProcess(void) { return (void *)(intptr_t)-1; }
static int is_machine_64bit(WORD machine) {
    return machine == IMAGE_FILE_MACHINE_AMD64 || machine == IMAGE_FILE_MACHINE_ARM64;
}
static void diagnostic(int fd, const char *format, ...) {
    assert(fd == 2 && strstr(format, "[process-wow64-v1]"));
    atomic_fetch_add(&logs, 1);
}
#define dprintf diagnostic
struct response { WORD machine; ULONG_PTR peb; NTSTATUS status; uint64_t end_time; };
static const struct response responses[] = {
    {0,0,STATUS_INVALID_HANDLE,0},
    {IMAGE_FILE_MACHINE_AMD64,0x104734000,0,0},
    {IMAGE_FILE_MACHINE_I386,0x400310000,0,0},
    {IMAGE_FILE_MACHINE_ARM64,0x104bfc000,0,0},
    {IMAGE_FILE_MACHINE_I386,0x500310000,0,0},
    {IMAGE_FILE_MACHINE_I386,0x600310000,0,123}, /* exited: preserve upstream query */
    {0,0,STATUS_ACCESS_DENIED,0}
};
struct request { ULONG_PTR handle; };
static ULONG_PTR wine_server_obj_handle(HANDLE h) { return (ULONG_PTR)h; }
static NTSTATUS wine_server_call(struct request *req) {
    assert(req->handle < sizeof(responses)/sizeof(responses[0]));
    return responses[req->handle].status;
}
#define SERVER_START_REQ(kind) do { \
    struct request storage, *req = &storage; \
    const struct response *reply = &responses[(ULONG_PTR)handle];
#define SERVER_END_REQ } while (0)
static NTSTATUS query(HANDLE handle, void *info, ULONG size) {
    NTSTATUS ret = 0;
    ULONG len = 0;
    switch (ProcessWow64Information) {
''' + case + r'''
    default: assert(0);
    }
    return ret;
}
static ULONG_PTR self(void *peb, long wow_offset) {
    ULONG_PTR value = UINTPTR_MAX;
    current_teb.Peb = peb;
    current_teb.WowTebOffset = wow_offset;
    assert(!query(GetCurrentProcess(), &value, sizeof(value)));
    return value;
}
static void *worker(void *arg) {
    unsigned i = (unsigned)(uintptr_t)arg;
    const ULONG_PTR owner = i == 0 ? 0x104734000ull :
        i == 1 ? 0x104bfc000ull : 0x400310000ull + ((ULONG_PTR)(i-2) << 32);
    const int wow = i >= 2;
    for (unsigned j = 0; j < 20000; j++) {
        /* Simulate another pseudo-process boot/retirement changing the
         * session global. Production must never use that value here. */
        atomic_store(&wow_peb, j & 1 ? 0 : owner + 0x1000);
        assert(self((void *)owner, wow ? 0x2000 : 0) == (wow ? owner + 0x1000 : 0));
        ULONG_PTR value = UINTPTR_MAX;
        assert(!query((HANDLE)(uintptr_t)(wow ? 2 : 1), &value, sizeof(value)));
        assert(value == (wow ? 0x400311000ull : 0));
    }
    return NULL;
}
int main(void) {
    /* Reproduce a NULL/foreign session result while the actual caller owns
     * a companion WoW TEB. The repaired query returns its physical PEB32. */
    atomic_store(&wow_peb, 0);
    assert(!atomic_load(&wow_peb));
    assert(self((void *)0x400310000ull, 0x2000) == 0x400311000ull);
    atomic_store(&wow_peb, 0x500311000ull);
    assert(self((void *)0x400310000ull, 0x2000) != atomic_load(&wow_peb));
    assert(!self((void *)0x104734000ull, 0)); /* AMD64 root */
    assert(!self((void *)0x104bfc000ull, 0)); /* native ARM64 child */
    assert(!self(NULL, 0x2000));
    assert(self((void *)0x500310000ull, 0x2000) == 0x500311000ull);

    _Alignas(16) unsigned char allocation[0x2000] = {0};
    ULONG_PTR peb32 = self(allocation, 0x2000);
    /* Real wow64.dll first write: WOW64INFO follows PEB32 (size 0x480). */
    *(uint32_t *)(peb32 + 0x480) = 0x1000;
    assert(*(uint32_t *)(allocation + 0x1480) == 0x1000);
    assert(*(uint32_t *)(allocation + 0x480) == 0); /* native PEB unchanged */

    ULONG_PTR value = 0x12345678;
    assert(query(GetCurrentProcess(), &value, sizeof(value)-1) == STATUS_INFO_LENGTH_MISMATCH);
    assert(value == 0x12345678);
    assert(query((HANDLE)2, &value, sizeof(value)+1) == STATUS_INFO_LENGTH_MISMATCH);
    assert(value == 0x12345678);
    assert(query((HANDLE)0, &value, sizeof(value)) == STATUS_INVALID_HANDLE && value == 0x12345678);
    assert(query((HANDLE)6, &value, sizeof(value)) == STATUS_ACCESS_DENIED && value == 0x12345678);
    for (uintptr_t i = 1; i <= 5; i++) {
        assert(!query((HANDLE)i, &value, sizeof(value)));
        assert(value == (is_machine_64bit(responses[i].machine) ? 0 : responses[i].peb + 0x1000));
    }
    pthread_t threads[6];
    for (uintptr_t i = 0; i < 6; i++) assert(!pthread_create(&threads[i], NULL, worker, (void *)i));
    for (unsigned i = 0; i < 6; i++) assert(!pthread_join(threads[i], NULL));
    assert(atomic_load(&logs) == 16);
    /* Reuse an exited child's PEB for a native owner: its own TEB, rather
     * than a stale global or the reused address, determines the answer. */
    assert(!self((void *)0x400310000ull, 0));
    assert(self((void *)0x400310000ull, 0x2000) == 0x400311000ull);
    puts("PASS production ProcessWow64Information: AMD64 root/native children report zero; independent WoW64 children survive NULL/foreign session global, write own WOW64INFO, concurrent queries and owner reuse; remote handles/status/size behavior unchanged; diagnostics bounded");
}
'''
with tempfile.TemporaryDirectory() as directory:
    path = Path(directory)
    src, exe = path / 'owner.c', path / 'owner'
    src.write_text(code)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O1', '-g', '-Wall', '-Wextra',
                    '-Werror', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    '-pthread', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True, timeout=30)
