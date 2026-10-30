#!/usr/bin/env python3
"""The real IOSB publisher/observer preserve pointers, layouts and genuine faults."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
private = (root / 'wine/dlls/ntdll/unix/unix_private.h').read_text()
server = (root / 'build/ntdll-unix/server_ios.c').read_text()


def function(source, name):
    start = source.index(name)
    begin = source.index('{', start)
    end, depth = begin + 1, 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


register = function(server, 'void ios_trace_iosb_registration(')
observe = function(server, 'static BOOL ios_trace_async_apc(')
publish = function(private, 'static inline client_ptr_t iosb_client_ptr(')
complete = function(private, 'static inline void set_async_iosb(')
invoke = function(server, 'static void invoke_system_apc(')
assert invoke.index('ios_trace_async_apc( call, "before-callback" )') < invoke.index('user->callback(')
assert 'set_async_iosb( call->async_io.sb, result->async_io.status, info );' in invoke

code = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
typedef int BOOL; typedef uint64_t client_ptr_t; typedef uintptr_t ULONG_PTR; typedef int32_t NTSTATUS;
#define TRUE 1
#define FALSE 0
#define WOW64_TLS_CPURESERVED 1
typedef struct { union { NTSTATUS Status; void *Pointer; }; ULONG_PTR Information; } IO_STATUS_BLOCK;
typedef struct { union { NTSTATUS Status; uint32_t Pointer; }; uint32_t Information; } IO_STATUS_BLOCK32;
typedef struct { struct { void *UniqueProcess, *UniqueThread; } ClientId; void *Peb; void *TlsSlots[64]; } TEB;
union apc_call { struct { unsigned type, status; client_ptr_t user, sb; unsigned result; } async_io; };
static TEB current;
static BOOL wow;
static unsigned logs;
static TEB *NtCurrentTeb(void) { return &current; }
static uintptr_t ios_wow_host_base(void) { return wow ? 0x400000000ull : 0; }
static BOOL in_wow64_call(void) { return wow; }
static client_ptr_t wine_server_client_ptr(void *p) { return (uintptr_t)p; }
static void *wine_server_get_ptr(client_ptr_t p) { return (void *)(uintptr_t)p; }
#define WriteRelease(ptr, value) __atomic_store_n((ptr), (value), __ATOMIC_RELEASE)
static int capture(int fd, const char *format, ...) {
    (void)fd; (void)format; logs++; return 0;
}
#define dprintf capture
''' + publish + '\n' + complete + '\n' + register + '\n' + observe + r'''
#include "io_status_trace.h"
int main(void) {
    struct rlimit limit = {0, 0}; assert(!setrlimit(RLIMIT_CORE, &limit));
    IO_STATUS_BLOCK io64 = {.Status = 0x103, .Information = 0};
    IO_STATUS_BLOCK32 io32 = {.Status = 0x103, .Information = 0};
    IO_STATUS_BLOCK wrapper = {.Pointer = &io32};
    wow = FALSE;
    assert(iosb_client_ptr(&io64) == (uintptr_t)&io64);
    set_async_iosb((uintptr_t)&io64, 0, 0x1234567887654321ull);
    assert(io64.Status == 0 && io64.Information == 0x1234567887654321ull);
    wow = TRUE;
    assert(iosb_client_ptr(&wrapper) == (uintptr_t)&io32);
    set_async_iosb((uintptr_t)&io32, 0, 37);
    assert(io32.Status == 0 && io32.Information == 37);
    unsigned before = logs;
    for (unsigned i = 0; i < 100; i++) (void)iosb_client_ptr(&wrapper);
    assert(logs <= before + 8);
    // The bad pointer is observed, never repaired, translated or skipped.
    wrapper.Pointer = (void *)0x10000;
    assert(iosb_client_ptr(&wrapper) == 0x10000);
    union apc_call call = {.async_io = {.sb = 0x10000}};
    assert(ios_trace_async_apc(&call, "before-callback"));
    assert(call.async_io.sb == 0x10000);
    pid_t child = fork(); assert(child >= 0);
    if (!child) { set_async_iosb(call.async_io.sb, 0, 37); _exit(0); }
    int status; assert(waitpid(child, &status, 0) == child);
    assert(WIFSIGNALED(status) && (WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGBUS));
    puts("PASS: real native/WoW64 IOSB publication, bounded observation and invalid completion still faults");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-apc-io-') as temp:
    source, binary = Path(temp) / 'main.c', Path(temp) / 'check'
    source.write_text(code)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    '-I', str(root / 'build/ntdll-unix'), str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
