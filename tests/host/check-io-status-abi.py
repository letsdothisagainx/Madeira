#!/usr/bin/env python3
"""Regression for native I/O in a WoW64 process and delayed 32-bit completions.

Compile actual staged Wine publishers/PE helpers and the native ABI controller;
use real memory/threads/isolated faults. No Steam or service replies are mocked.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile
import shutil

root = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('io_stage', root / 'tools/build/stage-io-status-abi.py')
stager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stager)


def function(source, signature):
    start = source.index(signature)
    begin = source.index('{', start)
    end, depth = begin + 1, 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


with tempfile.TemporaryDirectory(prefix='madeira-io-abi-') as temp:
    folder = Path(temp)
    stager.stage(folder, root / 'wine')
    unix = (folder / 'dlls/ntdll/unix/unix_private.h').read_text()
    pe = (folder / 'dlls/wow64/wow64_private.h').read_text()
    native = (root / 'build/ntdll-unix/io_status_abi.c').read_text()
    server = (root / 'build/ntdll-unix/server_ios.c').read_text()
    producer = function(unix, 'static inline client_ptr_t iosb_client_ptr(')
    submit = function(unix, 'static inline struct async_data server_async(')
    io_struct = function(unix, 'struct async_fileio\n') + ';'
    complete = server[server.index('    case APC_ASYNC_IO:'):server.index('    /* in every APC below,')]
    scope = (folder / 'dlls/wow64/syscall.c').read_text()
    assert '__FINALLY_CTX( io_scope_leave, &scope )' in scope
    assert 'if (status && normal) RtlRaiseStatus( status );' in scope
    assert 'io->iosb32   = FALSE;' in (folder / 'dlls/ntdll/unix/file.c').read_text()
    code = r'''
#define _GNU_SOURCE
#define WINE_IOS 1
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include "io_status_abi.h"
typedef int BOOL, THREADINFOCLASS; typedef int32_t NTSTATUS;
typedef unsigned int ULONG, DWORD; typedef uintptr_t ULONG_PTR, client_ptr_t;
typedef void *HANDLE; typedef void *PIO_APC_ROUTINE;
#define TRUE 1
#define FALSE 0
#define STATUS_SUCCESS 0
#define STATUS_INVALID_HANDLE ((NTSTATUS)0xc0000008)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xc0000004)
#define STATUS_ACCESS_VIOLATION ((NTSTATUS)0xc0000005)
#define STATUS_REVISION_MISMATCH ((NTSTATUS)0xc0000059)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000d)
#define STATUS_PENDING 0x103
#define NtCurrentThread() ((HANDLE)(intptr_t)-2)
#define GetCurrentThread() NtCurrentThread()
typedef struct { union { NTSTATUS Status; void *Pointer; }; uintptr_t Information; } IO_STATUS_BLOCK;
typedef struct { union { NTSTATUS Status; uint32_t Pointer; }; uint32_t Information; } IO_STATUS_BLOCK32;
_Static_assert(offsetof(IO_STATUS_BLOCK,Information)==8, "native IOSB layout");
_Static_assert(offsetof(IO_STATUS_BLOCK32,Information)==4, "guest IOSB layout");
static BOOL virtual_check_buffer_for_read(const void *p, size_t n) { return p && n; }
static BOOL virtual_check_buffer_for_write(void *p, size_t n) { return p && n; }
static void *wine_server_get_ptr(client_ptr_t p) { return (void *)p; }
static client_ptr_t wine_server_client_ptr(const void *p) { return (uintptr_t)p; }
static unsigned wine_server_obj_handle(HANDLE h) { return (uintptr_t)h; }
#define WriteRelease(p,v) __atomic_store_n((p),(v),__ATOMIC_RELEASE)
typedef BOOL async_callback_t(void *,ULONG_PTR *,unsigned int *);
''' + native[native.index('static _Thread_local'):]+ r'''
static uintptr_t wow_guest_base = 0x600000000ull;
static NTSTATUS NtSetInformationThread(HANDLE h,THREADINFOCLASS c,const void *p,ULONG n) {
    assert(c==MADEIRA_THREAD_IO_ABI); return ios_io_status_control(h,p,n);
}
static void RtlRaiseStatus(NTSTATUS s) { fprintf(stderr,"unexpected private ABI failure %x\n",(unsigned)s); abort(); }
''' + function(pe, 'static inline void iosb_control(') + '\n' + function(pe, 'static inline IO_STATUS_BLOCK *iosb_32to64(') + '\n' + function(pe, 'static inline void put_iosb(') + '\n' + producer + '\n' + io_struct + r'''
struct async_data { unsigned handle; client_ptr_t user,iosb; unsigned event; client_ptr_t apc,apc_context; };
''' + submit + r'''
enum { APC_ASYNC_IO=1 };
union apc_call { unsigned type; struct { unsigned type,status; client_ptr_t user,sb; unsigned result; } async_io; };
union apc_result { unsigned type; struct { unsigned type,status,total; } async_io; };
static BOOL ios_trace_async_apc(const union apc_call *c,const char *p) { (void)c;(void)p; return FALSE; }
static void actual_complete(const union apc_call *call,union apc_result *result) { switch(call->type) {
''' + complete + r'''
} }
static BOOL finish_and_free(void *user,ULONG_PTR *info,unsigned int *status) {
    assert(*info==54); *status=0x80000005; free(user); return TRUE;
}
static struct async_data queued(IO_STATUS_BLOCK *io) {
    struct async_fileio *user=malloc(sizeof(*user)); assert(user);
    user->callback=finish_and_free; user->iosb32=FALSE;
    return server_async(NULL,user,NULL,NULL,NULL,iosb_client_ptr(io));
}
static void dispatch(struct async_data data) {
    union apc_call call={.async_io={.type=APC_ASYNC_IO,.user=data.user,.sb=data.iosb,.result=54}};
    union apc_result result={0}; actual_complete(&call,&result);
    assert(result.async_io.status==0x80000005u && result.async_io.total==54);
}
static NTSTATUS control(unsigned op,struct madeira_io_scope *s) {
    struct madeira_io_control c={MADEIRA_IO_ABI_VERSION,op,s,NULL,NULL};
    return ios_io_status_control(NtCurrentThread(),&c,sizeof(c));
}
static void *thread_test(void *unused) {
    (void)unused; struct madeira_io_scope s; IO_STATUS_BLOCK native={.Pointer=(void *)0x10000};
    IO_STATUS_BLOCK32 guest={0}; IO_STATUS_BLOCK wrapper;
    assert(!control(MADEIRA_IO_ENTER,&s)); iosb_32to64(&wrapper,&guest);
    assert(iosb_client_ptr(&wrapper)==(uintptr_t)&guest);
    assert(iosb_client_ptr(&native)==(uintptr_t)&native);
    put_iosb(&guest,&wrapper); assert(!control(MADEIRA_IO_LEAVE,&s)); return NULL;
}
int main(void) {
    struct rlimit core={0,0}; assert(!setrlimit(RLIMIT_CORE,&core));
    // Exact logged failure: native stack IOSB contains 0x10000 in a WoW64 process.
    IO_STATUS_BLOCK native={.Pointer=(void *)0x10000,.Information=0};
    assert(iosb_client_ptr(&native)==(uintptr_t)&native);
    dispatch(queued(&native));
    assert((unsigned)native.Status==0x80000005u && native.Information==54);
    // A return/code pointer in that union must never become a completion destination.
    uint32_t code_words[4]={0xd503201f,0xd503201f,0xd503201f,0xd503201f};
    native.Pointer=code_words; dispatch(queued(&native)); assert(code_words[1]==0xd503201f);
    // The former process-wide rule corrupts the next instruction with byte count 54.
    IO_STATUS_BLOCK32 *old_target=(IO_STATUS_BLOCK32 *)code_words;
    old_target->Information=54; assert(code_words[1]==0x36);
    struct madeira_io_scope outer,inner;
    assert(!control(MADEIRA_IO_ENTER,&outer));
    struct { IO_STATUS_BLOCK32 io; uint64_t canary; } guest={{.Status=STATUS_PENDING},0xfeedface87654321ull};
    IO_STATUS_BLOCK wrapper; iosb_32to64(&wrapper,&guest.io);
    struct async_data delayed=queued(&wrapper);
    assert(((struct async_fileio *)(uintptr_t)delayed.user)->iosb32);
    assert(delayed.iosb==(uintptr_t)&guest.io);
    assert(!control(MADEIRA_IO_ENTER,&inner));
    assert(iosb_client_ptr(&wrapper)==(uintptr_t)&guest.io); // nested native callback keeps outer provenance
    native.Pointer=(void *)0x10000; dispatch(queued(&native));
    assert(native.Information==54);
    assert(control(MADEIRA_IO_ENTER,&outer)==STATUS_INVALID_PARAMETER); // no scope cycles
    assert(control(MADEIRA_IO_LEAVE,&outer)==STATUS_INVALID_PARAMETER); // LIFO
    assert(!control(MADEIRA_IO_LEAVE,&inner));
    put_iosb(&guest.io,&wrapper); assert(!control(MADEIRA_IO_LEAVE,&outer));
    dispatch(delayed); // scope gone, callback frees metadata: layout still 32-bit
    assert((unsigned)guest.io.Status==0x80000005u && guest.io.Information==54);
    assert(guest.canary==0xfeedface87654321ull);
    pthread_t threads[4];
    for(int i=0;i<4;i++) assert(!pthread_create(&threads[i],NULL,thread_test,NULL));
    for(int i=0;i<4;i++) assert(!pthread_join(threads[i],NULL));
    pid_t child=fork(); assert(child>=0);
    if(!child) { signal(SIGSEGV,SIG_DFL); signal(SIGBUS,SIG_DFL); ios_complete_io_status(0x10000,0,54,FALSE); _exit(0); }
    int status; assert(waitpid(child,&status,0)==child);
    assert(WIFSIGNALED(status) && (WTERMSIG(status)==SIGSEGV || WTERMSIG(status)==SIGBUS));
    puts("PASS native 0x10000/code-pointer IOSBs, explicit guest proxies, nested/thread scopes, delayed completion/canary, original status and genuine fault");
}
'''
    path, binary = folder / 'test.c', folder / 'test'
    path.write_text(code)
    subprocess.run([os.environ.get('CC','cc'), '-std=gnu11','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-pthread','-I',str(root/'build/ntdll-unix'),
                    str(path),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,env=dict(os.environ,ASAN_OPTIONS='handle_segv=0:handle_sigbus=0'))
    # Exercise restoration on an isolated source checkout, including refusal
    # to overwrite an edit made while a build was running.
    source = folder / 'source'
    for name in stager.FILES:
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / 'wine' / name, target)
    subprocess.run(['git','init','-q',str(source)],check=True)
    subprocess.run(['git','-C',str(source),'add','.'],check=True)
    subprocess.run(['git','-C',str(source),'-c','user.name=Fixture','-c','user.email=fixture@example.invalid',
                    'commit','-qm','source fixture'],check=True)
    originals = {n:(source/n).read_bytes() for n in stager.FILES}
    state = folder / 'state'; state.mkdir()
    stager.apply(state,source)
    changed = source / stager.FILES[0]; staged_bytes = changed.read_bytes()
    changed.write_bytes(staged_bytes + b'/* concurrent edit */\n')
    try:
        stager.restore(state)
    except SystemExit as error:
        assert 'Refusing to overwrite changes' in str(error)
    else:
        raise AssertionError('concurrent source edit was overwritten')
    assert changed.read_bytes().endswith(b'/* concurrent edit */\n')
    changed.write_bytes(staged_bytes)
    stager.restore(state)
    assert all((source/n).read_bytes()==data for n,data in originals.items())
    assert not (source/stager.HEADER).exists()
    print('PASS Wine overlay restores exact original files and refuses concurrent edits')
