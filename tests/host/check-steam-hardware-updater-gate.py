#!/usr/bin/env python3
"""Run the literal old/new NtCreateUserProcess helper gate and real lifetime ledger.

Only the TEB, logging and downstream loader transport are owned test edges.
This does not claim that a Valve executable ran on an iPhone or passed VAC.
"""
from pathlib import Path
import hashlib
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'build/ntdll-unix/process_ios.c'
OLD = ROOT / 'tests/host/fixtures/steam-helper-gate-68461258.c.inc'
assert hashlib.sha256(OLD.read_bytes()).hexdigest() == '567eeeb28502cd0998a91771e68f0d44400ee2e957a13fdb53f09103c1c32db2'
text = SOURCE.read_text()

def function(name):
    start = text.index('static int ' + name + '(') if 'static int ' + name + '(' in text else text.index('static int ' + name + ' (')
    opening = text.index('{', start)
    depth, i = 1, opening + 1
    while depth:
        depth += (text[i] == '{') - (text[i] == '}')
        i += 1
    return text[start:i]

a = text.index('        static const char * const blocked_names[] =')
b = text.index('\n    }\n\n    /* conhost.exe is refused', a)
current = text[a:b]
assert 'b < 4' in OLD.read_text() and 'b < 4' not in current
assert 'hardware_self_reexec' in current

code = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>
typedef uint16_t WCHAR;
typedef int32_t NTSTATUS;
typedef struct { unsigned short Length, MaximumLength; WCHAR *Buffer; } UNICODE_STRING;
typedef struct { UNICODE_STRING ImagePathName, CommandLine; } RTL_USER_PROCESS_PARAMETERS;
typedef struct { RTL_USER_PROCESS_PARAMETERS *ProcessParameters; } PEB;
typedef struct { PEB *Peb; struct { void *UniqueProcess; } ClientId; } TEB;
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
#define HandleToULong(h) ((unsigned)(uintptr_t)(h))
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xc0000022u)
static _Thread_local TEB teb;
static _Thread_local unsigned downstream_calls;
static _Thread_local NTSTATUS downstream_status;
static _Atomic unsigned records;
static TEB *NtCurrentTeb(void) { return &teb; }
static const char *debugstr_us(const UNICODE_STRING *value) { (void)value; return "owned-image"; }
static int gate_dprintf(int fd, const char *format, ...) {
    char output[1024]; va_list args; (void)fd;
    va_start(args,format); int n=vsnprintf(output,sizeof(output),format,args); va_end(args);
    assert(n>=0 && (size_t)n<sizeof(output)); atomic_fetch_add(&records,1); return n;
}
#define dprintf gate_dprintf
#include "steam_handoff.h"
HELPERS
static NTSTATUS loader_transport(RTL_USER_PROCESS_PARAMETERS *params) {
    assert(params && params->ImagePathName.Buffer); ++downstream_calls; return downstream_status;
}
static NTSTATUS before_gate(RTL_USER_PROCESS_PARAMETERS *params) {
OLD_GATE
    return loader_transport(params);
}
static NTSTATUS after_gate(RTL_USER_PROCESS_PARAMETERS *params) {
NEW_GATE
    return loader_transport(params);
}
struct context { PEB peb; RTL_USER_PROCESS_PARAMETERS params; WCHAR image[1024]; unsigned pid; };
static const char steam[]="C:\\Program Files (x86)\\Steam\\steam.exe";
static const char updater[]="C:\\Program Files (x86)\\Steam\\bin\\hardwareupdater\\hardwareupdater.exe";
static struct context root_context, helper_context, other_context;
static UNICODE_STRING wide(const char *path, WCHAR *buffer) {
    size_t n=strlen(path); assert(n<1024);
    for(size_t i=0;i<=n;i++)buffer[i]=(unsigned char)path[i];
    return (UNICODE_STRING){(unsigned short)(n*2),(unsigned short)(n*2+2),buffer};
}
static void context(struct context *ctx,const char *path,unsigned pid) {
    memset(ctx,0,sizeof(*ctx));ctx->params.ImagePathName=wide(path,ctx->image);
    ctx->peb.ProcessParameters=&ctx->params;ctx->pid=pid;
}
static void current_context(struct context *ctx) {
    teb.Peb=&ctx->peb;teb.ClientId.UniqueProcess=(void *)(uintptr_t)ctx->pid;
}
static NTSTATUS request(int old,const char *path,NTSTATUS status) {
    WCHAR image[1024]={0},command[1024]={0},saved[1024];
    RTL_USER_PROCESS_PARAMETERS p={wide(path,image),wide("hardwareupdater.exe --check-for-updates",command)}, copy=p;
    memcpy(saved,image,sizeof(image));downstream_status=status;downstream_calls=0;
    NTSTATUS result=old?before_gate(&p):after_gate(&p);
    assert(!memcmp(&p,&copy,sizeof(p)) && !memcmp(saved,image,sizeof(image)));
    return result;
}
static void denied(int old,const char *path) {
    assert(request(old,path,0)==STATUS_ACCESS_DENIED && downstream_calls==0);
}
static void continued(int old,const char *path,NTSTATUS status) {
    assert(request(old,path,status)==status && downstream_calls==1);
}
static struct ios_child_token track(struct context *ctx,struct context *parent) {
    struct ios_child_token token=ios_child_slot_take(&ctx->params.ImagePathName,ctx->pid,parent->pid,
        &parent->peb,&root_context.peb,&parent->params.ImagePathName);
    ios_current_child=token;madeira_child_process_started(&ctx->peb,ctx->pid);return token;
}
static void begin(void) {
    unsetenv("MADEIRA_PROC_GATE_STEAM");unsetenv("MADEIRA_SPAWN_BLOCK");
    context(&root_context,steam,0x68);context(&helper_context,updater,0x2d0);
    context(&other_context,"C:\\Dock\\dockhost.exe",0x28);
    madeira_child_session_begin(1,1);current_context(&root_context);
}
static void comparisons(void) {
    WCHAR l[1024],r[1024];UNICODE_STRING left=wide(updater,l),right=wide(updater,r);
    assert(ios_same_image_path(&left,&right));
    right=wide("c:/PROGRAM FILES (x86)/Steam/bin/hardwareupdater/HARDWAREUPDATER.EXE",r);
    assert(ios_same_image_path(&left,&right));
    right=wide("\\??\\C:\\Program Files (x86)\\Steam\\bin\\hardwareupdater\\hardwareupdater.exe",r);
    assert(ios_same_image_path(&left,&right));
    right=wide("\\\\?\\C:\\Program Files (x86)\\Steam\\bin\\hardwareupdater\\hardwareupdater.exe",r);
    assert(ios_same_image_path(&left,&right));
    right=wide("D:\\Other\\hardwareupdater.exe",r);assert(!ios_same_image_path(&left,&right));
    right=wide("hardwareupdater.exe",r);left=wide("hardwareupdater.exe",l);
    assert(!ios_same_image_path(&left,&right));
    left=wide(updater,l);right=wide(updater,r);right.Length--;assert(!ios_same_image_path(&left,&right));
    right=wide(updater,r);right.MaximumLength=2;assert(!ios_same_image_path(&left,&right));
    right=wide(updater,r);right.Buffer=NULL;assert(!ios_same_image_path(&left,&right));
    assert(!ios_same_image_path(NULL,&left));
}
struct thread_arg { struct context ctx; struct ios_child_token token; };
static void *worker(void *argument) {
    struct thread_arg *a=argument; current_context(&a->ctx);
    for(unsigned i=0;i<512;i++)continued(0,updater,(NTSTATUS)(i&1?0xc0000017u:0));
    return NULL;
}
int main(void) {
    begin();comparisons();
    /* Twelve captured requests from Steam PID0068, TIDs025c/0214,20:53:21..53.
     * The literal684 gate denies each before the normal loader is entered. */
    for(unsigned i=0;i<12;i++){denied(1,updater);continued(0,updater,0);}
    puts("PASS captured twelve failures: literal old production gate refuses; corrected production gate reaches the real loader boundary without modifying parameters");
    const NTSTATUS errors[]={0,(NTSTATUS)0xc0000034u,(NTSTATUS)0xc000007bu,(NTSTATUS)0xc0000135u,(NTSTATUS)0xc0000017u};
    for(size_t i=0;i<ARRAY_SIZE(errors);i++)continued(0,updater,errors[i]);
    /* Explicit operator controls remain in force even for the permitted helper. */
    setenv("MADEIRA_PROC_GATE_STEAM","0",1);denied(0,updater);unsetenv("MADEIRA_PROC_GATE_STEAM");
    setenv("MADEIRA_SPAWN_BLOCK","HARDWAREUPDATER",1);denied(0,updater);unsetenv("MADEIRA_SPAWN_BLOCK");
    current_context(&other_context);denied(1,updater);denied(0,updater);
    current_context(&root_context);
    const char *prior[]={"steamerrorreporter64.exe","gldriverquery64.exe","vulkandriverquery64.exe","steamsysinfo.exe"};
    for(size_t i=0;i<ARRAY_SIZE(prior);i++){continued(1,prior[i],0);continued(0,prior[i],0);}
    denied(0,"C:\\Steam\\hardwareupdater\\different.exe");denied(0,"C:\\Steam\\hardwareupdater.exe.bak");
    denied(0,"UnityCrashHandler64.exe");continued(0,"C:\\Game\\ordinary.exe",0);
    puts("PASS existing helper/Dock/explicit-block policies, exact new helper basename, unchanged parameters and honest downstream failure propagation");
    /* Exercise the real Steam child ledger for the PyInstaller SAMEEXE stage. */
    struct ios_child_token first=track(&helper_context,&root_context);assert(first.slot>=0);
    current_context(&helper_context);denied(1,updater);continued(0,updater,0);
    for(size_t i=0;i<ARRAY_SIZE(errors);i++)continued(0,updater,errors[i]);
    denied(0,"C:\\Different\\hardwareupdater.exe");
    setenv("MADEIRA_PROC_GATE_STEAM","0",1);denied(0,updater);unsetenv("MADEIRA_PROC_GATE_STEAM");
    setenv("MADEIRA_SPAWN_BLOCK","hardwareupdater.exe",1);denied(0,updater);unsetenv("MADEIRA_SPAWN_BLOCK");
    struct context descendant;context(&descendant,updater,0x2d4);struct ios_child_token next=track(&descendant,&helper_context);
    assert(next.slot>=0);current_context(&descendant);continued(0,updater,0);
    current_context(&helper_context);
    pthread_mutex_lock(&ios_child_lock);ios_child_slots[first.slot].generation=0;pthread_mutex_unlock(&ios_child_lock);
    denied(0,updater);
    pthread_mutex_lock(&ios_child_lock);ios_child_slots[first.slot].generation=first.generation;pthread_mutex_unlock(&ios_child_lock);
    /* Same PID with a different canonical owner cannot borrow that record. */
    struct context foreign;context(&foreign,updater,helper_context.pid);current_context(&foreign);denied(0,updater);
    current_context(&helper_context);teb.ClientId.UniqueProcess=(void *)(uintptr_t)(helper_context.pid+4);denied(0,updater);
    current_context(&helper_context);madeira_child_server_exited(helper_context.pid,0);denied(0,updater);
    /* A replacement gets a new generation; the old release cannot clear it. */
    struct ios_child_token replacement=track(&helper_context,&root_context);assert(replacement.slot==first.slot && replacement.generation!=first.generation);
    ios_child_slot_release(first);current_context(&helper_context);continued(0,updater,0);
    madeira_child_session_begin(0,0);denied(0,updater); /* Dock session, even same image. */
    begin();current_context(&helper_context);denied(0,updater); /* untracked */
    struct ios_child_token unanchored=track(&helper_context,&other_context);assert(unanchored.slot>=0);denied(0,updater);
    puts("PASS required PyInstaller same-image reexec with real ledger ancestry; foreign/untracked/retired/Dock/zero-generation owners rejected and stale release cannot retire a replacement");
    begin();struct thread_arg args[8];pthread_t threads[8];
    for(unsigned i=0;i<8;i++){context(&args[i].ctx,updater,0x400+i*4);args[i].token=track(&args[i].ctx,&root_context);assert(args[i].token.slot>=0);}
    for(unsigned i=0;i<8;i++)assert(!pthread_create(&threads[i],NULL,worker,&args[i]));
    for(unsigned i=0;i<8;i++){assert(!pthread_join(threads[i],NULL));ios_child_slot_release(args[i].token);current_context(&args[i].ctx);denied(0,updater);}
    /* A full ledger must not manufacture ancestry for an untracked child. */
    begin();struct context fillers[IOS_CHILD_SLOTS];
    for(unsigned i=0;i<IOS_CHILD_SLOTS;i++){context(&fillers[i],"C:\\Steam\\filler.exe",0x500+i*4);assert(track(&fillers[i],&root_context).slot>=0);}
    assert(track(&helper_context,&root_context).slot<0);current_context(&helper_context);denied(0,updater);
    puts("PASS 4096 concurrent production reexec decisions, authoritative retirement, bounded-full-ledger honest refusal; no official helper execution or VAC claim");
    return 0;
}
'''
code = code.replace('HELPERS', '\n'.join(function(name) for name in ['ios_image_name_is', 'ios_same_image_path', 'ios_steam_hardware_updater_reexec']))
code = code.replace('OLD_GATE', OLD.read_text()).replace('NEW_GATE', current)
with tempfile.TemporaryDirectory(prefix='madeira-hardware-gate-') as directory:
    path = Path(directory); source = path / 'gate.c'; executable = path / 'gate'
    source.write_text(code)
    subprocess.run([os.environ.get('CC','cc'), '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-pthread',
                    '-I', str(ROOT / 'build/ntdll-unix'), str(source), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True, timeout=30)
