#!/usr/bin/env python3
"""Compile production DEP query/set and view-sweep code against shared owners.

November 8's device capture loads client.dll and embree3.dll successfully, then
loads libmpg123-0.dll on native CS2 TID 0310.  The following ordered protection
and image-copy burst matches the global DEP sweep, although the exact invoking
API was not logged.  This test proves the source-level defect: a foreign session
wow_peb must never authorize native CS2 to sweep historical/foreign PE views.

This harness replaces only OS/view-protection plumbing.  Architecture checks,
owner/window lookup, DEP flags, and the sweep are extracted from production.
No device, prefix, official binaries, or vendor source is modified.
"""
import os
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
arguments = argparse.ArgumentParser(description=__doc__)
arguments.add_argument('--source-dir', type=Path,
                       help='read saved process_ios.c/virtual_ios.c for before-fix replay')
args = arguments.parse_args()
source_dir = args.source_dir or ROOT / 'build/ntdll-unix'
process = (source_dir / 'process_ios.c').read_text()
virtual = (source_dir / 'virtual_ios.c').read_text()
private = (ROOT / 'wine/dlls/ntdll/unix/unix_private.h').read_text()


def function(source, name):
    match = re.search(r'^(?:static\s+)?(?:inline\s+)?[\w *]+\b' + name +
                      r'\s*\([^;{}]*\)\s*\{', source, re.M)
    if not match:
        raise AssertionError(f'production function missing: {name}')
    end = match.end()
    depth = 1
    while depth:
        if source[end] == '{':
            depth += 1
        elif source[end] == '}':
            depth -= 1
        end += 1
    return source[match.start():end]


query_start = process.index('    case ProcessExecuteFlags:')
query_case = process[query_start:process.index('    case ProcessPriorityClass:', query_start)]
set_start = process.index('    case ProcessExecuteFlags:', query_start + 1)
set_case = process[set_start:process.index('    case ProcessInstrumentationCallback:', set_start)]
window_functions = '\n\n'.join(function(virtual, name) for name in (
    'ios_wow_slot_for_peb', 'ios_wow_slot_boot', 'ios_wow_slot_current',
    'ios_wow_base_for_peb', 'ios_wow_base', 'ios_dep_per_process',
    'ios_wow_force_exec_at', 'ios_wow_force_exec_set_current',
    'ios_wow_exec_flags_current', 'ios_wow_exec_flags_store_current'))
dep_helper = function(process, 'ios_process_dep_is_wow64') if re.search(
    r'\bios_process_dep_is_wow64\s*\(', process) else ''

code = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
typedef int BOOL;
typedef uint8_t BYTE;
typedef uint32_t ULONG, NTSTATUS;
typedef uintptr_t ULONG_PTR;
typedef void *HANDLE;
typedef struct { void *Peb; long WowTebOffset; struct {HANDLE UniqueProcess;} ClientId; } TEB;
typedef struct { unsigned unused; } WOW_TEB, WOW_PEB;
#define TRUE 1
#define FALSE 0
#define WINE_IOS 1
#define ProcessExecuteFlags 34
#define STATUS_SUCCESS 0
#define STATUS_INVALID_PARAMETER 0xc000000du
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004u
#define STATUS_ACCESS_DENIED 0xc0000022u
#define MEM_EXECUTE_OPTION_ENABLE 1
#define MEM_EXECUTE_OPTION_DISABLE 2
#define MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION 4
#define MEM_EXECUTE_OPTION_PERMANENT 8
#define VPROT_COMMITTED 1
#define IOS_WOW_WINDOW_SIZE 0x100000000ull
#define IOS_WOW_MAX_WINDOWS 8
static const BOOL is_win64 = TRUE;
static _Thread_local TEB current_teb;
static _Atomic(WOW_PEB *) wow_peb;
int ios_wow64_by_teb __attribute__((weak)) = 1;
static TEB *NtCurrentTeb(void) {return &current_teb;}
static WOW_TEB *get_wow_teb(TEB *teb) {
    return teb && teb->WowTebOffset ? (WOW_TEB *)((char *)teb + teb->WowTebOffset) : NULL;
}
static void *ios_jit_current_peb(void) { return current_teb.Peb; }
static ULONG HandleToULong(HANDLE h) {return (ULONG)(uintptr_t)h;}
static pthread_mutex_t ios_wow_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t virtual_mutex = PTHREAD_MUTEX_INITIALIZER;
struct ios_wow_window {
    void *peb;
    ULONG_PTR base;
    unsigned leaked, dead;
    pthread_t owner;
    unsigned force_exec, exec_flags_set;
    ULONG exec_flags;
    unsigned generation;
};
static struct ios_wow_window ios_wow_windows[IOS_WOW_MAX_WINDOWS];
static unsigned ios_wow_window_count;
static _Thread_local struct ios_wow_window *ios_wow_boot_slot;
static _Thread_local unsigned ios_wow_boot_generation;
static ULONG execute_flags = MEM_EXECUTE_OPTION_DISABLE;
static BOOL force_exec_prot;
static _Atomic unsigned reports;
static void diagnostic(int fd, const char *format, ...) {
    assert(fd == 2 && format);
    reports++;
}
#define dprintf diagnostic
''' + function(private, 'is_wow64') + '\n' + window_functions + r'''
struct file_view {
    void *base;
    size_t size;
    unsigned valloc;
    unsigned protect_count;
};
static struct file_view views[] = {
    {(void *)0x103100000ull, 0x4000, 1, 0}, /* native non-image view */
    {(void *)0x108800000ull, 0x10000, 0, 0}, /* native CS2 image */
    {(void *)0x135600000ull, 0x2e0000, 0, 0}, /* retired steamsysinfo.exe */
    {(void *)0x15b510000ull, 0xf1000, 0, 0}, /* retired opengl-program.exe */
    {(void *)0x500400000ull, 0x10000, 0, 0}, /* current I386 owner */
    {(void *)0x600400000ull, 0x10000, 0, 0}, /* foreign I386 owner */
};
static unsigned views_tree;
static unsigned protection_calls, executable_copies;
#define WINE_RB_FOR_EACH_ENTRY(view, tree, type, entry) \
    for (unsigned view_index=0; (void)(tree), view_index < sizeof(views)/sizeof(views[0]) && \
         (((view)=&views[view_index]), 1); view_index++)
static void server_enter_uninterrupted_section(pthread_mutex_t *mutex, sigset_t *sigset) {
    (void)sigset;
    assert(!pthread_mutex_lock(mutex));
}
static void server_leave_uninterrupted_section(pthread_mutex_t *mutex, sigset_t *sigset) {
    (void)sigset;
    assert(!pthread_mutex_unlock(mutex));
}
static int is_view_valloc(const struct file_view *view) {return view->valloc;}
static void mprotect_range(void *base, size_t size, BYTE commit, int clear) {
    (void)commit; (void)clear;
    protection_calls++;
    for (unsigned i=0; i<sizeof(views)/sizeof(views[0]); i++) {
        if (views[i].base != base) continue;
        assert(views[i].size == size);
        views[i].protect_count++;
        /* A forced-executable foreign PE reaches production mprotect_exec's
         * image-copy path.  Count that boundary without manufacturing code. */
        if (!views[i].valloc && (force_exec_prot || ios_wow_force_exec_at(base)))
            executable_copies++;
        return;
    }
    assert(0 && "unknown view");
}
''' + function(virtual, 'virtual_set_force_exec') + '\n' + dep_helper + r'''
static NTSTATUS query(void *info, ULONG size) {
    NTSTATUS ret = STATUS_SUCCESS;
    ULONG len = 0;
    switch (ProcessExecuteFlags) {
''' + query_case + r'''
    default: assert(0);
    }
    return ret;
}
static NTSTATUS set(void *info, ULONG size) {
    NTSTATUS ret = STATUS_SUCCESS;
    switch (ProcessExecuteFlags) {
''' + set_case + r'''
    default: assert(0);
    }
    return ret;
}
static unsigned failures;
#define CHECK(condition, message) do { if (!(condition)) { \
    fprintf(stderr,"FAIL %s (line %u)\n", message, __LINE__); failures++; \
} } while (0)
static void reset(void) {
    memset(ios_wow_windows, 0, sizeof(ios_wow_windows));
    ios_wow_window_count = 2;
    ios_wow_windows[0] = (struct ios_wow_window){
        .peb=(void *)0x500310000ull, .base=0x500000000ull, .generation=7};
    ios_wow_windows[1] = (struct ios_wow_window){
        .peb=(void *)0x600310000ull, .base=0x600000000ull, .generation=9};
    current_teb = (TEB){.Peb=(void *)0x108118000ull, .ClientId={.UniqueProcess=(void *)0x30c}};
    ios_wow_boot_slot = NULL;
    ios_wow_boot_generation = 0;
    atomic_store(&wow_peb,(WOW_PEB *)0x500311000ull);
    execute_flags = MEM_EXECUTE_OPTION_DISABLE;
    force_exec_prot = FALSE;
    protection_calls = executable_copies = reports = 0;
    for (unsigned i=0; i<sizeof(views)/sizeof(views[0]); i++) views[i].protect_count=0;
}
static void select_wow(unsigned index) {
    current_teb.Peb = ios_wow_windows[index].peb;
    current_teb.WowTebOffset = 0x2000;
    current_teb.ClientId.UniqueProcess=(void *)(uintptr_t)(0x90+index*4);
}
static void native_rejection(void) {
    reset();
    /* Exact bad precondition: is_wow64() is TRUE for native CS2 because an
     * unrelated I386 browser has initialized the session-global wow_peb. */
    CHECK(is_wow64(), "fixture reproduces contaminated session architecture");
    CHECK(!get_wow_teb(NtCurrentTeb()), "CS2 has no companion I386 TEB");
    CHECK(!ios_wow_base_for_peb(current_teb.Peb), "CS2 owns no WoW window");
    ULONG flags = 0;
    CHECK(!query(&flags,sizeof(flags)), "native DEP query succeeds");
    CHECK(flags == (MEM_EXECUTE_OPTION_DISABLE|MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION|
                     MEM_EXECUTE_OPTION_PERMANENT), "native DEP is permanently enabled");
    flags=MEM_EXECUTE_OPTION_ENABLE;
    CHECK(set(&flags,sizeof(flags)) == STATUS_INVALID_PARAMETER,
          "native DEP-off request rejected despite foreign session wow_peb");
    CHECK(!force_exec_prot && execute_flags==MEM_EXECUTE_OPTION_DISABLE,
          "native request does not mutate session execution flags");
    CHECK(!protection_calls && !executable_copies,
          "native request cannot sweep/copy historical and foreign PE mappings");

    reset();
    /* Fail closed even if an internal caller bypasses NtSetInformationProcess. */
    virtual_set_force_exec(TRUE);
    CHECK(!force_exec_prot && !protection_calls && !executable_copies,
          "direct no-window DEP call cannot fall through into global sweep");
}
static void live_wow_scope(void) {
    reset(); select_wow(0);
    ULONG flags=MEM_EXECUTE_OPTION_ENABLE, queried=0;
    CHECK(!set(&flags,sizeof(flags)), "live I386 owner can turn DEP off");
    CHECK(!query(&queried,sizeof(queried)) && queried==flags,
          "I386 query uses the same owner's flag storage");
    CHECK(ios_wow_windows[0].force_exec && !ios_wow_windows[1].force_exec && !force_exec_prot,
          "only current live window carries DEP-off state");
    CHECK(protection_calls==1 && views[4].protect_count==1 && executable_copies==1,
          "DEP sweep visits only current owner's 4 GiB window");
    for (unsigned i=0;i<sizeof(views)/sizeof(views[0]);i++)
        if (i!=4) CHECK(!views[i].protect_count,"foreign and native views remain untouched");
    CHECK(!set(&flags,sizeof(flags)) && protection_calls==1,
          "repeated identical request performs no second sweep");
    flags=MEM_EXECUTE_OPTION_DISABLE|MEM_EXECUTE_OPTION_PERMANENT;
    CHECK(!set(&flags,sizeof(flags)) && !ios_wow_windows[0].force_exec,
          "valid current process can permanently enable DEP");
    flags=MEM_EXECUTE_OPTION_ENABLE;
    CHECK(set(&flags,sizeof(flags))==STATUS_ACCESS_DENIED,
          "permanent DEP cannot subsequently be disabled");
    select_wow(1);
    CHECK(!set(&flags,sizeof(flags)) && ios_wow_windows[1].force_exec,
          "another process's permanent flags do not forbid its own DEP choice");
}
static void missing_and_recycled_owner(void) {
    reset(); current_teb.WowTebOffset=0x2000;
    ULONG flags=MEM_EXECUTE_OPTION_ENABLE;
    CHECK(set(&flags,sizeof(flags))==STATUS_INVALID_PARAMETER,
          "companion TEB without a live owned window fails closed");
    CHECK(!force_exec_prot && !protection_calls,"missing-window request changes no state");
    reset(); select_wow(0); ios_wow_windows[0].dead=1;
    CHECK(set(&flags,sizeof(flags))==STATUS_INVALID_PARAMETER,
          "retired owner cannot change session DEP");
    reset(); select_wow(0); ios_wow_windows[0].leaked=1;
    CHECK(set(&flags,sizeof(flags))==STATUS_INVALID_PARAMETER,
          "quarantined owner cannot change session DEP");
    reset(); select_wow(0);
    ios_wow_boot_slot=&ios_wow_windows[0];
    ios_wow_boot_generation=7;
    ios_wow_windows[0].generation=8;
    ios_wow_windows[0].peb=(void *)0x700310000ull;
    ios_wow_windows[0].owner=pthread_self();
    CHECK(!ios_wow_slot_boot(),"stale reservation generation is not ownership proof");
    CHECK(set(&flags,sizeof(flags))==STATUS_INVALID_PARAMETER,
          "old owner cannot adopt recycled window through stale bootstrap token");
    CHECK(!force_exec_prot && !protection_calls,"recycled owner does not sweep");
}
static void independent_teb_and_binding(void) {
    reset(); select_wow(0);
    atomic_store(&wow_peb,NULL);
    ULONG flags=MEM_EXECUTE_OPTION_ENABLE, queried=0;
    CHECK(is_wow64(),"own companion TEB identifies I386 when session wow_peb is NULL");
    CHECK(!set(&flags,sizeof(flags)) && !query(&queried,sizeof(queried)) && queried==flags,
          "own live I386 TEB/window remains authoritative with NULL session state");
    CHECK(protection_calls==1 && views[4].protect_count==1 && !force_exec_prot,
          "NULL session state preserves scoped I386 sweep");

    reset();
    current_teb.Peb=ios_wow_windows[0].peb;
    CHECK(!get_wow_teb(NtCurrentTeb()) && ios_wow_base_for_peb(current_teb.Peb),
          "fixture native TEB happens to match a live window's PEB");
    CHECK(set(&flags,sizeof(flags))==STATUS_INVALID_PARAMETER && !protection_calls,
          "window address alone cannot turn native TEB into I386");
    CHECK(!query(&queried,sizeof(queried)) &&
          queried==(MEM_EXECUTE_OPTION_DISABLE|MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION|
                    MEM_EXECUTE_OPTION_PERMANENT),
          "matching window without companion still reports permanent native DEP");

    reset(); select_wow(0);
    ios_wow_windows[0].peb=NULL;
    ios_wow_windows[0].owner=pthread_self();
    ios_wow_boot_slot=&ios_wow_windows[0];
    ios_wow_boot_generation=ios_wow_windows[0].generation;
    CHECK(ios_wow_slot_boot()==ios_wow_boot_slot,
          "fixture has legitimate unbound bootstrap reservation token");
    CHECK(set(&flags,sizeof(flags))==STATUS_INVALID_PARAMETER && !protection_calls,
          "bootstrap token does not authorize DEP syscall before owner bind");
    ios_wow_windows[0].peb=current_teb.Peb;
    CHECK(!set(&flags,sizeof(flags)) && views[4].protect_count==1 && !force_exec_prot,
          "bound bootstrap owner can subsequently change only its own DEP");
}
static void *concurrent_owner(void *argument) {
    unsigned index=(unsigned)(uintptr_t)argument;
    select_wow(index);
    for (unsigned i=0;i<2000;i++) {
        ULONG flags=i&1?MEM_EXECUTE_OPTION_ENABLE:MEM_EXECUTE_OPTION_DISABLE, queried=0;
        assert(!set(&flags,sizeof(flags)));
        assert(!query(&queried,sizeof(queried)) && queried==flags);
    }
    return NULL;
}
static void concurrent_owners(void) {
    reset();
    pthread_t threads[2];
    for (uintptr_t i=0;i<2;i++) assert(!pthread_create(&threads[i],NULL,concurrent_owner,(void *)i));
    for (unsigned i=0;i<2;i++) assert(!pthread_join(threads[i],NULL));
    CHECK(!force_exec_prot,"concurrent I386 DEP changes leave session flag disabled");
    for (unsigned i=0;i<4;i++)
        CHECK(!views[i].protect_count,"concurrent process transitions leave native/historical images untouched");
    CHECK(views[4].protect_count==1999 && views[5].protect_count==1999,
          "both live owners retain independent repeated DEP transitions");
}
int main(int argc,char **argv) {
    if (argc>1 && !strcmp(argv[1],"legacy")) {
        reset();
        virtual_set_force_exec(TRUE);
        CHECK(force_exec_prot && protection_calls==6 && executable_copies==5,
              "explicit legacy environment preserves historical global internal sweep");
        /* Opting out of scoped sweeps still does not turn native64 into I386. */
        reset();
        ULONG flags=MEM_EXECUTE_OPTION_ENABLE;
        CHECK(set(&flags,sizeof(flags))==STATUS_INVALID_PARAMETER && !protection_calls,
              "explicit historical sweep option does not override native architecture");
    } else {
        native_rejection(); live_wow_scope(); missing_and_recycled_owner();
        independent_teb_and_binding(); concurrent_owners();
    }
    if (failures) return 1;
    puts("PASS production DEP isolation: native64 rejects foreign-session WoW identity; own live I386 window only; no missing/stale owner fallback; independent concurrent flags and scoped sweeps; legacy sweep requires explicit opt-out");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-dep-isolation-') as directory:
    path = Path(directory)
    source, executable = path / 'dep.c', path / 'dep'
    source.write_text(code)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O1', '-g', '-Wall', '-Wextra',
                    '-Werror', '-Wno-unused-function', '-Wno-address', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', '-pthread', str(source), '-o', str(executable)],
                   check=True)
    environment = dict(os.environ, MADEIRA_DEP_PER_PROCESS='1')
    subprocess.run([str(executable)], env=environment, check=True, timeout=30)
    environment['MADEIRA_DEP_PER_PROCESS'] = '0'
    subprocess.run([str(executable), 'legacy'], env=environment, check=True, timeout=30)
