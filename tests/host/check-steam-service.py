#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright 2026 125hz
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Compile the production service-preparation policy against scripted Win32
outcomes. No Wine, Valve binaries, accounts, services or game data are used."""
from pathlib import Path
import os, subprocess, tempfile
root = Path(__file__).resolve().parents[2]
code = r'''
#include <assert.h>
#include "prepare.h"
static unsigned manager_error, initial, installed, installer_error, start_error;
static unsigned managers, queries, installs, starts;
static uint32_t manager(void) { managers++; return manager_error; }
static uint32_t query(void) { assert(managers == 1); queries++; return queries == 1 ? initial : installed; }
static uint32_t install(void) { assert(initial == 1060 && queries == 1); installs++; return installer_error; }
static uint32_t start(void) { assert(queries && (!installs || queries == 2)); starts++; return start_error; }
static struct service_ops ops = {manager, query, install, start};
static void reset(void) { manager_error=initial=installed=installer_error=start_error=0; managers=queries=installs=starts=0; }
int main(void) {
 reset(); initial=1060; assert(prepare_service(&ops)==0 && installs==1 && queries==2 && starts==1);
 reset(); assert(prepare_service(&ops)==0 && installs==0 && starts==1);
 reset(); manager_error=1722; assert(prepare_service(&ops)==1722 && queries==0 && installs==0 && starts==0);
 reset(); initial=5; assert(prepare_service(&ops)==5 && installs==0 && starts==0);
 reset(); initial=1072; assert(prepare_service(&ops)==1072 && installs==0 && starts==0);
 reset(); initial=1060; installed=1060; assert(prepare_service(&ops)==1060 && installs==1 && starts==0);
 reset(); initial=1060; installed=5; assert(prepare_service(&ops)==5 && starts==0);
 unsigned failures[] = {2,3,5,193,216,1460,1};
 for(unsigned i=0;i<sizeof(failures)/sizeof(failures[0]);i++) {
  reset(); initial=1060; installer_error=failures[i];
  assert(prepare_service(&ops)==failures[i] && queries==1 && starts==0);
 }
 reset(); start_error=1053; assert(prepare_service(&ops)==1053 && installs==0);
 reset(); start_error=1062; assert(prepare_service(&ops)==1062);
 return 0;
}
'''
with tempfile.TemporaryDirectory() as folder:
    t=Path(folder); source=t/'service.c'; source.write_text(code)
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-I'+str(root/'build/steam-service'),str(source),'-o',str(t/'service')],check=True)
    subprocess.run([str(t/'service')],check=True)
print('PASS real preparation policy: SCM ordering, missing-only install, requery, error preservation, start failures')
# Architecture and registry writes remain the genuine installer's responsibility.
s=(root/'build/steam-service/main.c').read_text()
for forbidden in ['CreateServiceW(', 'RegSetValue', 'CreateNamedPipe', 'WriteFile(', 'TerminateProcess(']:
    assert forbidden not in s, forbidden
assert 'SCS_32BIT_BINARY' in s and 'SCS_64BIT_BINARY' in s
assert 'QueryServiceStatusEx' in s and 'SERVICE_RUNNING' in s
swift=(root/'app/Madeira/MadeiraDock.swift').read_text()
assert 'madeira-steam-service.exe' in swift and '&& \\(executable)' in swift
view=(root/'app/Madeira/ContentView.swift').read_text()
assert 'madeira-steam-service.exe' in view and 'if not "%errorlevel%"=="0" exit /b %errorlevel%' in view
print('PASS helper uses real SCM and installer APIs; both launch routes gate on genuine results')

# The actual handoff policy requires evidence from held native handles. It must
# not turn an ordinary 1053, failed updater or second failed start into success.
handoff_code = r'''
#include <assert.h>
#include <stdio.h>
#include "update_handoff.h"
static struct steam_update_witness witness;
static uint32_t first, second, wait_error;
static unsigned starts, captures, waits;
static uint32_t attempt(void) {
    assert(starts < 2);
    return starts++ ? second : first;
}
static int capture(void) {
    assert(starts == 1 && first == 1053 && !captures && !waits);
    captures++;
    return steam_update_witness_matches(&witness);
}
static uint32_t wait_update(void) {
    assert(starts == 1 && captures == 1 && !waits);
    assert(steam_update_witness_matches(&witness));
    waits++;
    return wait_error;
}
static const struct steam_update_ops update = {attempt, capture, wait_update};
static void reset_update(void) {
    first = 1053; second = wait_error = 0;
    starts = captures = waits = 0;
    witness = (struct steam_update_witness){
        .parent_pid=0x48, .child_parent_pid=0x48,
        .attempt_started=100, .parent_created=110, .child_created=120,
        .parent_handle_valid=1, .parent_path_matches=1,
        .child_handle_valid=1, .child_path_matches=1,
        .parent_exited=1, .parent_exit_code=0
    };
}
static void refused(void) {
    assert(!steam_update_witness_matches(&witness));
    assert(service_start_with_update_handoff(&update) == 1053);
    assert(starts == 1 && captures == 1 && waits == 0);
}
int main(void) {
    /* Exact captured sequence: original service exits zero before connecting
     * its control pipe; its own legitimate updater must finish before retry. */
    reset_update();
    assert(service_start_with_update_handoff(&update) == 0);
    assert(starts == 2 && captures == 1 && waits == 1);

    reset_update(); first = 0;
    assert(service_start_with_update_handoff(&update) == 0);
    assert(starts == 1 && !captures && !waits);
    const uint32_t errors[] = {2,5,193,1060,1062,1072,1460,1722};
    for (unsigned i=0; i<sizeof(errors)/sizeof(*errors); i++) {
        reset_update(); first=errors[i];
        assert(service_start_with_update_handoff(&update) == errors[i]);
        assert(starts == 1 && !captures && !waits);
    }

    /* A candidate may be retained while its parent is still alive, but that
     * cannot authorize treating its parent's start failure as an update. */
    reset_update(); witness.parent_exited=0;
    assert(steam_update_child_matches(&witness)); refused();
    reset_update(); witness.parent_exit_code=1; refused();
    reset_update(); witness.parent_handle_valid=0; refused();
    reset_update(); witness.parent_path_matches=0; refused();
    reset_update(); witness.child_handle_valid=0; refused();
    reset_update(); witness.child_path_matches=0; refused();
    reset_update(); witness.parent_pid=0; witness.child_parent_pid=0; refused();
    reset_update(); witness.child_parent_pid=0x54; refused();
    reset_update(); witness.attempt_started=0; refused();
    reset_update(); witness.parent_created=0; refused();
    reset_update(); witness.child_created=99; refused(); /* pre-existing updater */
    reset_update(); witness.child_created=109; refused(); /* parent generation mismatch */
    reset_update(); witness.parent_created=121; refused(); /* reused numeric PID */
    reset_update(); witness.child_created=witness.parent_created;
    assert(steam_update_witness_matches(&witness)); /* equal timestamp is legal */

    const uint32_t wait_errors[] = {1,5,6,1067,1460};
    for (unsigned i=0; i<sizeof(wait_errors)/sizeof(*wait_errors); i++) {
        reset_update(); wait_error=wait_errors[i];
        assert(service_start_with_update_handoff(&update) == wait_errors[i]);
        assert(starts == 1 && captures == 1 && waits == 1);
    }
    const uint32_t retry_errors[] = {1053,1060,1062,1072,5};
    for (unsigned i=0; i<sizeof(retry_errors)/sizeof(*retry_errors); i++) {
        reset_update(); second=retry_errors[i];
        assert(service_start_with_update_handoff(&update) == retry_errors[i]);
        assert(starts == 2 && captures == 1 && waits == 1);
    }
    for (unsigned i=0; i<128; i++) {
        reset_update();
        /* Same numeric PID in a later run has a new held identity/time. */
        witness.attempt_started += i*100;
        witness.parent_created += i*100;
        witness.child_created += i*100;
        assert(service_start_with_update_handoff(&update) == 0);
        assert(starts == 2 && captures == 1 && waits == 1);
    }
    puts("PASS production Steam service handoff: original exit-zero plus verified updater, held parent/path/lineage/generation/time checks, real updater errors/timeouts, one retry only, ordinary failures preserved");
}
'''
with tempfile.TemporaryDirectory() as folder:
    t=Path(folder); source=t/'handoff.c'; source.write_text(handoff_code)
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all',
                    '-I'+str(root/'build/steam-service'),str(source),'-o',str(t/'handoff')],check=True)
    subprocess.run([str(t/'handoff')],check=True)

def production_function(signature):
    current = (root/'build/steam-service/main.c').read_text()
    start = current.index(signature)
    end = current.index('{', start)+1
    depth = 1
    while depth:
        depth += (current[end] == '{') - (current[end] == '}')
        end += 1
    return current[start:end]

# Execute the production full-image comparison and configured-path parser.
# QueryFullProcessImageName/GetProcessTimes remain mocked OS boundaries; basename
# matches, foreign paths and missing/failed identity queries cannot be witnesses.
identity_code = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>
typedef uint32_t DWORD;
typedef int BOOL;
typedef struct { DWORD dwLowDateTime, dwHighDateTime; } FILETIME;
typedef struct { const wchar_t *image; uint64_t created; } FakeProcess;
typedef FakeProcess *HANDLE;
#define TRUE 1
#define FALSE 0
static struct { wchar_t service_path[32768], updater_path[32768]; } update;
static unsigned fail_name, fail_times, fail_canonical, oversize_canonical;
static int _wcsnicmp(const wchar_t *a,const wchar_t *b,size_t n) {
    for (size_t i=0;i<n;i++) {
        wint_t x=towlower(a[i]), y=towlower(b[i]);
        if (x!=y) return x>y?1:-1;
        if (!x) return 0;
    }
    return 0;
}
static int _wcsicmp(const wchar_t *a,const wchar_t *b) {
    size_t n=wcslen(a), m=wcslen(b);
    return _wcsnicmp(a,b,(n>m?n:m)+1);
}
static BOOL QueryFullProcessImageNameW(HANDLE p,DWORD flags,wchar_t *out,DWORD *size) {
    assert(!flags && size && *size==32768);
    if (!p || fail_name) return FALSE;
    assert(wcslen(p->image)<*size);
    wcscpy(out,p->image); *size=wcslen(out); return TRUE;
}
static BOOL GetProcessTimes(HANDLE p,FILETIME *c,FILETIME *e,FILETIME *k,FILETIME *u) {
    (void)e;(void)k;(void)u;
    if (!p || fail_times) return FALSE;
    c->dwLowDateTime=(DWORD)p->created; c->dwHighDateTime=(DWORD)(p->created>>32);
    return TRUE;
}
static DWORD GetFullPathNameW(const wchar_t *p,DWORD size,wchar_t *out,wchar_t **file) {
    assert(size==32768);
    if (fail_canonical) return 0;
    if (oversize_canonical) return 32768;
    size_t n=wcslen(p); assert(n<size);
    wcscpy(out,p);
    if (file) { wchar_t *last=wcsrchr(out,L'\\'); *file=last?last+1:out; }
    return n;
}
''' + '\n'.join(production_function(name) for name in (
    'static uint64_t filetime_value(', 'static BOOL process_identity(',
    'static void configured_paths(')) + r'''
int main(void) {
    const wchar_t *service=L"C:\\Program Files (x86)\\Common Files\\Steam\\SteamService.exe";
    const wchar_t *child=L"C:\\Program Files (x86)\\Common Files\\Steam\\SteamServiceTmp.exe";
    configured_paths(L" \t\"C:\\Program Files (x86)\\Common Files\\Steam\\SteamService.exe\" /RunAsService");
    assert(!wcscmp(update.service_path,service) && !wcscmp(update.updater_path,child));
    configured_paths(L"C:\\Program Files (x86)\\Common Files\\Steam\\SteamService.exe /RunAsService");
    assert(!wcscmp(update.service_path,service) && !wcscmp(update.updater_path,child));
    const wchar_t *bad[]={NULL,L"",L"\"unterminated SteamService.exe",L"C:\\Other.exe",L"C:\\SteamService.exe.bak"};
    for (unsigned i=0;i<sizeof(bad)/sizeof(*bad);i++) {
        configured_paths(bad[i]); assert(!update.service_path[0] && !update.updater_path[0]);
    }
    wchar_t *huge=malloc(33020*sizeof(*huge)); assert(huge);
    wmemset(huge,L'X',33000); wcscpy(huge+33000,L".exe /RunAsService");
    configured_paths(huge); assert(!update.service_path[0]); free(huge);
    configured_paths(L"C:\\Program Files (x86)\\Common Files\\Steam\\SteamService.exe /RunAsService");
    FakeProcess process={service,0x100000002ull};
    uint64_t created=0;
    assert(process_identity((HANDLE)&process,update.service_path,&created) && created==0x100000002ull);
    process.image=L"c:\\program files (x86)\\common files\\steam\\STEAMSERVICE.EXE";
    assert(process_identity((HANDLE)&process,service,&created));
    process.image=L"C:\\Other\\SteamService.exe";
    assert(!process_identity((HANDLE)&process,service,&created)); /* same name, foreign directory */
    process.image=child;
    assert(!process_identity((HANDLE)&process,service,&created));
    assert(process_identity((HANDLE)&process,update.updater_path,&created));
    process.image=L"C:\\Other\\SteamServiceTmp.exe";
    assert(!process_identity((HANDLE)&process,update.updater_path,&created));
    process.image=service;
    fail_name=1; assert(!process_identity((HANDLE)&process,service,&created)); fail_name=0;
    fail_times=1; assert(!process_identity((HANDLE)&process,service,&created)); fail_times=0;
    fail_canonical=1; assert(!process_identity((HANDLE)&process,service,&created));
    configured_paths(service); assert(!update.service_path[0]); fail_canonical=0;
    oversize_canonical=1; assert(!process_identity((HANDLE)&process,service,&created));
    configured_paths(service); assert(!update.service_path[0]); oversize_canonical=0;
    assert(!process_identity(NULL,service,&created));
    puts("PASS production service/updater image identity: quoted/unquoted configured paths, exact directory and filename, case comparison, creation-time width, malformed/oversize paths and failed OS queries");
}
'''
with tempfile.TemporaryDirectory() as folder:
    t=Path(folder); source=t/'identity.c'; source.write_text(identity_code)
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all',
                    str(source),'-o',str(t/'identity')],check=True)
    subprocess.run([str(t/'identity')],check=True)

# Execute the final readiness loop verbatim, plus the actual worker/context
# release functions. A successful StartService call alone is not readiness.
attempt = production_function('static uint32_t start_attempt(')
ready_start = attempt.index('    begin = GetTickCount64();\n    DWORD previous_state')
ready_end = attempt.index('    CloseServiceHandle(service);', ready_start)
ready_loop = attempt[ready_start:ready_end]
worker_struct = s[s.index('struct start_call {'):s.index('\n',s.index('struct start_call {'))]
readiness_code = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint32_t DWORD;
typedef int32_t LONG;
typedef uint64_t ULONGLONG;
typedef void *SC_HANDLE;
typedef unsigned char BYTE;
#define WINAPI
#define MAXDWORD UINT32_MAX
#define SERVICE_RUNNING 4
#define SERVICE_STOPPED 1
#define SC_STATUS_PROCESS_INFO 0
#define ERROR_SERVICE_NOT_ACTIVE 1062
#define ERROR_TIMEOUT 1460
typedef struct {DWORD dwCurrentState,dwCheckPoint,dwWaitHint,dwServiceSpecificExitCode,dwWin32ExitCode;} SERVICE_STATUS_PROCESS;
static SERVICE_STATUS_PROCESS scripted[3];
static unsigned queries,sleeps,events,state_count,fail_query,freed,closed;
static ULONGLONG tick;
static DWORD query_error=5, start_error=1053;
static int start_ok;
static ULONGLONG GetTickCount64(void) {return tick;}
static void Sleep(DWORD ms) {assert(ms==250 && sleeps<125);tick+=ms;sleeps++;}
static void event(const char *name,DWORD value) {(void)value;assert(name);events++;}
static DWORD last_error(void) {return query_error;}
static int QueryServiceStatusEx(SC_HANDLE h,DWORD level,BYTE *out,DWORD size,DWORD *needed) {
    assert(h==(void *)1 && level==SC_STATUS_PROCESS_INFO && size==sizeof(SERVICE_STATUS_PROCESS));
    unsigned index=queries++;
    if (fail_query && queries==fail_query) return 0;
    assert(state_count);
    *(SERVICE_STATUS_PROCESS *)out=scripted[index<state_count?index:state_count-1];
    *needed=size;return 1;
}
static uint32_t wait_for_running(void) {
    SC_HANDLE service=(void *)1;
    ULONGLONG begin;
    DWORD error=0,needed=0;
''' + ready_loop + r'''
    return error;
}
static LONG InterlockedDecrement(volatile LONG *n) {return __atomic_sub_fetch(n,1,__ATOMIC_SEQ_CST);}
static void *GetProcessHeap(void) {return (void *)1;}
static int HeapFree(void *heap,DWORD flags,void *p) {assert(heap==(void *)1&&!flags&&p);freed++;free(p);return 1;}
static int StartServiceW(SC_HANDLE h,DWORD n,void *args) {assert(h==(void *)2&&!n&&!args);query_error=start_error;return start_ok;}
static int CloseServiceHandle(SC_HANDLE h) {assert(h==(void *)2&&!closed);closed++;return 1;}
''' + worker_struct + '\n' + production_function('static void release_start_call(') + '\n' + production_function('static DWORD WINAPI call_start_service(') + r'''
static void reset_running(void) {
    queries=sleeps=events=fail_query=0;state_count=1;tick=1000;query_error=5;
    memset(scripted,0,sizeof(scripted));
    scripted[0].dwCurrentState=2; scripted[0].dwWaitHint=1000;
}
int main(void) {
    reset_running();state_count=2;scripted[1].dwCurrentState=SERVICE_RUNNING;
    assert(!wait_for_running()&&queries==2&&sleeps==1&&events==6);
    reset_running();scripted[0].dwCurrentState=SERVICE_RUNNING;
    scripted[0].dwWin32ExitCode=1053;
    assert(!wait_for_running()&&queries==1&&!sleeps); /* real current state is authoritative */
    reset_running();state_count=2;scripted[1].dwCurrentState=SERVICE_STOPPED;
    scripted[1].dwWin32ExitCode=1053;
    assert(wait_for_running()==1053&&queries==2&&sleeps==1);
    reset_running();scripted[0].dwCurrentState=SERVICE_STOPPED;
    assert(wait_for_running()==ERROR_SERVICE_NOT_ACTIVE&&queries==1&&!sleeps);
    reset_running();scripted[0].dwCurrentState=SERVICE_STOPPED;
    scripted[0].dwWin32ExitCode=1066;scripted[0].dwServiceSpecificExitCode=77;
    assert(wait_for_running()==1066&&queries==1&&!sleeps);
    reset_running();fail_query=1;
    assert(wait_for_running()==5&&queries==1&&!sleeps&&!events);
    reset_running();fail_query=2;
    assert(wait_for_running()==5&&queries==2&&sleeps==1);
    reset_running();assert(wait_for_running()==ERROR_TIMEOUT&&queries==121&&sleeps==120&&events==3);
    reset_running();tick=UINT64_MAX-1000;
    assert(wait_for_running()==ERROR_TIMEOUT&&queries==121&&sleeps==120);

    struct start_call *call=calloc(1,sizeof(*call));assert(call);
    call->service=(void *)2;call->references=2;start_ok=0;
    assert(!call_start_service(call)); /* worker returns first: main still owns the result */
    assert(!freed&&closed==1&&call->references==1&&call->error==1053);
    release_start_call(call);assert(freed==1);
    call=calloc(1,sizeof(*call));assert(call);
    call->service=(void *)2;call->references=2;closed=0;start_ok=1;
    release_start_call(call); /* main times out first; late worker must retain valid context */
    assert(freed==1&&call->references==1);
    assert(!call_start_service(call));assert(freed==2&&closed==1);
    puts("PASS production SCM readiness/worker lifecycle: pending is not success, only SERVICE_RUNNING succeeds, query/stop/deadline errors preserved, bounded unchanged-state logging, worker-first and timeout-first context ownership");
}
'''
with tempfile.TemporaryDirectory() as folder:
    t=Path(folder); source=t/'readiness.c'; source.write_text(readiness_code)
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all',
                    str(source),'-o',str(t/'readiness')],check=True)
    subprocess.run([str(t/'readiness')],check=True)
