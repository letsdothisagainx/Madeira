#!/usr/bin/env python3
"""Execute the production geometry observer at stubbed Wine query boundaries.

No Wine process, window, renderer or GPU is emulated. Numeric snapshots and
query outcomes are fixtures; the production filter, budget, error handling,
reporting and immutable-input source staging are exercised directly.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--wine-root', type=Path, default=ROOT / 'wine')
args = parser.parse_args()
header = ROOT / 'build/win32u-unix/window_geometry.h'
stager = ROOT / 'tools/build/stage-window-geometry.py'
source_path = args.wine_root / 'dlls/win32u/window.c'
original = source_path.read_bytes()
spec = importlib.util.spec_from_file_location('window_geometry_stage', stager)
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)

transformed = stage.stage(original.decode())
assert transformed.count('#include "window_geometry.h"') == 1
assert transformed.count('madeira_window_geometry_begin(') == 1
assert transformed.count('madeira_window_geometry_defaults(') == 1
assert transformed.count('madeira_window_geometry_rects(') == 2
assert transformed.count('if (md_geometry.sequence) md_geometry.window_dpi = win_dpi;') == 1
assert ('    win_dpi = get_dpi_for_window( hwnd );\n'
        '    if (md_geometry.sequence) md_geometry.window_dpi = win_dpi;') in transformed
assert transformed.count('return madeira_window_geometry_result( &md_geometry, 0 );') == 7
assert transformed.count('return madeira_window_geometry_result( &md_geometry, hwnd );') == 1
assert transformed.index('madeira_window_geometry_defaults(') > transformed.index('    fix_cs_coordinates( &cs, &sw );')
assert transformed.index('madeira_window_geometry_rects( &md_geometry, &new_rects, 1 );') > transformed.index(
    '        map_window_points( 0, parent, (POINT *)&new_rects.client, 2, win_dpi );')
# Removing the inserted observations restores the exact original source. No
# original expression, branch, callback, return value or error path is replaced.
restored = transformed.replace('#include "window_geometry.h"\n\n', '', 1)
restored = restored.replace('    struct madeira_window_geometry md_geometry = madeira_window_geometry_begin(\n'
                            '        style, ex_style, x, y, cx, cy, parent);\n', '', 1)
restored = restored.replace('\n    madeira_window_geometry_defaults( &md_geometry, &cs );', '', 1)
restored = restored.replace('\n    if (md_geometry.sequence) md_geometry.window_dpi = win_dpi;', '', 1)
restored = restored.replace('    madeira_window_geometry_rects( &md_geometry, &new_rects, 0 );\n', '', 1)
restored = restored.replace('\n        madeira_window_geometry_rects( &md_geometry, &new_rects, 1 );', '', 1)
restored = restored.replace('return madeira_window_geometry_result( &md_geometry, 0 );', 'return 0;')
restored = restored.replace('return madeira_window_geometry_result( &md_geometry, hwnd );', 'return hwnd;')
assert restored.encode() == original, 'geometry staging changed production window behavior'
for changed in (
        transformed,
        original.decode().replace('    fix_cs_coordinates( &cs, &sw );', '    changed_default_boundary( &cs, &sw );'),
        original.decode().replace('HWND WINAPI NtUserCreateWindowEx(', 'HWND WINAPI changed_CreateWindowEx('),
        original.decode().replace('    fix_cs_coordinates( &cs, &sw );', '    fix_cs_coordinates( &cs, &sw );\n    fix_cs_coordinates( &cs, &sw );'),
        original.decode().replace('return hwnd;', 'return hwnd; /* unchanged return contract? */', 1).replace(
            'return 0;  /* WS_CHILD needs a parent, but WS_POPUP doesn\'t */', 'return NULL;  /* changed early exit */')):
    try:
        stage.stage(changed)
    except ValueError:
        pass
    else:
        raise AssertionError('changed, duplicated or already staged Wine boundary accepted')

harness = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint16_t WCHAR;
typedef uintptr_t HWND;
typedef unsigned UINT, DWORD;
typedef int BOOL;
typedef struct { int left, top, right, bottom; } RECT;
typedef struct { WCHAR *Buffer; unsigned short Length, MaximumLength; } UNICODE_STRING;
typedef struct { UNICODE_STRING ImagePathName; } RTL_USER_PROCESS_PARAMETERS;
typedef struct { RTL_USER_PROCESS_PARAMETERS *ProcessParameters; } PEB;
typedef struct { PEB *Peb; DWORD LastErrorValue; int WowTebOffset; } TEB;
typedef struct { int x, y, cx, cy; } CREATESTRUCTW;
struct window_rects { RECT window, client, visible; };
#define WS_CHILD 0x40000000u
#define HWND_MESSAGE ((HWND)(uintptr_t)-3)
#define COORDS_SCREEN 3
static _Thread_local TEB current_teb;
static _Thread_local TEB *teb_pointer;
static _Thread_local unsigned current_pid, current_tid;
static _Thread_local unsigned monitor_success, raw_dpi, query_success;
static _Thread_local unsigned monitor_calls, query_calls;
static _Thread_local struct window_rects query_geometry;
static WCHAR image[1100];
static RTL_USER_PROCESS_PARAMETERS parameters;
static PEB owners[40];
static pthread_mutex_t capture_lock = PTHREAD_MUTEX_INITIALIZER;
static char output[200000];
static size_t output_used;
static unsigned reports;
static TEB *NtCurrentTeb(void) { return teb_pointer; }
static unsigned GetCurrentProcessId(void) { errno=EIO; current_teb.LastErrorValue=991; return current_pid; }
static unsigned GetCurrentThreadId(void) { errno=ENOSPC; current_teb.LastErrorValue=992; return current_tid; }
static UINT get_thread_dpi(void) { errno=EACCES; current_teb.LastErrorValue=996; return 96; }
static UINT get_win_monitor_dpi(HWND hwnd, UINT *dpi) {
    assert(hwnd==0x1234); monitor_calls++; errno=EIO; current_teb.LastErrorValue=993;
    *dpi=raw_dpi; return monitor_success;
}
static BOOL get_window_rects(HWND hwnd, int coords, struct window_rects *rects, UINT dpi) {
    assert(hwnd==0x1234 && coords==COORDS_SCREEN && dpi==raw_dpi);
    query_calls++; errno=EBADF; current_teb.LastErrorValue=994;
    if (query_success) *rects=query_geometry;
    return query_success;
}
static int capture(int fd, const char *format, ...) {
    assert(fd==2); va_list ap;
    pthread_mutex_lock(&capture_lock);
    va_start(ap,format);
    int n=vsnprintf(output+output_used,sizeof(output)-output_used,format,ap);
    va_end(ap);
    assert(n>0 && (size_t)n<sizeof(output)-output_used);
    output_used+=(size_t)n; reports++;
    pthread_mutex_unlock(&capture_lock);
    errno=EPIPE; current_teb.LastErrorValue=995;
    return n;
}
#define dprintf capture
#include "HEADER"
#undef dprintf

static void set_image(const char *text) {
    size_t n=strlen(text); assert(n<sizeof(image)/sizeof(image[0]));
    for(size_t i=0;i<=n;i++) image[i]=(unsigned char)text[i];
    parameters.ImagePathName=(UNICODE_STRING){image,(unsigned short)(n*2),(unsigned short)((n+1)*2)};
}
static void identity(unsigned owner, unsigned pid, unsigned tid) {
    assert(owner<40);
    current_teb=(TEB){.Peb=&owners[owner],.LastErrorValue=77}; teb_pointer=&current_teb;
    current_pid=pid; current_tid=tid;
    monitor_success=96; raw_dpi=144; query_success=1; monitor_calls=query_calls=0;
    query_geometry=(struct window_rects){{70,-20,730,470},{80,0,720,450},{80,0,720,450}};
    errno=EDOM;
}
static struct madeira_window_geometry begin(unsigned style, HWND parent) {
    current_teb.LastErrorValue=77; errno=EDOM;
    struct madeira_window_geometry out=madeira_window_geometry_begin(style,0x80000,INT_MIN,-19,640,480,parent);
    assert(current_teb.LastErrorValue==77 && errno==EDOM);
    return out;
}
static void finish(struct madeira_window_geometry *out, HWND result) {
    current_teb.LastErrorValue=81; errno=ERANGE;
    assert(madeira_window_geometry_result(out,result)==result);
    assert(current_teb.LastErrorValue==81 && errno==ERANGE);
}
static void filter_cases(void) {
    identity(0,0x348,0x34c);
    const char *names[]={"C:\\private-account-secret\\steam.exe","C:\\cs2.exe.old","C:\\notcs2.exe","C:\\cs2.exe\\other.exe",""};
    for(unsigned i=0;i<sizeof(names)/sizeof(names[0]);i++) { set_image(names[i]); assert(!begin(0,0).sequence); }
    set_image("C:\\private-account-secret\\cs2.exe");
    assert(!begin(WS_CHILD,1).sequence && !begin(0,HWND_MESSAGE).sequence);
    /* Production prefilter must not touch even the PEB pointer for WoW64,
     * children or message-only windows. ASan/UBSan traps a read at address1. */
    current_teb.Peb=(PEB *)(uintptr_t)1;
    current_teb.WowTebOffset=0x2000; assert(!begin(0,0).sequence);
    current_teb.WowTebOffset=-0x2000; assert(!begin(0,0).sequence);
    current_teb.WowTebOffset=0;
    assert(!begin(WS_CHILD,1).sequence && !begin(0,HWND_MESSAGE).sequence);
    current_teb.Peb=&owners[0];
    parameters.ImagePathName.Length--; assert(!begin(0,0).sequence); parameters.ImagePathName.Length++;
    WCHAR saved=image[3]; image[3]=0; assert(!begin(0,0).sequence); image[3]=saved;
    unsigned short length=parameters.ImagePathName.Length;
    parameters.ImagePathName.Length=2048; assert(!begin(0,0).sequence); parameters.ImagePathName.Length=length;
    WCHAR *buffer=parameters.ImagePathName.Buffer;
    parameters.ImagePathName.Buffer=NULL; assert(!begin(0,0).sequence); parameters.ImagePathName.Buffer=buffer;
    owners[0].ProcessParameters=NULL; assert(!begin(0,0).sequence); owners[0].ProcessParameters=&parameters;
    current_teb.Peb=NULL; assert(!begin(0,0).sequence); current_teb.Peb=&owners[0];
    teb_pointer=NULL; errno=EDOM;
    assert(!madeira_window_geometry_begin(0,0,1,2,3,4,0).sequence && errno==EDOM);
    teb_pointer=&current_teb;
    assert(!reports && !monitor_calls && !query_calls);
}
static void phase_cases(void) {
    set_image("C:\\private-account-secret\\CS2.EXE"); identity(0,0x348,0x34c);
    struct madeira_window_geometry out=begin(0x86ca0000,0x10020);
    assert(out.sequence==1 && out.pid==0x348 && out.tid==0x34c);
    assert(out.caller_dpi==96);
    out.window_dpi=192; /* The stager copies Wine's existing computed win_dpi. */
    assert(out.x==INT_MIN && out.y==-19 && out.width==640 && out.height==480);
    CREATESTRUCTW defaults={80,0,800,450};
    struct window_rects initial={{160,0,1760,900},{160,0,1760,900},{0}};
    struct window_rects nc={{160,0,1760,900},{168,30,1752,892},{0}};
    madeira_window_geometry_defaults(&out,&defaults);
    madeira_window_geometry_rects(&out,&initial,0);
    madeira_window_geometry_rects(&out,&nc,1);
    assert(out.phases==7 && out.default_width==800 && out.default_height==450);
    assert(!memcmp(&out.initial_window,&initial.window,sizeof(RECT)));
    assert(!memcmp(&out.nc_client,&nc.client,sizeof(RECT)));
    assert(!out.final_valid);
    finish(&out,0x1234);
    assert(reports==1 && monitor_calls==1 && query_calls==1);
    assert(out.final_valid && out.final_dpi==144);
    assert(!memcmp(&out.final_window,&query_geometry.window,sizeof(RECT)));
    assert(!memcmp(&out.final_client,&query_geometry.client,sizeof(RECT)));
    assert(strstr(output,"request={-2147483648,-19,640,480}"));
    assert(strstr(output,"phases=7 caller-dpi=96 window-dpi=192 default={80,0,800,450}"));
    assert(strstr(output,"initial-window={160,0,1760,900}"));
    assert(strstr(output,"nccalc-client={168,30,1752,892}"));
    assert(strstr(output,"result=1234 final-valid=1 final-dpi=144"));
    assert(strstr(output,"final-client={80,0,720,450}"));
    assert(strstr(output,"meaning=create-window-not-swapchain"));
    struct madeira_window_geometry ignored={0}, before=ignored;
    madeira_window_geometry_defaults(&ignored,&defaults);
    madeira_window_geometry_rects(&ignored,&initial,0);
    madeira_window_geometry_rects(&ignored,&nc,1); finish(&ignored,0x1234);
    assert(!memcmp(&ignored,&before,sizeof(ignored)) && reports==1);
    unsigned m=monitor_calls,q=query_calls;
    out=begin(0,0); finish(&out,0);
    assert(!out.phases && !out.final_valid && monitor_calls==m && query_calls==q);
    out=begin(0,0); monitor_success=0; finish(&out,0x1234);
    assert(!out.final_valid && monitor_calls==m+1 && query_calls==q);
    out=begin(0,0); monitor_success=96; raw_dpi=0; finish(&out,0x1234);
    assert(!out.final_valid && monitor_calls==m+2 && query_calls==q);
    out=begin(0,0); raw_dpi=144; query_success=0; finish(&out,0x1234);
    assert(!out.final_valid && monitor_calls==m+3 && query_calls==q+1);
}
static void budgets(void) {
    unsigned before=reports;
    for(unsigned i=0;i<100;i++) { struct madeira_window_geometry out=begin(0,0); finish(&out,0); }
    assert(reports-before==27); /* Five earlier creations consumed this process's budget. */
    identity(1,0x348,0x350); before=reports; /* same PID, another PEB */
    for(unsigned i=0;i<100;i++) { struct madeira_window_geometry out=begin(0,0); finish(&out,0); }
    assert(reports-before==32);
    identity(1,0x349,0x354); before=reports; /* same PEB, another PID */
    for(unsigned i=0;i<100;i++) { struct madeira_window_geometry out=begin(0,0); finish(&out,0); }
    assert(reports-before==32);
    identity(2,0x360,0x364);
    pthread_mutex_lock(&madeira_window_geometry_lock);
    assert(!begin(0,0).sequence); /* contention omits without waiting */
    pthread_mutex_unlock(&madeira_window_geometry_lock);
    struct madeira_window_geometry out=begin(0,0); assert(out.sequence==1); finish(&out,0);
}
static void *worker(void *arg) {
    identity(3,0x370,(unsigned)(uintptr_t)arg);
    for(unsigned i=0;i<200;i++) { struct madeira_window_geometry out=begin(0,0); finish(&out,0); }
    return NULL;
}
static void concurrency_and_capacity(void) {
    pthread_t threads[8]; unsigned before=reports;
    for(unsigned i=0;i<8;i++) assert(!pthread_create(&threads[i],NULL,worker,(void *)(uintptr_t)(0x380+i)));
    for(unsigned i=0;i<8;i++) assert(!pthread_join(threads[i],NULL));
    assert(reports>before && reports-before<=32);
    identity(3,0x370,0x399);
    for(unsigned i=0;i<32;i++) { struct madeira_window_geometry out=begin(0,0); finish(&out,0); }
    assert(reports-before==32);
    /* Slots already used: owner0, owner1/PID348, owner1/PID349, owner2, owner3. */
    for(unsigned owner=4;owner<31;owner++) {
        identity(owner,0x400+owner,0x500+owner);
        struct madeira_window_geometry out=begin(0,0); assert(out.sequence==1); finish(&out,0);
    }
    identity(31,0x600,0x604); before=reports;
    assert(!begin(0,0).sequence && reports==before); /* full map does not evict or reset */
    identity(0,0x348,0x34c); assert(!begin(0,0).sequence);
}
int main(void) {
    for(unsigned owner=0;owner<40;owner++) owners[owner].ProcessParameters=&parameters;
    filter_cases(); phase_cases(); budgets(); concurrency_and_capacity();
    assert(!strstr(output,"private-account-secret") && !strstr(output,"cs2.exe") && !strstr(output,"CS2.EXE"));
    assert(!strstr(output,"C:\\") && !strstr(output,"ImagePathName"));
    puts("PASS production window geometry: CS2/top-level gate, numeric phase snapshots, independent final query, failed queries/creation, PID+PEB budgets, concurrent trylock, bounded capacity, privacy and Wine error preservation");
    return 0;
}
'''.replace('HEADER', str(header))

with tempfile.TemporaryDirectory(prefix='madeira-window-geometry-') as directory:
    folder = Path(directory)
    code, executable = folder / 'observer.c', folder / 'observer'
    code.write_text(harness)
    compiler = os.environ.get('CC') or shutil.which('clang') or 'cc'
    subprocess.run([compiler, '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-pthread',
                    str(code), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
    staged = folder / 'owned/window.c'
    result = subprocess.run(['python3', str(stager), '--source', str(source_path), '--output', str(staged)],
                            text=True, capture_output=True, check=True)
    manifest = json.loads(result.stdout)
    assert staged.read_text() == transformed and source_path.read_bytes() == original
    assert manifest['source_sha256'] == hashlib.sha256(original).hexdigest()
    assert manifest['output_sha256'] == hashlib.sha256(staged.read_bytes()).hexdigest()
    assert manifest['geometry_changes'] is False and manifest['records_per_process'] == 32
    assert manifest['process_slots'] == 32
    for output in (source_path, folder / 'source-alias.c'):
        if output != source_path:
            output.symlink_to(source_path)
        result = subprocess.run(['python3', str(stager), '--source', str(source_path), '--output', str(output)],
                                text=True, capture_output=True)
        assert result.returncode and source_path.read_bytes() == original
    result = subprocess.run(['python3', str(stager), '--source', str(staged), '--output', str(folder / 'double.c')],
                            text=True, capture_output=True)
    assert result.returncode and not (folder / 'double.c').exists()

assert source_path.read_bytes() == original
print('PASS actual Wine CreateWindowEx staging: original control flow exactly retained, all eight returns observed, changed anchors rejected and pinned source unchanged; no phone/GPU execution')
