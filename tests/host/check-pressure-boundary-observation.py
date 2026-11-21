#!/usr/bin/env python3
"""Normal metadata inputs for Run14's bounded, read-only pressure capture.

Executes the actual request/take and range-classification functions. No guest
payload, Mach thread operation, protection change, or fault experiment runs.
"""
from pathlib import Path
import os
import argparse
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--require-swift', action='store_true')
args = parser.parse_args()
source = (ROOT / 'build/ntdll-unix/virtual_ios.c').read_text()


def function(text, signature):
    start = text.index(signature)
    return text[start:text.index('\n}', start) + 2]


queue = source.split('/* madeira-pressure-boundary begin', 1)[1]
queue = queue[queue.index('struct ios_pressure_boundary_request'):queue.index('/* madeira-pressure-boundary end */')]
classify = function(source, 'static void ios_pressure_boundary_range(unsigned long long base,')
thread = (ROOT / 'build/ntdll-unix/thread_ios.c').read_text()
snapshot = function(thread, 'unsigned long long ios_thread_process_snapshot(')
native = (ROOT / 'build/dxmt-ios/memory_pressure_native.h').read_text()
acquire = function(native, 'static inline void md_resource_growth_acquire(')
assert acquire.index('pthread_mutex_unlock(&md_resource_growth_mutex);\n  if (observe_footprint') < acquire.index(
    'madeira_pressure_boundary_request(owner, lease, observe_footprint')
assert 'available <= floor || bytes > available - floor' in acquire
assert source.count('ios_pressure_boundary_take(&pressure_boundary)') == 1
assert source.index('ios_pressure_boundary_take(&pressure_boundary)') > source.index('last_full = now_ts;')
assert 'if (pressure_sweep || cycle == 2 || (cycle % ios_warmer_sweep_cycles()) == 0)' in source
assert 'queries >= 100000' in queue and '>= 250000000LL' in queue
assert 'ios_pressure_boundary_allow_query(pressure_queries, &pm_t0)' in source
assert '(pressure_sweep && (b == B_GUEST || b == B_FEX))' in source
for forbidden in ('malloc(', 'calloc(', 'mach_vm_', 'thread_suspend(', 'thread_resume(', 'mprotect(',
                  'munmap(', 'delete_view(', 'ios_thread_process_lease('):
    assert forbidden not in queue + classify, forbidden
assert classify.index('pthread_mutex_unlock(&virtual_mutex)') < classify.index('pthread_mutex_trylock(&ios_wow_mutex)')
assert classify.index('pthread_mutex_unlock(&ios_wow_mutex)') < classify.index('ios_thread_process_snapshot(owner,')

code = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(*(a)))
static char last[1800];
static unsigned logs;
static int fixture_dprintf(int fd, const char *format, ...) {
 assert(fd==2); va_list ap; va_start(ap,format); vsnprintf(last,sizeof(last),format,ap); va_end(ap);
 for (const unsigned char *p=(void*)last; *p; ++p) assert(*p<128);
 const char *path=getenv("MADEIRA_TEST_ROWS");
 if(path) {FILE *rows=fopen(path,"a"); assert(rows); fputs(last,rows); assert(!fclose(rows));}
 ++logs; errno=55; return (int)strlen(last);
}
#define dprintf fixture_dprintf
static pthread_mutex_t ios_thread_group_mutex=PTHREAD_MUTEX_INITIALIZER;
struct group {void *owner; unsigned count; int exiting,reclaimed; unsigned long long lease;};
static struct group ios_thread_groups[8];
'''+snapshot+'\n'+queue+r'''
static pthread_mutex_t virtual_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t ios_wow_mutex=PTHREAD_MUTEX_INITIALIZER;
#define SEC_IMAGE 0x1000000
#define SEC_FILE 0x800000
#define IOS_VIEW_QUARANTINED 4
#define IOS_WOW_WINDOW_SIZE UINT64_C(0x100000000)
struct file_view {
 void *base; size_t size; unsigned protect,ios_flags;
 void *ios_fex_owner; unsigned long long ios_fex_lease;
 void *ios_cef_owner; unsigned long long ios_cef_lease;
};
static struct file_view views[4];
static struct file_view *find_view(const void *p, size_t size) {
 uintptr_t at=(uintptr_t)p;
 for(unsigned i=0;i<4;++i) if(at>=(uintptr_t)views[i].base &&
     at-(uintptr_t)views[i].base<views[i].size && size<=views[i].size-(at-(uintptr_t)views[i].base)) return &views[i];
 return NULL;
}
struct ios_wow_window {void *peb; uintptr_t base; unsigned generation;};
static struct ios_wow_window window;
static struct ios_wow_window *ios_wow_live_slot_for_addr(const void *p) {
 uintptr_t at=(uintptr_t)p;
 return window.peb && at>=window.base && at-window.base<IOS_WOW_WINDOW_SIZE ? &window : NULL;
}
'''+classify+r'''
static void request(void *owner,unsigned long long lease) {
 errno=71; madeira_pressure_boundary_request(owner,lease,6238714392,203736552,2798672,201326592); assert(errno==71);
}
static void range(uint64_t base,uint64_t size) {
 errno=72; ios_pressure_boundary_range(base,size,4096,5); assert(errno==72);
}
static void *writer(void *arg) {
 for(unsigned n=0;n<10000;++n) request(arg,1);
 return NULL;
}
int main(void) {
 struct ios_pressure_boundary_request out={0};
 struct timespec now; assert(!clock_gettime(CLOCK_MONOTONIC,&now));
 assert(ios_pressure_boundary_allow_query(0,&now));
 assert(ios_pressure_boundary_allow_query(99999,&now));
 assert(!ios_pressure_boundary_allow_query(100000,&now));
 now.tv_sec--; assert(!ios_pressure_boundary_allow_query(64,&now));
 void *owner=(void*)0x10000;
 ios_thread_groups[0]=(struct group){owner,4,0,0,1};
 pthread_t writers[8];
 for(unsigned i=0;i<8;++i) assert(!pthread_create(&writers[i],NULL,writer,owner));
 for(unsigned i=0;i<8;++i) assert(!pthread_join(writers[i],NULL));
 assert(ios_pressure_boundary_take(&out));
 assert(out.owner==owner && out.lease==1 && out.charged==2798672 && out.available==203736552);
 assert(strstr(last,"capture=queued") && strstr(last,"counters=not-physical-ownership"));
 request(owner,1); assert(!ios_pressure_boundary_take(&out));
 // Same PEB, new normal process generation: a distinct observation, not adoption.
 ios_thread_groups[0].lease=2;request(owner,2);assert(ios_pressure_boundary_take(&out));
 assert(out.lease==2);
 request(owner,3);ios_thread_groups[0].lease=4;
 assert(!ios_pressure_boundary_take(&out) && strstr(last,"canceled-stale"));
 ios_thread_groups[0].exiting=1;request(owner,4);
 assert(!ios_pressure_boundary_take(&out) && strstr(last,"canceled-stale"));
 // Fixed session bound: even another valid generation cannot grow storage.
 ios_thread_groups[0].exiting=0;ios_thread_groups[0].lease=5;request(owner,5);
 assert(!ios_pressure_boundary_take(&out));

 views[0]=(struct file_view){(void*)0x100000,0x200000,0,0,owner,5,NULL,0};
 range(0x100000,0x100000);
 assert(strstr(last,"origin=fex-view-lease") && strstr(last,"lease-match=1"));
 assert(strstr(last,"charged-physical=unknown") && strstr(last,"reclaim-permission=0"));
 assert(ios_thread_groups[0].count==4 && !ios_thread_groups[0].exiting);
 views[0].ios_fex_lease=4;range(0x100000,0x100000);assert(strstr(last,"lease-match=0"));
 views[0].ios_fex_owner=NULL;views[0].ios_cef_owner=owner;views[0].ios_cef_lease=5;
 views[0].protect=SEC_IMAGE;range(0x100000,0x100000);
 assert(strstr(last,"origin=cef-image-lease") && strstr(last,"kind=image"));
 views[0].ios_cef_owner=NULL;views[0].ios_cef_lease=0;
 window=(struct ios_wow_window){owner,0x100000,9};range(0x100000,0x100000);
 assert(strstr(last,"origin=wow-window-snapshot") && strstr(last,"window-generation=9"));
 window.peb=NULL;range(0x100000,0x100000);assert(strstr(last,"origin=unattributed"));
 // A kernel region spanning multiple Wine views does not inherit a guessed owner.
 range(0x100000,0x300000);assert(strstr(last,"vad=0") && strstr(last,"origin=unattributed"));
 // Normal lock contention remains a skipped observation, never a wait.
 assert(!pthread_mutex_lock(&virtual_mutex));range(0x100000,0x100000);
 assert(strstr(last,"vad=-1"));assert(!pthread_mutex_unlock(&virtual_mutex));
 assert(!pthread_mutex_lock(&ios_pressure_boundary_mutex));request(owner,5);
 assert(!pthread_mutex_unlock(&ios_pressure_boundary_mutex));
 assert(ios_thread_groups[0].count==4 && ios_thread_groups[0].lease==5);
 puts("PASS actual bounded pressure request/classification: 80000 concurrent requests coalesce, generations/cap/trylocks hold, metadata stays read-only and ASCII; no payload/Mach/fault experiment");
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-pressure-observe-') as directory:
    src = Path(directory) / 'test.c'
    binary = Path(directory) / 'test'
    src.write_text(code)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-pthread', str(src), '-o', str(binary)], check=True)
    rows = Path(directory) / 'rows.txt'
    subprocess.run([str(binary)], check=True, timeout=15, env={**os.environ, 'MADEIRA_TEST_ROWS': str(rows)})
    swift = shutil.which('swiftc')
    if swift:
        sanitizer = (ROOT / 'app/Madeira/RunDiagnostics.swift').read_text()
        sanitizer = sanitizer[:sanitizer.index('    private static func json(')] + '}\n'
        (Path(directory) / 'Sanitizer.swift').write_text(sanitizer)
        (Path(directory) / 'Check.swift').write_text('''import Foundation
@main struct Check {
 static func main() throws {
  let rows = try String(contentsOfFile: CommandLine.arguments[1], encoding: .utf8).split(separator: "\\n")
  assert(rows.count > 10)
  for row in rows {
   let text = String(row)
   guard let clean = RunDiagnostics.sanitize(text) else { fatalError("bounded pressure row omitted") }
   assert(clean.contains("[pressure-"))
   if text.contains("[pressure-owner-v1]") {
    assert(clean.contains("current-lease=") && clean.contains("origin=") && clean.contains("charged-physical=unknown"))
   }
   assert(RunDiagnostics.sanitize(text + " Cookie: PRIVATE_VALUE") == nil)
  }
  print("PASS actual unchanged Swift sanitizer preserves pressure ownership fields and privacy omission")
 }
}''')
        check = Path(directory) / 'sanitize'
        subprocess.run([swift, '-parse-as-library', str(Path(directory) / 'Sanitizer.swift'),
                        str(Path(directory) / 'Check.swift'), '-o', str(check)], check=True)
        subprocess.run([str(check), str(rows)], check=True)
    elif args.require_swift:
        raise SystemExit('Swift compiler required')
    else:
        print('SKIP actual Swift sanitizer execution: compiler unavailable locally')
