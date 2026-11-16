#!/usr/bin/env python3
"""Exercise actual WaitOnAddress stack-node lifetime under concurrent wakes.

Native timeout/direct-alert delivery is a controlled pthread adapter. The PE
wait, wake selection, intrusive lists, compare and queue spinlocks run from
production source. The old implementation returns its stack while the waker
still uses it; the candidate must block until queue unlock, with unchanged
native status. This is not an iPhone Steam or game-launch result.
"""
from pathlib import Path
import importlib.util
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('wait_address_lifetime', ROOT/'tools/build/stage-wait-address-lifetime.py')
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
original = (ROOT/'wine/dlls/ntdll/sync.c').read_text()
candidate = stage.stage(original)


def function(text, marker):
    begin=text.index(marker);opening=text.index('{',begin);depth=0
    for token in re.finditer(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]',text[opening:],re.S):
        if token.group()=='{':depth+=1
        elif token.group()=='}':
            depth-=1
            if not depth:return text[begin:opening+token.end()]
    raise AssertionError('unclosed production function')


for name in ('void WINAPI RtlWakeAddressSingle(', 'void WINAPI RtlWakeAddressAll('):
    assert function(candidate,name)==function(original,name), 'wake selection must remain byte-exact'
old_wait = function(original, 'NTSTATUS WINAPI RtlWaitOnAddress(')
new_wait = function(candidate, 'NTSTATUS WINAPI RtlWaitOnAddress(')
assert old_wait.replace(stage.OLD,stage.NEW,1).replace('    NTSTATUS ret;\n','    NTSTATUS ret;\n    static const volatile char lifetime_contract[] = "[wait-address-lifetime-v1]";\n    (void)lifetime_contract[0];\n',1)==new_wait
assert original.replace(old_wait,new_wait,1)==candidate
for invalid in (candidate,original.replace(stage.OLD,'/* missing cleanup */',1)):
    try:stage.stage(invalid)
    except ValueError:pass
    else:raise AssertionError('changed or double-staged source accepted')

PRELUDE=r'''
#include <pthread.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include "wine/list.h"
#define WINAPI
#define TRUE 1
#define FALSE 0
#define STATUS_SUCCESS 0
#define STATUS_TIMEOUT 0x102
#define STATUS_ALERTED 0x101
#define STATUS_INVALID_PARAMETER 0xC000000D
static void fixture_note(const char*format,...){(void)format;}
#define TRACE(...) fixture_note(__VA_ARGS__)
#define ERR(...) fixture_note(__VA_ARGS__)
typedef uint32_t ULONG,DWORD;typedef uintptr_t ULONG_PTR,DWORD_PTR;typedef size_t SIZE_T;typedef int32_t NTSTATUS,LONG;typedef void* HANDLE;typedef int BOOL;typedef uint64_t ULONG64;typedef uint16_t USHORT;typedef uint8_t UCHAR;typedef union{int64_t QuadPart;} LARGE_INTEGER;
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
typedef int SYSTEM_INFORMATION_CLASS;
static const char*debugstr_timeout(const LARGE_INTEGER*t){(void)t;return "fixture";}
static NTSTATUS NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS,void*,ULONG,ULONG*);
static atomic_int registered,paused,release_waker,returned,unsafe_access,alerts,native_result;
static int ios_sync_lean=1;
static struct{int64_t woa_waits,woa_wake_single,woa_wake_all;}ios_xp_nt;
static struct{void*Instrumentation[12];struct{void*UniqueThread;}ClientId;}teb;
#define NtCurrentTeb() (&teb)
static LONG InterlockedIncrement(LONG*p){return __atomic_add_fetch(p,1,__ATOMIC_SEQ_CST);}
static int64_t InterlockedIncrement64(int64_t*p){return __atomic_add_fetch(p,1,__ATOMIC_SEQ_CST);}
static LONG InterlockedCompareExchange(LONG*p,LONG v,LONG c){__atomic_compare_exchange_n(p,&c,v,0,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST);return c;}
static LONG InterlockedExchange(LONG*p,LONG v){return __atomic_exchange_n(p,v,__ATOMIC_SEQ_CST);}
static void YieldProcessor(void){sched_yield();}
static DWORD GetCurrentThreadId(void){return 4;}
static void ios_srw_dump_park(const void*a){(void)a;}
static void fixture_pause_before_unlink(void){atomic_store(&paused,1);while(!atomic_load(&release_waker))sched_yield();}
static void fixture_pause_after_unlink(void){fixture_pause_before_unlink();}
static NTSTATUS NtWaitForAlertByThreadId(const void*a,const LARGE_INTEGER*t){(void)a;assert(t);atomic_store(&registered,1);while(!atomic_load(&native_result))sched_yield();return atomic_load(&native_result);}
static NTSTATUS NtAlertThreadByThreadId(HANDLE t){assert(t==(void*)4);atomic_fetch_add(&alerts,1);atomic_store(&native_result,STATUS_ALERTED);return 0;}
static NTSTATUS NtAlertMultipleThreadByThreadId(HANDLE*t,ULONG n,void*a,void*b){assert(!a&&!b);for(ULONG i=0;i<n;i++)NtAlertThreadByThreadId(t[i]);return 0;}
'''
POST=r'''
static LONG value=1;static const LONG comparison=1;
static int variant,timeout_case,post_unlink;
static atomic_int end_waiter;
static uint64_t mono_ms(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return(uint64_t)t.tv_sec*1000+t.tv_nsec/1000000;}
static void until(atomic_int*flag){uint64_t end=mono_ms()+4000;while(!atomic_load(flag)){assert(mono_ms()<end);sched_yield();}}
static void*waiter(void*p){(void)p;LARGE_INTEGER t={.QuadPart=-10000};NTSTATUS ret=RtlWaitOnAddress(&value,&comparison,4,&t);assert(ret==(timeout_case?STATUS_TIMEOUT:STATUS_SUCCESS));atomic_store(&returned,1);while(!atomic_load(&end_waiter))sched_yield();return NULL;}
static void*waker(void*p){(void)p;until(&registered);if(variant)RtlWakeAddressAll(&value);else RtlWakeAddressSingle(&value);return NULL;}
int main(int argc,char**argv){
 assert(argc==5);int fixed=atoi(argv[1]);variant=atoi(argv[2]);timeout_case=atoi(argv[3]);post_unlink=atoi(argv[4]);
 struct futex_queue*q=get_futex_queue(&value);list_init(&q->queue);
 pthread_t a,b;assert(!pthread_create(&a,NULL,waiter,NULL));assert(!pthread_create(&b,NULL,waker,NULL));until(&paused);
 if(timeout_case)atomic_store(&native_result,STATUS_TIMEOUT);else NtAlertThreadByThreadId((HANDLE)4);
 uint64_t end=mono_ms()+100;while(!atomic_load(&returned)&&mono_ms()<end)sched_yield();
 int early=atomic_load(&returned);assert(early==!fixed);
 if(!fixed){puts("BASELINE_RETURNED_WHILE_WAKER_STILL_REFERENCES_STACK_NODE");fflush(stdout);}
 atomic_store(&release_waker,1);pthread_join(b,NULL);until(&returned);atomic_store(&end_waiter,1);pthread_join(a,NULL);
 assert(atomic_load(&alerts)==(timeout_case?1:2));
 if(fixed)assert(list_empty(&q->queue));
 // Do not follow the old implementation's recorded expired stack node.
 list_init(&q->queue);
 printf("%s wake=%s completion=%s pause=%s: returned-before-waker-finished=%d native-status-preserved=1\n",fixed?"candidate":"original",variant?"all":"single",timeout_case?"timeout":"direct-alert",post_unlink?"after-unlink-before-tid":"before-unlink",early);
 return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-wait-lifetime-') as directory:
    temp=Path(directory)
    helpers=original[original.index('struct futex_entry\n'):original.index('/***********************************************************************\n *           RtlWaitOnAddress', original.index('struct futex_entry\n'))]
    native_query='''\nstatic NTSTATUS NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS c,void*p,ULONG n,ULONG*l){assert(c==0xf00d&&n==sizeof(void*));*(void**)p=futex_queues;if(l)*l=sizeof(void*);return 0;}\n'''
    for fixed,source in ((0,original),(1,candidate)):
        wait=function(source,'NTSTATUS WINAPI RtlWaitOnAddress(')
        for variant in (0,1):
            signature='void WINAPI RtlWakeAddressAll(' if variant else 'void WINAPI RtlWakeAddressSingle('
            for post in ((0,1) if variant else (0,)):
                wake=function(source,signature)
                anchor='            entry->addr = NULL;'
                assert wake.count(anchor)==1
                if not post:wake=wake.replace(anchor,anchor+'\n            fixture_pause_before_unlink();',1)
                else:wake=wake.replace('            list_remove( &entry->entry );','            list_remove( &entry->entry );\n            fixture_pause_after_unlink();',1)
                path=temp/'test.c';binary=temp/'test'
                other = 'void WINAPI RtlWakeAddressSingle(' if variant else 'void WINAPI RtlWakeAddressAll('
                path.write_text(PRELUDE+helpers+native_query+wait+'\n'+wake+'\n'+function(source,other)+'\n'+POST)
                compiler=os.environ.get('CC','cc')
                subprocess.run([compiler,'-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-variable',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all','-pthread','-I',str(ROOT/'wine/include'),str(path),'-o',str(binary)],check=True)
                if fixed:assert stage.MARKER.encode() in binary.read_bytes()
                for timeout in (0,1):
                    result=subprocess.run([str(binary),str(fixed),str(variant),str(timeout),str(post)],capture_output=True,text=True,timeout=10,
                        env=dict(os.environ,ASAN_OPTIONS='detect_stack_use_after_return=1:detect_leaks=0',UBSAN_OPTIONS='halt_on_error=1'))
                    if fixed:
                        assert result.returncode==0, result.stdout+result.stderr
                        print(result.stdout.strip())
                    else:
                        assert 'BASELINE_RETURNED_WHILE_WAKER_STILL_REFERENCES_STACK_NODE' in result.stdout
                        assert result.returncode!=0, 'old implementation unexpectedly survived expired-node access'
                        assert 'AddressSanitizer:' in result.stderr and ('stack-use-after' in result.stderr or 'SEGV' in result.stderr), result.stderr
                        print(f'PASS old source fails under ASan after premature stack return: wake={"all" if variant else "single"} completion={"timeout" if timeout else "direct-alert"} post-unlink={post}')
    # Transaction failure/interruption must restore the pinned source and
    # decline unrelated edits. This fixture repository owns no user prefix.
    wine=temp/'wine';(wine/'dlls/ntdll').mkdir(parents=True);path=wine/stage.FILE;path.write_text(original)
    subprocess.run(['git','init','-q',str(wine)],check=True)
    subprocess.run(['git','-C',str(wine),'add','.'],check=True)
    subprocess.run(['git','-C',str(wine),'-c','user.email=fixture@example.invalid','-c','user.name=Fixture','commit','-qm','source'],check=True)
    backup=temp/'backup';stage.apply(wine,backup);assert path.read_text()==candidate
    stage.restore(wine,backup);assert path.read_text()==original
    shutil.rmtree(backup)
    stage.apply(wine,backup);path.write_text(candidate+'\n/* unrelated edit */\n')
    try:stage.restore(wine,backup)
    except ValueError:pass
    else:raise AssertionError('unrelated source edit was overwritten')
    path.write_text(original);stage.restore(wine,backup);assert path.read_text()==original
assert (ROOT/'wine/dlls/ntdll/sync.c').read_text()==original
print('PASS actual WaitOnAddress lifetime: single/all, timeout/direct alert, pre/post unlink; native statuses and wake selection unchanged; pinned-source transactions recover safely')
