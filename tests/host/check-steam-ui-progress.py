#!/usr/bin/env python3
"""Run production UI counters and WinProc callback boundary without input payloads."""
from pathlib import Path
import os,subprocess,tempfile
root=Path(__file__).resolve().parents[2]
driver=(root/'build/win32u-unix/driver_ios.c').read_text();message=(root/'build/win32u-unix/message_ios.c').read_text();app=(root/'app/Madeira/Winios/Winios.m').read_text()
def function(s,marker):
 a=s.index(marker);b=s.index('{',a)+1;depth=1
 while depth:
  depth+=(s[b]=='{')-(s[b]=='}');b+=1
 return s[a:b]
event=function(driver,'void winios_ui_progress_event(');snapshot=function(driver,'int winios_ui_progress_snapshot(');dispatch=function(message,'static LRESULT dispatch_win_proc_params(')
code=r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include "trace.h"
#include "progress.h"
typedef uint32_t DWORD,UINT,ULONG,NTSTATUS;typedef uintptr_t ULONG_PTR;typedef intptr_t LRESULT;typedef unsigned short WCHAR;
#define WINAPI
#define WINE_IOS
#define MAX_WINPROC_RECURSION 64
#define NtUserCallWinProc 1
struct params {struct {WCHAR* Buffer;unsigned Length;} ImagePathName;} params;
typedef struct params RTL_USER_PROCESS_PARAMETERS;
struct peb {struct params* ProcessParameters;} peb;
typedef struct {struct peb* Peb;DWORD LastErrorValue;struct {void *UniqueProcess,*UniqueThread;} ClientId;} TEB;
static TEB current;static TEB* NtCurrentTeb(void){return &current;}
static struct madeira_ui_progress_slot steam_ui_progress[MADEIRA_UI_PROGRESS_SLOTS];
static int fake_clock(int id,struct timespec *ts){assert(id==CLOCK_MONOTONIC);ts->tv_sec=10;ts->tv_nsec=1;errno=EIO;current.LastErrorValue=999;return 0;}
#define clock_gettime fake_clock
''' +event+'\n'+snapshot+r'''
struct ntuser_thread_info {unsigned recursion_count;} info;
static struct ntuser_thread_info* NtUserGetThreadInfo(void){return &info;}
struct win_proc_params {UINT msg;void* hwnd;};
static NTSTATUS callback_status;static ULONG callback_length=sizeof(LRESULT);static unsigned callback_calls;
static LRESULT callback_result[2]={123,456};
static NTSTATUS KeUserModeCallback(unsigned id,struct win_proc_params* p,size_t n,void** out,ULONG* size){
 assert(id==NtUserCallWinProc&&n==sizeof(*p));callback_calls++;
 struct madeira_ui_progress_snapshot s={0};assert(winios_ui_progress_snapshot(0x64,0x68,&s));assert(s.count[MADEIRA_UI_DISPATCH_BEGIN]==callback_calls);
 if(madeira_ui_input_message(p->msg))assert(s.count[MADEIRA_UI_INPUT_BEGIN]>=1);
 *out=callback_result;*size=callback_length;current.LastErrorValue=444;errno=EINTR;return callback_status;
}
''' +dispatch+r'''
static struct madeira_ui_progress_slot concurrent[MADEIRA_UI_PROGRESS_SLOTS];
static void* add(void* p){unsigned tid=(unsigned)(uintptr_t)p;for(unsigned i=0;i<10000;i++)assert(madeira_ui_progress_add(concurrent,1,tid,MADEIRA_UI_POLL,i,0,0));return 0;}
int main(void){
 WCHAR name[]={'s','t','e','a','m','w','e','b','h','e','l','p','e','r','.','e','x','e'};params.ImagePathName.Buffer=name;params.ImagePathName.Length=sizeof(name);peb.ProcessParameters=&params;current.Peb=&peb;current.ClientId.UniqueProcess=(void*)0x64;current.ClientId.UniqueThread=(void*)0x68;
 current.LastErrorValue=77;errno=ERANGE;
 for(unsigned i=0;i<100;i++)winios_ui_progress_event(MADEIRA_UI_POLL,0,0);
 struct madeira_ui_progress_snapshot s={0};assert(winios_ui_progress_snapshot(0x64,0x68,&s)&&s.count[MADEIRA_UI_POLL]==100);
 assert(current.LastErrorValue==77&&errno==ERANGE);assert(!winios_ui_progress_snapshot(0x64,0x69,&s));
 struct win_proc_params p={0x201,(void*)0x500bc};assert(dispatch_win_proc_params(&p,sizeof(p),NULL,NULL)==123);
 assert(current.LastErrorValue==444&&errno==EINTR);assert(winios_ui_progress_snapshot(0x64,0x68,&s)&&s.count[MADEIRA_UI_INPUT_RETURN]==1&&s.count[MADEIRA_UI_DISPATCH_RETURN]==1&&s.input_hwnd==0x500bc&&s.input_message==0x201);
 callback_status=0xc0000005;assert(dispatch_win_proc_params(&p,sizeof(p),NULL,NULL)==0);
 callback_status=0;callback_length=0;assert(dispatch_win_proc_params(&p,sizeof(p),NULL,NULL)==0);
 assert(winios_ui_progress_snapshot(0x64,0x68,&s)&&s.count[MADEIRA_UI_INPUT_RETURN]==1&&s.count[MADEIRA_UI_INPUT_FAILED]==2);
 info.recursion_count=MAX_WINPROC_RECURSION+1;unsigned before=callback_calls;assert(!dispatch_win_proc_params(&p,sizeof(p),NULL,NULL)&&callback_calls==before);info.recursion_count=0;
 // A different process on the native thread must refresh admission; non-Steam work is excluded.
 WCHAR foreign[]={'x','.','e','x','e'};params.ImagePathName.Buffer=foreign;params.ImagePathName.Length=sizeof(foreign);current.ClientId.UniqueProcess=(void*)0x100;winios_ui_progress_event(MADEIRA_UI_POLL,0,0);assert(!winios_ui_progress_snapshot(0x100,0x68,&s));
 pthread_t threads[8];for(unsigned i=0;i<8;i++)assert(!pthread_create(&threads[i],0,add,(void*)(uintptr_t)(i+1)));for(unsigned i=0;i<8;i++)assert(!pthread_join(threads[i],0));
 for(unsigned i=1;i<=8;i++){assert(madeira_ui_progress_read(concurrent,1,i,&s));assert(s.count[MADEIRA_UI_POLL]==10000);}
 for(unsigned i=9;i<=32;i++)assert(madeira_ui_progress_add(concurrent,1,i,MADEIRA_UI_FLUSH,1,0,0));assert(!madeira_ui_progress_add(concurrent,1,33,MADEIRA_UI_POLL,1,0,0));assert(madeira_ui_progress_read(concurrent,1,1,&s)&&s.count[MADEIRA_UI_POLL]==10000);
 assert(!madeira_ui_progress_add(concurrent,0,1,MADEIRA_UI_POLL,1,0,0));assert(!madeira_ui_progress_add(concurrent,1,1,MADEIRA_UI_PROGRESS_KINDS,1,0,0));
 puts("PASS production Steam UI counters: continued counts beyond eight, process/thread isolation, concurrency/capacity and errno preservation; real WinProc boundary distinguishes successful input callback return from failed/short callback and never treats injection as acknowledgement");
}
'''
with tempfile.TemporaryDirectory() as t:
 p=Path(t)/'test.c';p.write_text(code);exe=Path(t)/'test'
 subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-fsanitize=address,undefined','-fno-sanitize-recover=all','-pthread','-I'+str(root/'build/steam-ui'),str(p),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
frame=function(app,'static void winios_trace_steam_frame(')
assert frame.index('state[2]=@(total)')<frame.index('if (total>8) return;')
heartbeat=function(app,'static void winios_steam_progress_start(')
assert 'dispatch_get_main_queue()' in heartbeat and 'state[5].unsignedIntValue>=12' in heartbeat and 'ticks>96' in heartbeat
assert 'winios_ui_progress_snapshot(' in heartbeat and 'input-winproc=' in heartbeat
assert '.hidden =' not in heartbeat and '.contents =' not in heartbeat and 'NtUser' not in heartbeat
assert 'if(flags&PM_REMOVE)winios_ui_progress_event(MADEIRA_UI_DEQUEUED' in message
build=(root/'build/win32u-unix/build.sh').read_text();assert 'compile_one "$BUILD_DIR/message_ios.c" "message"' in build and 'compile_one "$BUILD_DIR/driver_ios.c" "driver"' in build
print('PASS independent UIKit heartbeat retains lifetime frame outcomes/submission counts and caps reports; compiled message/driver object replacements are the active build inputs')
