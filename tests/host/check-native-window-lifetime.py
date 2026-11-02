#!/usr/bin/env python3
"""Execute production native window registry and server-to-UIKit bridge ordering."""
from pathlib import Path
import os,subprocess,tempfile
root=Path(__file__).resolve().parents[2]
app=(root/'app/Madeira/Winios/Winios.m').read_text();server=(root/'build/wineserver/window_ios.c').read_text()
def function(text,marker):
 a=text.index(marker);b=text.index('{',a)+1;depth=1
 while depth:depth+=(text[b]=='{')-(text[b]=='}');b+=1
 return text[a:b]
# The real native bridges compile as plain C: no UIKit/Wine API can be run
# under their registry mutex. Only the queueing endpoint is substituted.
create=function(app,'uint64_t winios_native_window_create(');retire=function(app,'void winios_native_window_retire(')
reset=function(app,'static void winios_reset_window_metadata(HWND hwnd)')
census_frame=function(app,'static void winios_census_note_frame(')
census_find=function(app,'static struct winios_census_window *winios_census_find(')
window_header=(root/'app/Madeira/Winios/Winios.h').read_text()
window_struct=window_header[window_header.index('#define WINIOS_CENSUS_MAX'):window_header.index('};',window_header.index('struct winios_census_window'))+2]
code=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include "window_lifetime.h"
typedef void* HWND;
static struct madeira_window_registry g_window_lifetimes;
static pthread_mutex_t g_window_lifetime_lock=PTHREAD_MUTEX_INITIALIZER;
static struct madeira_window_ticket queued[32];static unsigned pending;
static uint64_t layer,metal;static int metadata,surface_size,fit;static unsigned resets;
static _Atomic(uintptr_t) g_restore_foreground,g_size_game_hwnd;
static void (*reset_extra)(void);
static void winios_census_forget(HWND hwnd){(void)hwnd;assert(!pthread_mutex_trylock(&g_window_lifetime_lock));pthread_mutex_unlock(&g_window_lifetime_lock);metadata=0;resets++;if(reset_extra)reset_extra();}
static int winios_forget_swapchain_hwnd(HWND hwnd){(void)hwnd;return 1;}
static void winios_remove_window_ticket(HWND hwnd,struct madeira_window_ticket t){
 assert((uintptr_t)hwnd==t.hwnd&&pending<32);assert(!pthread_mutex_trylock(&g_window_lifetime_lock));pthread_mutex_unlock(&g_window_lifetime_lock);queued[pending++]=t;
}
''' +reset+'\n'+create+'\n'+retire+'\n'+window_struct+r'''
#define WINIOS_WS_VISIBLE 0x10000000u
#define WINIOS_WS_MINIMIZE 0x20000000u
#define WINIOS_WS_CAPTION 0x00c00000u
static pthread_mutex_t g_census_lock=PTHREAD_MUTEX_INITIALIZER;
static _Atomic int g_census_on=1;
static struct winios_census_window g_census[WINIOS_CENSUS_MAX];static int g_census_n;
static unsigned restores;static void (*owner_pause)(void);
static int winios_drv_census_owner(HWND hwnd,unsigned *pid,unsigned *style){
 (void)hwnd;assert(!pthread_mutex_trylock(&g_window_lifetime_lock));pthread_mutex_unlock(&g_window_lifetime_lock);
 assert(!pthread_mutex_trylock(&g_census_lock));pthread_mutex_unlock(&g_census_lock);
 if(owner_pause){owner_pause();}*pid=0x444;*style=WINIOS_WS_VISIBLE|WINIOS_WS_MINIMIZE;return 1;
}
static int winios_census_image(unsigned pid,char *image){(void)pid;memset(image,0,WINIOS_CENSUS_IMAGE);return 1;}
static int winios_restore_born_minimized_enabled(void){return 1;}
static int winios_drv_post_restore(HWND hwnd){(void)hwnd;assert(!pthread_mutex_trylock(&g_window_lifetime_lock));pthread_mutex_unlock(&g_window_lifetime_lock);restores++;return 1;}
static int winios_window_ticket_matches(struct madeira_window_ticket t,int present){assert(present);pthread_mutex_lock(&g_window_lifetime_lock);int valid=madeira_window_can_present(&g_window_lifetimes,t);pthread_mutex_unlock(&g_window_lifetime_lock);return valid;}
''' +census_find+'\n'+census_frame+r'''
static void reset_census(void){g_census_n=0;memset(g_census,0,sizeof(g_census));}
static uint64_t paused_serial;static void recycle_during_owner_rpc(void){
 owner_pause=0;winios_native_window_retire(0x600ee,0x444,0x448,paused_serial);
 assert(winios_native_window_create(0x600ee,0x544,0x548));
 // A legitimate new producer has already published its current census row.
 g_census_n=1;g_census[0].hwnd=0x600ee;g_census[0].pid=0x544;
}

static void deliver_remove(struct madeira_window_ticket t){
 int cleanup=madeira_window_can_cleanup(&g_window_lifetimes,t,layer);
 if(cleanup){layer=0;metal=0;surface_size=0;fit=0;}
}
static void deliver_frame(struct madeira_window_ticket t){
 if(madeira_window_can_present(&g_window_lifetimes,t))layer=t.serial;
}
int main(void){
 const uint32_t old_hwnd=0x300e8,new_hwnd=0x400e8,root=0x10020;
 assert((old_hwnd&0xffff)==(new_hwnd&0xffff));
 // Special/native windows and early untracked callbacks remain supported.
 struct madeira_window_ticket special=madeira_window_capture(&g_window_lifetimes,0);
 assert(madeira_window_can_present(&g_window_lifetimes,special));
 struct madeira_window_ticket early=madeira_window_capture(&g_window_lifetimes,old_hwnd);
 assert(madeira_window_can_present(&g_window_lifetimes,early));
 uint64_t r=winios_native_window_create(root,0x20,0x24);assert(r);
 struct madeira_window_ticket sibling=madeira_window_capture(&g_window_lifetimes,root);
 uint64_t a=winios_native_window_create(old_hwnd,0x64,0x68);assert(a);
 struct madeira_window_ticket old=madeira_window_capture(&g_window_lifetimes,old_hwnd);
 assert(!madeira_window_can_present(&g_window_lifetimes,early));
 // A validated cross-process SetWindowPos/parent callback uses the target
 // incarnation, while old/foreign pixel producers retain owner checks.
 assert(madeira_window_can_present(&g_window_lifetimes,madeira_window_capture(&g_window_lifetimes,old_hwnd)));
 assert(!madeira_window_can_present(&g_window_lifetimes,madeira_window_owner(old,0x20,0x24,0)));
 deliver_frame(old);metal=a;metadata=1;surface_size=100;fit=1;
 atomic_store(&g_restore_foreground,old_hwnd);atomic_store(&g_size_game_hwnd,root);
 // Birth cannot displace a live owner even at the same low handle index.
 assert(!winios_native_window_create(new_hwnd,0x264,0x268));
 assert(madeira_window_can_present(&g_window_lifetimes,old));
 winios_native_window_retire(old_hwnd,0x64,0x68,a);assert(pending==1);
 assert(!madeira_window_can_present(&g_window_lifetimes,old));
 assert(!madeira_window_can_present(&g_window_lifetimes,madeira_window_capture(&g_window_lifetimes,old_hwnd)));
 deliver_frame(old);assert(layer==a);deliver_remove(queued[0]);assert(!layer&&!metal&&!metadata&&!surface_size&&!fit);
 assert(!atomic_load(&g_restore_foreground)&&atomic_load(&g_size_game_hwnd)==root);
 assert(madeira_window_can_present(&g_window_lifetimes,sibling));
 winios_native_window_retire(old_hwnd,0x64,0x68,a);assert(pending==1); // idempotent
 // Same-index new generation: queued and newly captured OLD handles reject.
 metadata=1;atomic_store(&g_restore_foreground,new_hwnd);
 uint64_t b=winios_native_window_create(new_hwnd,0x264,0x268);assert(b&&b!=a&&!metadata&&!atomic_load(&g_restore_foreground));
 unsigned before_resets=resets;metadata=2;assert(winios_native_window_create(new_hwnd,0x264,0x268)==b&&metadata==2&&resets==before_resets);
 struct madeira_window_ticket next=madeira_window_capture(&g_window_lifetimes,new_hwnd);
 assert(!madeira_window_can_present(&g_window_lifetimes,old));
 assert(!madeira_window_can_present(&g_window_lifetimes,madeira_window_capture(&g_window_lifetimes,old_hwnd)));
 layer=a;metal=a;metadata=2;deliver_remove(old);assert(!layer&&!metal&&metadata==2); // remove old UI, retain replacement metadata
 deliver_frame(next);metal=b;deliver_remove(old);assert(layer==b&&metal==b&&metadata==2);
 winios_native_window_retire(old_hwnd,0x64,0x68,a);assert(pending==1);
 // Death before any queued CALayer was created still clears exact metadata.
 winios_native_window_retire(new_hwnd,0x264,0x268,b);assert(pending==2);assert(!metadata);layer=0;metal=0;deliver_remove(queued[1]);assert(!metadata);
 deliver_frame(next);assert(!layer);
 // Full handle and PID can eventually be reused: its host birth ticket changes.
 uint64_t c=winios_native_window_create(new_hwnd,0x364,0x368);assert(c!=b);
 struct madeira_window_ticket replacement=madeira_window_capture(&g_window_lifetimes,new_hwnd);
 assert(!madeira_window_can_present(&g_window_lifetimes,next));
 struct madeira_window_ticket wrong=madeira_window_owner(replacement,0x264,0x268,0);
 assert(!madeira_window_can_present(&g_window_lifetimes,wrong)&&!madeira_window_can_cleanup(&g_window_lifetimes,wrong,0));
 wrong=madeira_window_owner(replacement,0x364,0x268,1);assert(!madeira_window_can_present(&g_window_lifetimes,wrong));
 assert(madeira_window_can_present(&g_window_lifetimes,madeira_window_owner(replacement,0x364,0x999,0))); // legitimate cross-thread paint
 // An old queued removal cannot discard a replacement Metal/GDI layer.
 deliver_frame(replacement);metal=c;metadata=3;deliver_remove(next);assert(layer==c&&metal==c&&metadata==3);
 // Old retirement arriving after row reuse likewise cannot retire the new owner.
 winios_native_window_retire(new_hwnd,0x264,0x268,b);assert(pending==2&&madeira_window_can_present(&g_window_lifetimes,replacement));
 assert(madeira_window_can_present(&g_window_lifetimes,sibling));
 // A frame paused in a Wine owner/image query cannot publish after death
 // and full-HWND rebirth, or restore/minimize the replacement incarnation.
 reset_extra=reset_census;paused_serial=winios_native_window_create(0x600ee,0x444,0x448);
 struct madeira_window_ticket paused=madeira_window_capture(&g_window_lifetimes,0x600ee);
 owner_pause=recycle_during_owner_rpc;atomic_store(&g_restore_foreground,0);
 winios_census_note_frame((HWND)(uintptr_t)0x600ee,-32000,-32000,160,24,1,paused);
 assert(g_census_n==1&&g_census[0].pid==0x544&&!g_census[0].shown_once&&!g_census[0].restore_sent);
 assert(!restores&&!atomic_load(&g_restore_foreground));
 // Whole-server restart invalidates live tickets without resetting serials.
 uint64_t last=g_window_lifetimes.next;madeira_window_end_session(&g_window_lifetimes);
 assert(!madeira_window_can_present(&g_window_lifetimes,replacement));
 assert(winios_native_window_create(new_hwnd,0x364,0x368)>last);
 assert(!madeira_window_can_present(&g_window_lifetimes,replacement));
 puts("PASS actual native window bridges/registry: process death clears ghost GDI/Metal layers and pre-layer metadata, live sibling retained, duplicate death idempotent, queued/late captures and removals reject retired/reused HWNDs and owners; no lock held across dispatch");
}
'''
with tempfile.TemporaryDirectory() as t:
 p=Path(t)/'test.c';p.write_text(code);exe=Path(t)/'test'
 subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=all','-pthread','-I'+str(root/'build/steam-ui'),str(p),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
# Verify authoritative server ownership, publication after successful creation,
# and retirement before handle detachment/free (including forced thread death).
creation=function(server,'static struct window *create_window(')
destruction=function(server,'void free_window_handle(')
assert creation.index('winios_native_window_create(')>creation.index('current->desktop_users++')
assert 'win->ios_native_pid=current->process->id;win->ios_native_tid=current->id;' in creation
assert destruction.index('winios_native_window_retire(')<destruction.index('detach_window_thread( win )')<destruction.index('free_user_handle( win->handle )')
assert 'free_window_handle( win )' in function(server,'void destroy_thread_windows(')
# Every asynchronous path capable of modifying/creating an HWND layer captures
# before enqueue and checks its incarnation in the UIKit block.
for marker in ['void winios_note_game_metal_hwnd(', 'CAMetalLayer *winios_metal_layer_for_hwnd(', 'CAMetalLayer *winios_vulkan_layer_for_hwnd(', 'void winios_window_visibility(', 'void winios_window_geometry(', 'void winios_window_frame(', 'int winios_surface_present(']:
 f=function(app,marker);assert f.index('ticket=winios_capture_window')<f.index('^{')<f.index('winios_prepare_window_ticket(hwnd,ticket)'),marker
metal=function(app,'CAMetalLayer *winios_metal_layer_for_hwnd(')
assert metal.index('winios_layer_for(hwnd, true, ticket)')<metal.index('CAMetalLayer *ml = g_metal_layers[key]')
remove=function(app,'static void winios_remove_window_ticket(HWND hwnd,struct madeira_window_ticket ticket)')
assert 'winios_census_forget' not in remove and 'g_restore_foreground' not in remove
assert create.index('winios_reset_window_metadata')>create.index('pthread_mutex_unlock')
assert retire.index('winios_reset_window_metadata')>retire.index('pthread_mutex_unlock')
assert retire.index('winios_reset_window_metadata')<retire.index('winios_remove_window_ticket')
assert 'winios_clear_surface_identity(key)' in remove and 'winios_clear_surface_identity(key)' in function(app,'static int winios_prepare_window_ticket(HWND hwnd,struct madeira_window_ticket ticket)')
clear=function(app,'static void winios_clear_surface_identity(');assert 'g_surf_sizes removeObjectForKey:key' in clear and 'g_fit_client_px=CGRectZero' in clear and 'g_fit_view_pt=CGRectZero' in clear
assert 'dispatch_sync' not in create+retire+remove and 'NtUser' not in create+retire+remove
print('PASS active server creation/death and all queued native GDI/Metal/geometry paths use exact-incarnation gates, with metadata cleanup independent of first CALayer creation')

for marker in ['void winios_window_visibility(', 'void winios_window_geometry(', 'void winios_window_frame(']:
 assert 'ticket=winios_capture_window_target(hwnd)' in function(app,marker)
assert 'ticket=winios_capture_window(hwnd)' in function(app,'int winios_surface_present(')
