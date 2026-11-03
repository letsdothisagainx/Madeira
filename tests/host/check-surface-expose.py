#!/usr/bin/env python3
"""Execute the production expose hook against a lost-backing paint queue."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / 'build/win32u-unix/driver_ios.c').read_text()
start = source.index('static void winios_expose_surface(')
end = source.index('\n}\n', start) + 3
hook = source[start:end]
callback = source[source.index('static void winios_drv_window_pos_changed('):]
assert 'winios_expose_surface( hwnd, swp_flags, &new_rects->visible, surface );' in callback
assert 'if (old_surface != new_surface) swp_flags |= SWP_FRAMECHANGED;' in (root / 'wine/dlls/win32u/window.c').read_text()
assert 'RDW_UPDATENOW' not in hook and 'RDW_ERASENOW' not in hook

harness = r'''
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef void *HWND; typedef unsigned UINT, DWORD; typedef int BOOL;
typedef struct {int left,top,right,bottom;} RECT;
struct window_surface {const void *funcs;};
#define SWP_SHOWWINDOW 0x40
#define SWP_HIDEWINDOW 0x80
#define SWP_FRAMECHANGED 0x20
#define RDW_INVALIDATE 1
#define RDW_ERASE 4
#define RDW_FRAME 0x400
#define RDW_ALLCHILDREN 0x80
static int desktop=1, game=0, visible=1, paint_success=1, reports, calls, queued;
static const char winios_surface_funcs, dummy_funcs;
static struct {DWORD LastErrorValue;} teb;
#define NtCurrentTeb() (&teb)
static int winios_desktop_mode(void){return desktop;}
static int winios_game_windows(void){return game;}
static int IsRectEmpty(const RECT *r){return r->left>=r->right||r->top>=r->bottom;}
static int is_window_visible(HWND h){assert(h==(void *)0x2016a);return visible;}
static int log_event(int fd,const char *fmt,...){(void)fd;(void)fmt;reports++;errno=EIO;teb.LastErrorValue=999;return 0;}
#define dprintf log_event
static BOOL NtUserRedrawWindow(HWND h,void *r,int region,unsigned flags){
 assert(h==(void *)0x2016a&&!r&&!region);
 assert(flags==(RDW_INVALIDATE|RDW_ERASE|RDW_FRAME|RDW_ALLCHILDREN));
 calls++;queued=paint_success;return paint_success;
}
/* The renderer supplies these pixels only when its child gets a paint.
 * This is a queue fixture, not a Chromium/GPU implementation. */
static uint32_t pixels[562*240];
static void replace_backing(void){memset(pixels,0,sizeof(pixels));queued=0;}
static void drain_paints(void){if(queued){pixels[8*562+8]=0xffeeeeee;pixels[200*562+450]=0xff238040;queued=0;}}
'''+hook+r'''
int main(void){
 struct window_surface surface={&winios_surface_funcs},dummy={&dummy_funcs};
 RECT rect={433,204,995,444},empty={0};HWND h=(void *)0x2016a;
 /* Negative control: the old game-only path never queued a desktop expose. */
 replace_backing();if(game)winios_expose_surface(h,SWP_FRAMECHANGED,&rect,&surface);
 drain_paints();assert(!pixels[8*562+8]);
 teb.LastErrorValue=77;errno=EDOM;
 for(int i=0;i<128;i++){
  replace_backing();winios_expose_surface(h,SWP_FRAMECHANGED,&rect,&surface);
  assert(queued&&pixels[8*562+8]==0); /* no inline guest paint */
  drain_paints();assert(pixels[8*562+8]&&pixels[200*562+450]);
  assert(teb.LastErrorValue==77&&errno==EDOM);
 }
 int before=calls;
 winios_expose_surface(h,0,&rect,&surface); /* movement/ordinary frame is not damage */
 winios_expose_surface(h,SWP_SHOWWINDOW,&rect,NULL);
 winios_expose_surface(h,SWP_SHOWWINDOW,&rect,&dummy);
 winios_expose_surface(h,SWP_SHOWWINDOW,&empty,&surface);
 winios_expose_surface(h,SWP_SHOWWINDOW|SWP_HIDEWINDOW,&rect,&surface);
 visible=0;winios_expose_surface(h,SWP_SHOWWINDOW,&rect,&surface);visible=1;
 assert(calls==before&&visible==1);
 winios_expose_surface(h,SWP_SHOWWINDOW,&rect,&surface);assert(calls==++before);
 desktop=0;game=0;winios_expose_surface(h,SWP_FRAMECHANGED,&rect,&surface);assert(calls==before);
 game=1;winios_expose_surface(h,SWP_FRAMECHANGED,&rect,&surface);assert(calls==++before);
 paint_success=0;queued=0;winios_expose_surface(h,SWP_SHOWWINDOW,&rect,&surface);assert(calls==++before&&!queued);
 assert(reports==32);
 puts("PASS production expose hook: desktop lost-backing negative control,128 replacements,queued child paints,hidden/dummy surfaces declined,game path retained,failed redraw and bounded logs");
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-expose-') as temp:
    p = Path(temp); (p / 'test.c').write_text(harness)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', str(p / 'test.c'), '-o', str(p / 'test')], check=True)
    subprocess.run([str(p / 'test')], check=True)
