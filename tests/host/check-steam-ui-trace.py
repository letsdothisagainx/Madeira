#!/usr/bin/env python3
"""Exercise bounded Steam metadata tracing and transparent ShowWindow forwarding."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
driver = (root / 'build/win32u-unix/driver_ios.c').read_text()
app = (root / 'app/Madeira/Winios/Winios.m').read_text()


def function(source, name):
    start = source.index(name)
    begin = source.index('{', start)
    end, depth = begin + 1, 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


show = function(driver, 'static UINT winios_drv_show_window(')
callback = function(driver, 'static void winios_drv_window_pos_changed(')
observer = function(app, 'void winios_ui_surface_trace(')
assert callback.index('winios_ui_surface_trace( hwnd,') > callback.index('winios_pWindowPosChanged( hwnd,')
assert 'dispatch_async(dispatch_get_main_queue()' in observer
assert 'dispatch_sync' not in observer and 'winios_layer_for(' not in observer and 'NtUser' not in observer
assert '.hidden =' not in observer and '.contents =' not in observer

code = r'''
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "trace.h"
typedef void *HWND; typedef unsigned UINT; typedef int INT, BOOL;
typedef struct { int left, top, right, bottom; } RECT;
enum { STEAM_UI_SHOW };
static struct madeira_ui_trace_slot slots[MADEIRA_UI_TRACE_WINDOWS];
static atomic_uint accepted;
static UINT hook_result, received_flags;
static INT received_cmd;
static RECT *received_rect;
static HWND received_hwnd;
static unsigned calls;
static BOOL winios_trace_steam_window(const char *event, unsigned kind, HWND hwnd, UINT swp,
                                      HWND after, void *surface) {
    (void)swp; assert(!strcmp(event, "show-request") && !after && !surface);
    return madeira_ui_trace_take(slots, 42, (uintptr_t)hwnd, kind);
}
static UINT winios_pShowWindow(HWND hwnd, INT cmd, RECT *rect, UINT swp) {
    calls++; received_hwnd = hwnd; received_cmd = cmd; received_rect = rect; received_flags = swp;
    return hook_result;
}
static void *race(void *unused) {
    (void)unused;
    for (unsigned i = 0; i < 10000; i++)
        if (madeira_ui_trace_take(slots, 43, 0x200ac, 4)) atomic_fetch_add(&accepted, 1);
    return NULL;
}
static int image(const char *name) {
    unsigned short path[256]; size_t n = strlen(name); assert(n < 256);
    for (size_t i = 0; i < n; i++) path[i] = (unsigned char)name[i];
    return madeira_steam_ui_image(path, n);
}
''' + show + r'''
int main(void) {
    assert(image("C:\\Program Files (x86)\\Steam\\steam.exe") == 1);
    assert(image("C:/Steam/BIN/SteamWebHelper.EXE") == 2);
    assert(!image("C:\\Steam\\steam.exe.bak") && !image("notsteamwebhelper.exe"));
    assert(!image("C:\\Steam.exe\\cs2.exe") && !image("dockhost.exe"));
    assert(!madeira_steam_ui_image(NULL, 4));
    RECT rect = {351, 104, 1407, 648};
    UINT flags[] = {0, 0x40, 0x80, 0x13, 0x43, 0x83, 0xffff};
    for (unsigned i = 0; i < sizeof(flags)/sizeof(flags[0]); i++) {
        hook_result = i & 1 ? ~0u : 0x40u;
        assert(winios_drv_show_window((void *)0x200ac, i, &rect, flags[i]) == hook_result);
        assert(received_hwnd == (void *)0x200ac && received_cmd == (INT)i);
        assert(received_rect == &rect && received_flags == flags[i]);
    }
    assert(calls == 7 && rect.left == 351 && rect.bottom == 648);
    pthread_t threads[8];
    for (unsigned i = 0; i < 8; i++) assert(!pthread_create(&threads[i], NULL, race, NULL));
    for (unsigned i = 0; i < 8; i++) assert(!pthread_join(threads[i], NULL));
    assert(accepted == 8);
    // A late visibility transition and a separate process have independent budgets.
    for (unsigned i = 0; i < 8; i++) assert(madeira_ui_trace_take(slots, 43, 0x200ac, 3));
    assert(!madeira_ui_trace_take(slots, 43, 0x200ac, 3));
    assert(madeira_ui_trace_take(slots, 44, 0x200ac, 3));
    assert(!madeira_ui_trace_take(slots, 44, 0x200ac, MADEIRA_UI_TRACE_KINDS));
    assert(!madeira_ui_trace_take(slots, 44, 0, 0));
    puts("PASS: exact Steam processes, concurrent bounded budgets and unchanged ShowWindow flags/placement/result");
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-steam-ui-') as temp:
    source, binary = Path(temp) / 'main.c', Path(temp) / 'check'
    source.write_text(code)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-D_POSIX_C_SOURCE=200809L',
                    '-Wall', '-Wextra', '-Werror', '-pthread', '-fsanitize=address,undefined',
                    '-I', str(root / 'build/steam-ui'), str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
