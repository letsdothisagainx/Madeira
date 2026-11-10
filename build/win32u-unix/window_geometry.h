/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Passive CreateWindowEx geometry, compiled only into an owned Wine copy.
 * One fixed numeric row per CS2 top-level creation, at most32 per guest
 * process. Request/default tuples are{x,y,width,height}; rectangles are
 * {left,top,right,bottom}. Phases bits1/2/4 mean defaults, calculated initial
 * window-DPI geometry, and calculated NCCALCSIZE geometry. The final query is
 * in monitor raw-DPI coordinates; a DPI value0 means inherited/unknown.
 * Calculated rectangles are distinct from a successful final query.
 * This changes no window, message, DPI, display mode or graphics operation. */
#ifndef MADEIRA_WINDOW_GEOMETRY_H
#define MADEIRA_WINDOW_GEOMETRY_H
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include "../ntdll-unix/cs2_observation.h"

#define MADEIRA_WINDOW_GEOMETRY_PROCESSES 32
#define MADEIRA_WINDOW_GEOMETRY_LIMIT 32
static pthread_mutex_t madeira_window_geometry_lock = PTHREAD_MUTEX_INITIALIZER;
static struct { uintptr_t owner; unsigned pid, count; }
    madeira_window_geometry_processes[MADEIRA_WINDOW_GEOMETRY_PROCESSES];

struct madeira_window_geometry {
    unsigned sequence, pid, tid, style, exstyle, phases, caller_dpi, window_dpi, final_dpi, final_valid;
    int x, y, width, height, default_x, default_y, default_width, default_height;
    uintptr_t parent;
    RECT initial_window, initial_client, nc_window, nc_client, final_window, final_client;
};

static struct madeira_window_geometry madeira_window_geometry_begin(
    unsigned style, unsigned exstyle, int x, int y, int width, int height, HWND parent)
{
    struct madeira_window_geometry out = {0};
    int saved_errno = errno;
    TEB *teb = NtCurrentTeb();
    unsigned saved_error = teb ? teb->LastErrorValue : 0;
    RTL_USER_PROCESS_PARAMETERS *params;
    /* CS2 is64-bit. The current thread's offset, unlike session wow_peb,
     * identifies WoW64 exactly. Exclude unrelated windows before metadata. */
    if (!teb || teb->WowTebOffset || (style & WS_CHILD) || parent == HWND_MESSAGE)
    {
        if (teb) teb->LastErrorValue = saved_error;
        errno = saved_errno;
        return out;
    }
    params = teb->Peb ? teb->Peb->ProcessParameters : NULL;
    if (params &&
        !(params->ImagePathName.Length % sizeof(WCHAR)) &&
        ios_cs2_role((const uint16_t *)params->ImagePathName.Buffer,
                     params->ImagePathName.Length / sizeof(WCHAR)) &&
        !pthread_mutex_trylock(&madeira_window_geometry_lock))
    {
        unsigned pid = GetCurrentProcessId(), i;
        uintptr_t owner = (uintptr_t)teb->Peb;
        for (i = 0; i < MADEIRA_WINDOW_GEOMETRY_PROCESSES; i++)
        {
            if (!madeira_window_geometry_processes[i].owner)
            {
                madeira_window_geometry_processes[i].owner = owner;
                madeira_window_geometry_processes[i].pid = pid;
            }
            if (madeira_window_geometry_processes[i].owner == owner &&
                madeira_window_geometry_processes[i].pid == pid)
            {
                if (madeira_window_geometry_processes[i].count < MADEIRA_WINDOW_GEOMETRY_LIMIT)
                    out.sequence = ++madeira_window_geometry_processes[i].count;
                break;
            }
        }
        pthread_mutex_unlock(&madeira_window_geometry_lock);
        if (out.sequence)
        {
            out.pid = pid; out.tid = GetCurrentThreadId();
            out.caller_dpi = get_thread_dpi();
            out.style = style; out.exstyle = exstyle; out.parent = (uintptr_t)parent;
            out.x = x; out.y = y; out.width = width; out.height = height;
        }
    }
    if (teb) teb->LastErrorValue = saved_error;
    errno = saved_errno;
    return out;
}

static void madeira_window_geometry_defaults(struct madeira_window_geometry *out, const CREATESTRUCTW *cs)
{
    if (!out->sequence) return;
    out->default_x = cs->x; out->default_y = cs->y;
    out->default_width = cs->cx; out->default_height = cs->cy;
    out->phases |= 1;
}

static void madeira_window_geometry_rects(struct madeira_window_geometry *out,
                                         const struct window_rects *rects, unsigned after_nc)
{
    if (!out->sequence) return;
    if (after_nc)
    {
        out->nc_window = rects->window; out->nc_client = rects->client;
        out->phases |= 4;
    }
    else
    {
        out->initial_window = rects->window; out->initial_client = rects->client;
        out->phases |= 2;
    }
}

static HWND madeira_window_geometry_result(struct madeira_window_geometry *out, HWND result)
{
    if (out->sequence)
    {
        TEB *teb = NtCurrentTeb();
        unsigned saved_error = teb->LastErrorValue;
        int saved_errno = errno;
        struct window_rects final;
        UINT raw_dpi = 0;
        if (result && get_win_monitor_dpi(result, &raw_dpi) && raw_dpi &&
            get_window_rects(result, COORDS_SCREEN, &final, raw_dpi))
        {
            out->final_valid = 1; out->final_dpi = raw_dpi;
            out->final_window = final.window; out->final_client = final.client;
        }
        dprintf(2, "[cs2-window-geometry-v1] pid=%04x tid=%04x sequence=%u limit=32 "
                   "request={%d,%d,%d,%d} style=%08x exstyle=%08x parent=%llx "
                   "phases=%u caller-dpi=%u window-dpi=%u default={%d,%d,%d,%d} "
                   "initial-window={%d,%d,%d,%d} initial-client={%d,%d,%d,%d} "
                   "nccalc-window={%d,%d,%d,%d} nccalc-client={%d,%d,%d,%d} "
                   "result=%llx final-valid=%u final-dpi=%u final-window={%d,%d,%d,%d} "
                   "final-client={%d,%d,%d,%d} meaning=create-window-not-swapchain\n",
                out->pid, out->tid, out->sequence, out->x, out->y, out->width, out->height,
                out->style, out->exstyle, (unsigned long long)out->parent, out->phases,
                out->caller_dpi, out->window_dpi,
                out->default_x, out->default_y, out->default_width, out->default_height,
                (int)out->initial_window.left, (int)out->initial_window.top,
                (int)out->initial_window.right, (int)out->initial_window.bottom,
                (int)out->initial_client.left, (int)out->initial_client.top,
                (int)out->initial_client.right, (int)out->initial_client.bottom,
                (int)out->nc_window.left, (int)out->nc_window.top,
                (int)out->nc_window.right, (int)out->nc_window.bottom,
                (int)out->nc_client.left, (int)out->nc_client.top,
                (int)out->nc_client.right, (int)out->nc_client.bottom,
                (unsigned long long)(uintptr_t)result, out->final_valid, out->final_dpi,
                (int)out->final_window.left, (int)out->final_window.top,
                (int)out->final_window.right, (int)out->final_window.bottom,
                (int)out->final_client.left, (int)out->final_client.top,
                (int)out->final_client.right, (int)out->final_client.bottom);
        teb->LastErrorValue = saved_error;
        errno = saved_errno;
    }
    return result;
}
#endif
