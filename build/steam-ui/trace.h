/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Bounded metadata diagnostics; no command lines or window contents. */
#ifndef MADEIRA_STEAM_UI_TRACE_H
#define MADEIRA_STEAM_UI_TRACE_H
#include <stdint.h>
#include <stddef.h>

static inline int madeira_steam_ui_image( const unsigned short *path, size_t length )
{
    static const char *const names[] = { "steam.exe", "steamwebhelper.exe" };
    size_t start = 0, i, n;
    if (!path) return 0;
    for (i = 0; i < length; i++) if (path[i] == '\\' || path[i] == '/') start = i + 1;
    for (n = 0; n < sizeof(names) / sizeof(names[0]); n++)
    {
        for (i = 0; start + i < length && names[n][i]; i++)
        {
            unsigned short c = path[start + i];
            if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
            if (c != (unsigned char)names[n][i]) break;
        }
        if (start + i == length && !names[n][i]) return (int)n + 1;
    }
    return 0;
}

/* Separate budgets retain ShowWindow and show/hide transitions when early
 * SetWindowPos traffic is noisy. Wine HWNDs are 32-bit user handles. */
#define MADEIRA_UI_TRACE_KINDS 5
#define MADEIRA_UI_TRACE_WINDOWS 64
struct madeira_ui_trace_slot { uint64_t key; unsigned int count[MADEIRA_UI_TRACE_KINDS]; };
static inline int madeira_ui_trace_take( struct madeira_ui_trace_slot *slots,
                                         uint32_t pid, uintptr_t hwnd, unsigned int kind )
{
    uint64_t key = ((uint64_t)pid << 32) | hwnd;
    unsigned int i;
    if (!hwnd || hwnd > UINT32_MAX || kind >= MADEIRA_UI_TRACE_KINDS) return 0;
    for (i = 0; i < MADEIRA_UI_TRACE_WINDOWS; i++)
    {
        uint64_t old = __atomic_load_n( &slots[i].key, __ATOMIC_RELAXED );
        if (!old) __atomic_compare_exchange_n( &slots[i].key, &old, key, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED );
        if (__atomic_load_n( &slots[i].key, __ATOMIC_RELAXED ) == key)
        {
            unsigned int count = __atomic_load_n( &slots[i].count[kind], __ATOMIC_RELAXED );
            while (count < 8)
                if (__atomic_compare_exchange_n( &slots[i].count[kind], &count, count + 1, 0,
                                                 __ATOMIC_RELAXED, __ATOMIC_RELAXED )) return 1;
            return 0;
        }
    }
    return 0;
}
#endif
