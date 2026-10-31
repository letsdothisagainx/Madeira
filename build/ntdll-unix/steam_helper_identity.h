/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef MADEIRA_STEAM_HELPER_IDENTITY_H
#define MADEIRA_STEAM_HELPER_IDENTITY_H
#include <stddef.h>
static const char *ios_steam_helper_name( const unsigned short *path, size_t length )
{
    static const char *const names[] = { "gldriverquery.exe", "gldriverquery64.exe",
        "vulkandriverquery.exe", "vulkandriverquery64.exe", "steamwebhelper.exe" };
    size_t start = 0, i, n;
    if (!path) return NULL;
    for (i = 0; i < length; i++) if (path[i] == '/' || path[i] == '\\') start = i + 1;
    for (n = 0; n < sizeof(names) / sizeof(names[0]); n++)
    {
        for (i = 0; start + i < length && names[n][i]; i++)
        {
            unsigned short c = path[start + i];
            if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
            if (c != (unsigned char)names[n][i]) break;
        }
        if (start + i == length && !names[n][i]) return names[n];
    }
    return NULL;
}
#endif
