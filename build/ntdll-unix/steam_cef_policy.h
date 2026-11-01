/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef MADEIRA_STEAM_CEF_POLICY_H
#define MADEIRA_STEAM_CEF_POLICY_H
#include <stddef.h>
#include <string.h>

static inline int madeira_cef_image( const unsigned short *image, size_t length )
{
    static const char name[] = "steamwebhelper.exe";
    size_t first = 0, i;
    if (!image) return 0;
    for (i = 0; i < length; i++) if (image[i] == '/' || image[i] == '\\') first = i + 1;
    if (length - first != sizeof(name) - 1) return 0;
    for (i = 0; i < sizeof(name) - 1; i++)
    {
        unsigned short c = image[first + i];
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (c != (unsigned char)name[i]) return 0;
    }
    return 1;
}

static inline int madeira_cef_compat_options( const char *policy )
{
    /* An explicit comparison with Valve's unchanged command line. Unknown
     * settings retain the established compatibility policy. */
    return !policy || strcmp( policy, "valve" );
}
#endif
