/* SPDX-License-Identifier: GPL-3.0-or-later
 * Steam's client owns the identity of games it launches. A game identity
 * left by another Madeira entry must never be supplied to the client. */
#ifndef MADEIRA_STEAM_CLIENT_IDENTITY_H
#define MADEIRA_STEAM_CLIENT_IDENTITY_H
#include <string.h>
#include <strings.h>
static int madeira_is_steam_client_image(const char *image)
{
    const char *name = image;
    if (!name) return 0;
    for (const char *p = image; *p; p++)
        if (*p == '\\' || *p == '/') name = p + 1;
    return !strcasecmp(name, "steam.exe");
}
#endif
