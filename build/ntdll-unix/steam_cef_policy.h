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

enum madeira_cef_role { MADEIRA_CEF_BROWSER, MADEIRA_CEF_CRASHPAD, MADEIRA_CEF_OTHER_CHILD };

static inline void madeira_cef_token_char( char *token, size_t cap, size_t *length, unsigned short c )
{
    if (*length + 1 < cap) token[*length] = c < 128 ? (char)c : (char)0xff;
    (*length)++;
}

/* Inspect real Windows arguments, including quoting/backslashes and last-switch
 * precedence. A --type= substring inside another switch's value is not a type.
 * Only fixed process-role names are returned; argument data is never logged. */
static inline enum madeira_cef_role madeira_cef_process_role( const unsigned short *line, size_t length )
{
    enum madeira_cef_role role = MADEIRA_CEF_BROWSER;
    size_t p = 0;
    while (line && p < length)
    {
        char token[64];
        size_t n = 0;
        int quoted = 0;
        while (p < length && (line[p] == ' ' || line[p] == '\t')) p++;
        while (p < length && (quoted || (line[p] != ' ' && line[p] != '\t')))
        {
            unsigned short c = line[p++];
            if (c == '\\')
            {
                size_t slashes = 1;
                while (p < length && line[p] == '\\') { slashes++; p++; }
                if (p < length && line[p] == '"')
                {
                    for (size_t i = 0; i < slashes / 2; i++) madeira_cef_token_char( token, sizeof(token), &n, '\\' );
                    p++;
                    if (slashes & 1) madeira_cef_token_char( token, sizeof(token), &n, '"' );
                    else quoted = !quoted;
                }
                else for (size_t i = 0; i < slashes; i++) madeira_cef_token_char( token, sizeof(token), &n, '\\' );
            }
            else if (c == '"')
            {
                if (quoted && p < length && line[p] == '"')
                {
                    p++;
                    madeira_cef_token_char( token, sizeof(token), &n, '"' );
                }
                else quoted = !quoted;
            }
            else madeira_cef_token_char( token, sizeof(token), &n, c );
        }
        token[n < sizeof(token) ? n : sizeof(token)-1] = 0;
        if (n == 2 && !strcmp( token, "--" )) break;
        const char *key = token;
        if (key[0] == '-' && key[1] == '-') key += 2;
        else if (key[0] == '-' || key[0] == '/') key++;
        else continue;
        if (!strncmp( key, "type=", 5 ))
            role = n >= sizeof(token) ? MADEIRA_CEF_OTHER_CHILD :
                   !key[5] ? MADEIRA_CEF_BROWSER :
                   !strcmp( key + 5, "crashpad-handler" ) ? MADEIRA_CEF_CRASHPAD : MADEIRA_CEF_OTHER_CHILD;
        else if (!strcmp( key, "type" )) role = MADEIRA_CEF_BROWSER;
    }
    return role;
}
#endif
