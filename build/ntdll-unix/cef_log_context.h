/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Included after Wine's text-log mirror in the staged file.c only. */
#ifndef MADEIRA_CEF_LOG_CONTEXT_H
#define MADEIRA_CEF_LOG_CONTEXT_H
#include "../steam-ui/trace.h"
extern void ios_cef_assert_context(void);
static void ios_cef_log_observe( int fd, const void *buffer, unsigned int length )
{
    static unsigned int assertions;
    static __thread char tags[12][128];
    static __thread unsigned int next, used, following;
    TEB *teb = NtCurrentTeb();
    RTL_USER_PROCESS_PARAMETERS *params = teb && teb->Peb ? teb->Peb->ProcessParameters : NULL;
    const char *b = buffer;
    char path[PATH_MAX];
    const char *name;
    unsigned int n, start, end;
    int saved_errno = errno;
    if (!params || madeira_steam_ui_image( params->ImagePathName.Buffer,
            params->ImagePathName.Length / sizeof(WCHAR) ) != 2 || !buffer || !length) return;
    if (!ios_guest_log_fd_path( fd, path, sizeof(path) )) goto out;
    name = strrchr( path, '/' ); name = name ? name + 1 : path;
    if (strcasecmp( name, "debug.log" )) goto out;
    n = length < 4096 ? length : 4096;
    for (start = 0; start < n; start = end + 1)
    {
        char line[512], tag[128];
        const char *close;
        size_t len, taglen;
        for (end = start; end < n && b[end] != '\n'; end++) ;
        len = end - start; if (len >= sizeof(line)) len = sizeof(line) - 1;
        memcpy( line, b + start, len ); line[len] = 0;
        /* Keep only Chromium's timestamp/level/source prefix. Log bodies can
         * contain URLs or account data and never enter the context ring. */
        if (!len || line[0] != '[' || !(close = strchr( line, ']' ))) continue;
        taglen = close - line + 1;
        if (taglen >= sizeof(tag)) taglen = sizeof(tag) - 1;
        memcpy( tag, line, taglen ); tag[taglen] = 0;
        if (strstr( line, "Check failed:" ) || strstr( line, "NOTREACHED" ))
        {
            unsigned int event = __atomic_fetch_add( &assertions, 1, __ATOMIC_RELAXED );
            if (event < 2)
            {
                dprintf( 2, "[cef-assert] event=%u pid=%04x tid=%04x source=%s context=source-tags-only\n",
                         event + 1, (unsigned)(ULONG_PTR)teb->ClientId.UniqueProcess,
                         (unsigned)(ULONG_PTR)teb->ClientId.UniqueThread, tag );
                for (unsigned int i = 0; i < used; i++)
                    dprintf( 2, "[cef-adjacent] before=%u source=%s\n", used - i,
                             tags[(next + 12 - used + i) % 12] );
                ios_cef_assert_context();
                following = 8;
            }
        }
        else if (following)
        {
            dprintf( 2, "[cef-adjacent] after=%u source=%s\n", 9 - following, tag );
            following--;
        }
        memcpy( tags[next], tag, taglen + 1 );
        next = (next + 1) % 12; if (used < 12) used++;
    }
out:
    errno = saved_errno;
}
#endif
