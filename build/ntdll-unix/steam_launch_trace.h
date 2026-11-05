/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Passive, bounded summaries of Steam's own AppID 730 launch/content logs.
 * No log body, pathname, command line, URL or account identifier is emitted.
 * Included only in the staged Wine file.c, after cef_log_context.h.
 */
#ifndef MADEIRA_STEAM_LAUNCH_TRACE_H
#define MADEIRA_STEAM_LAUNCH_TRACE_H
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

static unsigned int ios_steam_launch_lines;
static const char *ios_steam_launch_source( const char *path )
{
    const char *name = strrchr( path, '/' );
    name = name ? name + 1 : path;
    if (!strcasecmp( name, "content_log.txt" )) return "content";
    if (!strcasecmp( name, "gameprocess_log.txt" )) return "gameprocess";
    if (!strcasecmp( name, "console_log.txt" )) return "console";
    return NULL;
}

static int ios_steam_launch_app730( const char *line )
{
    const char *p = line;
    while ((p = strstr( p, "AppID" )))
    {
        p += 5;
        while (*p == ' ' || *p == '\t') p++;
        if (!strncmp( p, "730", 3 ) && (p[3] < '0' || p[3] > '9')) return 1;
    }
    return 0;
}

/* Task names are an allowlist, never arbitrary text from a guest log. */
static const char *ios_steam_launch_task( const char *line )
{
    static const char * const names[] = {
        "UpdatingAppInfo", "CheckingAppOwnership", "UpdatingApp", "Validating",
        "PreparingLaunch", "ProcessingInstallScript", "SynchronizingCloud",
        "SyncingCloud", "SiteLicenseSeatCheckout", "WaitingGameCommandLine",
        "CreatingProcess", "Launching", "Completing", "ShowError", "Waiting"
    };
    const char *p = strstr( line, "changed task to " );
    unsigned int i;
    if (!p) return "none";
    p += strlen( "changed task to " );
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
    {
        size_t n = strlen( names[i] );
        if (!strncmp( p, names[i], n ) &&
            !((p[n] >= 'a' && p[n] <= 'z') || (p[n] >= 'A' && p[n] <= 'Z') ||
              (p[n] >= '0' && p[n] <= '9') || p[n] == '_')) return names[i];
    }
    return "unknown";
}

static void ios_steam_launch_line( const char *source, const char *line )
{
    static __thread unsigned int previous_signature;
    const char *event, *task, *error;
    unsigned int flags = 0, code = 0, has_error = 0, signature = 2166136261u, serial;
    if (!ios_steam_launch_app730( line )) return;
    if (strstr( line, "Validating" ) || strstr( line, "validating" )) flags |= 1;
    if (strstr( line, "Verifying" ) || strstr( line, "verifying" )) flags |= 2;
    if (strstr( line, "Fully Installed" )) flags |= 4;
    if (strstr( line, "Update Required" )) flags |= 8;
    if (strstr( line, "Update Running" )) flags |= 16;
    if (strstr( line, "Update Paused" )) flags |= 32;
    if (strstr( line, "Update Complete" ) || strstr( line, "update finished" )) flags |= 64;
    if (strstr( line, "GameAction" )) event = "game-action";
    else if (strstr( line, "Adding process" )) event = "process-added";
    else if (strstr( line, "Removing process" ) || strstr( line, "no longer tracking process" )) event = "process-removed";
    else if (flags || strstr( line, "update state" ) || strstr( line, "update changed" )) event = "content-state";
    else return;
    task = ios_steam_launch_task( line );
    error = strstr( line, "AppError_" );
    if (error)
    {
        unsigned int digits = 0;
        error += strlen( "AppError_" );
        while (*error >= '0' && *error <= '9' && digits < 5)
        { code = code * 10 + (*error++ - '0'); digits++; }
        has_error = digits && !(*error >= '0' && *error <= '9');
        if (!has_error) code = 0;
    }
    /* Dedupe only the safe summary, not guest bytes. Do not claim an unknown
     * task or an absent completion line represents successful validation. */
    for (const char *p = source; *p; p++) signature = (signature ^ *p) * 16777619u;
    for (const char *p = event; *p; p++) signature = (signature ^ *p) * 16777619u;
    for (const char *p = task; *p; p++) signature = (signature ^ *p) * 16777619u;
    signature ^= flags + (code << 8) + (has_error << 25);
    if (signature == previous_signature) return;
    previous_signature = signature;
    serial = __atomic_load_n( &ios_steam_launch_lines, __ATOMIC_RELAXED );
    for (;;)
    {
        if (serial >= 128) return;
        if (__atomic_compare_exchange_n( &ios_steam_launch_lines, &serial, serial + 1, 0,
                                         __ATOMIC_RELAXED, __ATOMIC_RELAXED )) break;
    }
    dprintf( 2, "[steam-launch-v1] source=%s app=730 pid=%04x tid=%04x event=%s task=%s "
                "state-flags=0x%x app-error-present=%u app-error=%u sequence=%u\n",
             source, (unsigned int)GetCurrentProcessId(), (unsigned int)GetCurrentThreadId(),
             event, task, flags, has_error, code, serial + 1 );
}

static void ios_steam_launch_log_observe( int fd, const void *buffer, unsigned int length )
{
    static __thread struct
    {
        uintptr_t owner;
        dev_t dev;
        ino_t ino;
        const char *source;
        unsigned int used, dropped;
        char line[768];
    } stream;
    TEB *teb = NtCurrentTeb();
    RTL_USER_PROCESS_PARAMETERS *params = teb && teb->Peb ? teb->Peb->ProcessParameters : NULL;
    struct stat st;
    char path[PATH_MAX];
    const char *source, *bytes = buffer;
    int saved_errno = errno;
    if (__atomic_load_n( &ios_steam_launch_lines, __ATOMIC_RELAXED ) >= 128 ||
        !params || madeira_steam_ui_image( params->ImagePathName.Buffer,
            params->ImagePathName.Length / sizeof(WCHAR) ) != 1 || !buffer || !length) return;
    if (!ios_guest_log_fd_path( fd, path, sizeof(path) ) ||
        !(source = ios_steam_launch_source( path )) || fstat( fd, &st )) goto out;
    if (stream.owner != (uintptr_t)teb->Peb || stream.dev != st.st_dev || stream.ino != st.st_ino ||
        stream.source != source)
    {
        stream.owner = (uintptr_t)teb->Peb; stream.dev = st.st_dev; stream.ino = st.st_ino;
        stream.source = source; stream.used = stream.dropped = 0;
    }
    /* Bound work too. If a very large write is clipped, drop its final partial
     * line; never join a missing middle to a later write. */
    for (unsigned int i = 0; i < length && i < 65536; i++)
    {
        if (bytes[i] == '\n')
        {
            if (!stream.dropped)
            {
                stream.line[stream.used] = 0;
                ios_steam_launch_line( source, stream.line );
            }
            stream.used = stream.dropped = 0;
        }
        else if (!stream.dropped)
        {
            if (stream.used < sizeof(stream.line) - 1) stream.line[stream.used++] = bytes[i];
            else { stream.used = 0; stream.dropped = 1; }
        }
    }
    if (length > 65536) { stream.used = 0; stream.dropped = 1; }
out:
    errno = saved_errno;
}
#endif
