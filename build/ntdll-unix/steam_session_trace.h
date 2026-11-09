/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Read-only summaries of the genuine client's/game's own connection logs.
 * Input bodies may contain credentials and identifiers; only fixed tokens and
 * explicitly labelled small result codes can leave this classifier.
 */
#ifndef MADEIRA_STEAM_SESSION_TRACE_H
#define MADEIRA_STEAM_SESSION_TRACE_H
#include <time.h>

static unsigned int ios_steam_session_lines;

/* Prove coverage separately from a parsed message. An absent VAC summary is
 * never evidence that authentication succeeded or that the game logged a
 * rejection. Only fixed source labels and owning Windows IDs are emitted. */
static void ios_steam_session_source_observed( const char *source, unsigned int role,
                                              uintptr_t owner, dev_t dev, ino_t ino )
{
    static uint64_t seen[32];
    uint64_t key = (uint64_t)owner ^ ((uint64_t)dev << 17) ^ ((uint64_t)ino << 3) ^
                   ((uint64_t)GetCurrentProcessId() << 32);
    for (const char *p = source; *p; p++) key = (key ^ (unsigned char)*p) * 1099511628211ULL;
    if (!key) key = 1;
    for (unsigned int i = 0; i < sizeof(seen) / sizeof(seen[0]); i++)
    {
        uint64_t previous = __atomic_load_n( &seen[i], __ATOMIC_RELAXED );
        if (previous == key) return;
        if (!previous && __atomic_compare_exchange_n( &seen[i], &previous, key, 0,
                                                      __ATOMIC_RELAXED, __ATOMIC_RELAXED ))
        {
            dprintf( 2, "[steam-session-source-v1] source=%s role=%s pid=%04x tid=%04x "
                        "successful-write-observed=1 body=excluded authentication-result=unknown\n",
                     source, role == 1 ? "steam" : role == 2 ? "cs2" : "service",
                     (unsigned int)GetCurrentProcessId(), (unsigned int)GetCurrentThreadId() );
            return;
        }
        if (previous == key) return;
    }
}

static int ios_steam_session_basename( const WCHAR *image, unsigned int length, const char *expected )
{
    unsigned int base = 0, i;
    if (!image || !length || length > 32768) return 0;
    for (i = 0; i < length; i++) if (image[i] == '\\' || image[i] == '/') base = i + 1;
    if (length - base != strlen( expected )) return 0;
    for (i = base; i < length; i++)
    {
        WCHAR c = image[i];
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (c != (unsigned char)expected[i - base]) return 0;
    }
    return 1;
}

/* Do not identify a process by the session-wide main image or wow_peb. */
static unsigned int ios_steam_session_role( const RTL_USER_PROCESS_PARAMETERS *params )
{
    const WCHAR *image = params->ImagePathName.Buffer;
    unsigned int length = params->ImagePathName.Length / sizeof(WCHAR);
    if (madeira_steam_ui_image( image, length ) == 1) return 1;
    if (ios_steam_session_basename( image, length, "cs2.exe" )) return 2;
    if (ios_steam_session_basename( image, length, "steamservice.exe" )) return 3;
    return 0;
}

static const char *ios_steam_session_source( const char *path, unsigned int role )
{
    const char *name = strrchr( path, '/' );
    name = name ? name + 1 : path;
    if (role == 1)
    {
        const char *launch = ios_steam_launch_source( path );
        if (launch) return launch;
        if (!strcasecmp( name, "connection_log.txt" )) return "steam-connection";
    }
    if (role == 2 && !strcasecmp( name, "console.log" )) return "cs2-console";
    if (role == 3 && (!strcasecmp( name, "service_log.txt" ) ||
                      !strcasecmp( name, "steamservice.log" ))) return "steam-service";
    return NULL;
}

static int ios_steam_session_has( const char *line, const char *token )
{
    const char *p = line;
    size_t n = strlen( token );
    while ((p = strstr( p, token )))
    {
        if ((p == line || !((p[-1] >= 'a' && p[-1] <= 'z') ||
                            (p[-1] >= 'A' && p[-1] <= 'Z') ||
                            (p[-1] >= '0' && p[-1] <= '9') || p[-1] == '_')) &&
            !((p[n] >= 'a' && p[n] <= 'z') || (p[n] >= 'A' && p[n] <= 'Z') ||
              (p[n] >= '0' && p[n] <= '9') || p[n] == '_')) return 1;
        p += n;
    }
    return 0;
}

static int ios_steam_session_code( const char *line, const char *label, unsigned int *value )
{
    const char *p = line;
    size_t n = strlen( label );
    unsigned int digits = 0, result = 0;
    while ((p = strstr( p, label )))
    {
        if (p == line || !((p[-1] >= 'a' && p[-1] <= 'z') ||
                           (p[-1] >= 'A' && p[-1] <= 'Z') ||
                           (p[-1] >= '0' && p[-1] <= '9') || p[-1] == '_')) break;
        p += n;
    }
    if (!p) return 0;
    p += n;
    if (label[n - 1] != '=' && *p != ' ' && *p != '\t' && *p != '=' && *p != ':') return 0;
    while (*p == ' ' || *p == '\t' || *p == '=' || *p == ':') p++;
    while (*p >= '0' && *p <= '9' && digits < 4)
    { result = result * 10 + (*p++ - '0'); digits++; }
    if (!digits || result > 255 || (*p >= '0' && *p <= '9') ||
        (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || *p == '_') return 0;
    *value = result;
    return 1;
}

/* These are SDK enum spellings or a few exact diagnostic phrases, not a
 * translation of an unknown numeric code into a purported VAC decision. */
static void ios_steam_session_line( const char *source, const char *line, unsigned int role )
{
    static const char * const auth[] = {
        "k_EAuthSessionResponseOK", "k_EAuthSessionResponseUserNotConnectedToSteam",
        "k_EAuthSessionResponseNoLicenseOrExpired", "k_EAuthSessionResponseVACBanned",
        "k_EAuthSessionResponseLoggedInElseWhere", "k_EAuthSessionResponseVACCheckTimedOut",
        "k_EAuthSessionResponseAuthTicketCanceled", "k_EAuthSessionResponseAuthTicketInvalidAlreadyUsed",
        "k_EAuthSessionResponseAuthTicketInvalid", "k_EAuthSessionResponsePublisherIssuedBan"
    };
    static __thread uintptr_t previous_owner;
    static __thread unsigned int previous_signature;
    const char *event = NULL, *reported = "unavailable";
    TEB *teb = NtCurrentTeb();
    uintptr_t owner = (uintptr_t)(teb ? teb->Peb : NULL);
    unsigned int result = 0, has_result, signature = 2166136261u, serial;
    struct timespec now;

    if (__atomic_load_n( &ios_steam_session_lines, __ATOMIC_RELAXED ) >= 96 || !owner) return;
    if (strstr( line, "SteamAPI_Init" ))
    {
        if (strstr( line, "Loaded" ) && strstr( line, "steamclient" ) && strstr( line, "OK" ))
            event = "api-client-loaded";
        else if (strstr( line, "failed" ) || strstr( line, "Failed" ) || strstr( line, "FAIL" ))
            event = "api-initialization-failed";
    }
    for (unsigned int i = 0; i < sizeof(auth) / sizeof(auth[0]); i++)
        if (ios_steam_session_has( line, auth[i] )) { reported = auth[i]; event = "auth-session-response"; break; }
    if (!event && (ios_steam_session_has( line, "VAC" ) || strstr( line, "VACCheck" )))
        event = "vac-message"; /* body/reason unknown; never infer a ban */
    if (!event && (strstr( line, "SteamServersConnected" ) || strstr( line, "Steam servers connected" )))
        event = "steam-servers-connected-message";
    if (!event && (strstr( line, "SteamServersDisconnected" ) || strstr( line, "Steam servers disconnected" )))
        event = "steam-servers-disconnected-message";
    if (!event && strstr( line, "SteamServerConnectFailure" )) event = "steam-server-connect-failure";
    if (!event && (strstr( line, "SteamNetworkingSockets" ) || strstr( line, "SteamNetSockets" ) ||
                   strstr( line, "steamnetworkingsockets" )))
    {
        if (strstr( line, "ProblemDetectedLocally" )) event = "network-problem-detected-locally";
        else if (strstr( line, "ClosedByPeer" )) event = "network-closed-by-peer";
        else if (strstr( line, "No control data returned even though we asked for TOS" ))
            event = "network-tos-control-missing";
        else if (strstr( line, "failed" ) || strstr( line, "Failed" ) || strstr( line, "error" ))
            event = "network-error-message";
    }
    if (!event && role == 3 && (strstr( line, "error" ) || strstr( line, "failed" ) || strstr( line, "Failed" )))
        event = "service-error-message";
    if (!event) return;
    has_result = ios_steam_session_code( line, "EResult", &result );
    if (!has_result) has_result = ios_steam_session_code( line, "AuthSessionResponse=", &result );
    for (const char *p = source; *p; p++) signature = (signature ^ *p) * 16777619u;
    for (const char *p = event; *p; p++) signature = (signature ^ *p) * 16777619u;
    for (const char *p = reported; *p; p++) signature = (signature ^ *p) * 16777619u;
    signature ^= result + (has_result << 16) + (role << 24);
    if (previous_owner == owner && previous_signature == signature) return;
    previous_owner = owner; previous_signature = signature;
    serial = __atomic_load_n( &ios_steam_session_lines, __ATOMIC_RELAXED );
    for (;;)
    {
        if (serial >= 96) return;
        if (__atomic_compare_exchange_n( &ios_steam_session_lines, &serial, serial + 1, 0,
                                         __ATOMIC_RELAXED, __ATOMIC_RELAXED )) break;
    }
    memset( &now, 0, sizeof(now) );
    clock_gettime( CLOCK_MONOTONIC, &now );
    dprintf( 2, "[steam-session-v1] source=%s role=%s pid=%04x tid=%04x event=%s "
                "reported-token=%s numeric-result-present=%u numeric-result=%u sequence=%u "
                "monotonic-ms=%llu evidence=application-log auth-validation=unclaimed body=excluded\n",
             source, role == 1 ? "steam" : role == 2 ? "cs2" : "service",
             (unsigned int)GetCurrentProcessId(), (unsigned int)GetCurrentThreadId(), event, reported,
             has_result, result, serial + 1,
             (unsigned long long)now.tv_sec * 1000 + (unsigned long long)now.tv_nsec / 1000000 );
}
#endif
