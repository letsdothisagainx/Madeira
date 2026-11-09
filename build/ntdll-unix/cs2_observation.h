/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Passive accepted-process/image observations. No trust or readiness result.
 * All exported names are literals; unknown arguments/paths never leave here. */
#ifndef MADEIRA_CS2_OBSERVATION_H
#define MADEIRA_CS2_OBSERVATION_H
#include <stddef.h>
#include <stdint.h>
void ios_cs2_observe_current_start(unsigned machine);
void ios_cs2_observe_current_map(const void *name, unsigned machine, int hybrid);

#ifdef MADEIRA_CS2_OBSERVATION_IMPLEMENTATION
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#define IOS_CS2_PATH 1024
#define IOS_CS2_ARGS 128
/* The measured CS2 main thread alone had 125 map events. Keep bounded
 * headroom for concurrent/resource views without claiming a full census. */
#define IOS_CS2_MAPS 256
#define IOS_CS2_DROPS 128
struct ios_cs2_flags {
    unsigned flag[5], arguments, unknown, complete;
    char sequence[IOS_CS2_ARGS * 2];
};
static unsigned ios_cs2_lower(unsigned c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }
static int ios_cs2_role(const uint16_t *image, size_t length)
{
    static const char suffix[] = "cs2.exe";
    size_t i, base = length;
    if (!image || !length || length >= IOS_CS2_PATH) return 0;
    for (i = 0; i < length; i++) if (!image[i]) return 0;
    while (base && image[base - 1] != '/' && image[base - 1] != '\\') base--;
    if (length - base != sizeof(suffix) - 1) return 0;
    for (i = 0; i < sizeof(suffix) - 1; i++) if (ios_cs2_lower(image[base + i]) != (unsigned char)suffix[i]) return 0;
    return 1;
}
/* CRT quoting: argv[0] uses the executable-name rule; later arguments use
 * even/odd backslashes before quotes and doubled quotes within quotes. */
static struct ios_cs2_flags ios_cs2_parse(const uint16_t *text, size_t length)
{
    static const char *const known[] = { "-steam", "-condebug", "-joy", "-insecure", "-allow_third_party_software" };
    struct ios_cs2_flags out = {{0}, 0, 0, 1, "-"};
    size_t p = 0, serial = 0, used = 0;
    if (!text || !length || length > 32767) { out.complete = 0; return out; }
    /* CRT gives a leading separator an empty argv[0]. */
    if (text[0] == ' ' || text[0] == '\t') serial = 1;
    while (p < length)
    {
        char token[64];
        size_t n = 0;
        int quoted = 0, first = !serial;
        while (p < length && (text[p] == ' ' || text[p] == '\t')) p++;
        if (p == length) break;
        if (serial && out.arguments == IOS_CS2_ARGS) { out.complete = 0; break; }
        while (p < length && (quoted || (text[p] != ' ' && text[p] != '\t')))
        {
            unsigned c = text[p++];
            int literal_quote = 0;
            if (!c) { out.complete = 0; p = length; break; }
            if (!first && c == '\\')
            {
                size_t slashes = 1, i;
                while (p < length && text[p] == '\\') { slashes++; p++; }
                if (p < length && text[p] == '"')
                {
                    for (i = 0; i < slashes / 2; i++) { if (n < sizeof(token)) token[n] = '\\'; n++; }
                    c = '"'; p++;
                    literal_quote = slashes & 1;
                }
                else { for (i = 0; i < slashes; i++) { if (n < sizeof(token)) token[n] = '\\'; n++; } continue; }
            }
            if (c == '"' && !literal_quote)
            {
                if (!first && quoted && p < length && text[p] == '"') { p++; c = '"'; }
                else { quoted = !quoted; continue; }
            }
            if (n < sizeof(token)) token[n] = c < 128 ? (char)ios_cs2_lower(c) : '?';
            n++;
        }
        if (quoted) out.complete = 0;
        if (serial++)
        {
            unsigned k;
            out.arguments++;
            for (k = 0; k < 5; k++) if (n == strlen(known[k]) && n < sizeof(token) && !memcmp(token, known[k], n)) break;
            if (k == 5 || quoted || !out.complete) out.unknown++;
            else
            {
                out.flag[k] = 1;
                if (used) out.sequence[used++] = ',';
                out.sequence[used++] = (char)('0' + k); out.sequence[used] = 0;
            }
        }
        if (!out.complete) break;
    }
    if (!serial) out.complete = 0;
    return out;
}
static int ios_cs2_path(const uint16_t *input, size_t length, char out[IOS_CS2_PATH])
{
    size_t i, at = 0, start = 0, component = 0;
    if (!input || !length || length >= IOS_CS2_PATH) return 0;
    if (length >= 4 && input[0] == '\\' && ((input[1] == '?' && input[2] == '?') ||
        (input[1] == '\\' && input[2] == '?')) && input[3] == '\\') start = 4;
    for (i = start; i < length; i++)
    {
        unsigned c = input[i];
        if (c < 32 || c > 126 || c == '"' || c == '?' || c == '#' || c == '@' || c == '%') return 0;
        if (c == '\\') c = '/';
        if (c == '/')
        {
            if (!component && at) return 0;
            if ((component == 1 && out[at - 1] == '.') || (component == 2 && out[at - 1] == '.' && out[at - 2] == '.')) return 0;
            component = 0;
        }
        else component++;
        out[at++] = (char)ios_cs2_lower(c);
    }
    if ((component == 1 && out[at - 1] == '.') || (component == 2 && out[at - 1] == '.' && out[at - 2] == '.')) return 0;
    out[at] = 0;
    if (!strncmp(out, "unix/", 5)) memmove(out, out + 4, at - 3);
    return out[0] == '/' || (out[0] >= 'a' && out[0] <= 'z' && out[1] == ':' && out[2] == '/');
}
static const char *const ios_cs2_game_paths[] = {
    "game/bin/win64/cs2.exe", "game/bin/win64/tier0.dll", "game/bin/win64/engine2.dll",
    "game/bin/win64/filesystem_stdio.dll", "game/bin/win64/rendersystemdx11.dll",
    "game/bin/win64/steam_api64.dll", "game/bin/win64/steamnetworkingsockets.dll",
    "game/csgo/bin/win64/client.dll", "game/csgo/bin/win64/server.dll"
};
static const char *const ios_cs2_system_names[] = {
    "ntdll.dll", "kernel32.dll", "kernelbase.dll", "wintrust.dll", "crypt32.dll", "bcrypt.dll",
    "advapi32.dll", "sechost.dll", "rpcrt4.dll", "ws2_32.dll", "ucrtbase.dll", "msvcrt.dll",
    "win32u.dll", "user32.dll", "gdi32.dll", "d3d9.dll", "d3d11.dll", "dxgi.dll", "winemetal.dll", "nvapi64.dll",
    "setupapi.dll", "version.dll", "psapi.dll", "ole32.dll", "oleaut32.dll", "combase.dll",
    "coml2.dll", "winhttp.dll", "cryptnet.dll", "ncrypt.dll", "mswsock.dll", "shlwapi.dll",
    "shell32.dll", "shcore.dll", "imm32.dll", "uxtheme.dll", "comctl32.dll", "xtajit64.dll", "libarm64ecfex.dll"
};
struct ios_cs2_process {
    void *owner;
    uint64_t lease;
    uint32_t pid;
    unsigned maps, unknown, dropped;
    char game[IOS_CS2_PATH], steam[IOS_CS2_PATH], search[IOS_CS2_PATH];
};
static struct ios_cs2_process ios_cs2_processes[4];
static pthread_mutex_t ios_cs2_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct ios_cs2_process *ios_cs2_find(void *owner, uint32_t pid, uint64_t lease)
{
    unsigned i;
    if (!owner || !pid || !lease) return NULL;
    for (i = 0; i < 4; i++) if (__atomic_load_n(&ios_cs2_processes[i].owner, __ATOMIC_ACQUIRE) == owner &&
        ios_cs2_processes[i].pid == pid && ios_cs2_processes[i].lease == lease) return &ios_cs2_processes[i];
    return NULL;
}
static int ios_cs2_under(const char *path, const char *root, const char *relative)
{
    size_t n = strlen(root);
    return n && !strncmp(path, root, n) && path[n] == '/' && !strcmp(path + n + 1, relative);
}
static void ios_cs2_classify(const struct ios_cs2_process *state, const char *path,
                            const char **kind, char relative[96])
{
    static const char *const system_dirs[] = { "system32", "sysx64", "syswow64" };
    static const char *const farms[] = { "aarch64-windows", "arm64ec-windows", "i386-windows" };
    unsigned i, j;
    char candidate[96];
    *kind = "private"; strcpy(relative, "redacted");
    for (i = 0; i < sizeof(ios_cs2_game_paths)/sizeof(*ios_cs2_game_paths); i++)
        if (ios_cs2_under(path, state->game, ios_cs2_game_paths[i])) { *kind = "game"; strcpy(relative, ios_cs2_game_paths[i]); return; }
    if (ios_cs2_under(path, state->steam, "steamclient64.dll")) { *kind = "steam-client"; strcpy(relative, "steamclient64.dll"); return; }
    for (i = 0; i < sizeof(ios_cs2_system_names)/sizeof(*ios_cs2_system_names); i++) for (j = 0; j < 3; j++)
    {
        snprintf(candidate, sizeof(candidate), "%s/%s", system_dirs[j], ios_cs2_system_names[i]);
        if (ios_cs2_under(path, "c:/windows", candidate)) { *kind = "system"; strcpy(relative, candidate); return; }
        snprintf(candidate, sizeof(candidate), "%s/%s", farms[j], ios_cs2_system_names[i]);
        if (ios_cs2_under(path, state->search, candidate)) { *kind = "search-root"; strcpy(relative, candidate); return; }
    }
}
/* Production supplies fault-safe copies and the existing create=false lease
 * lookup. No owner adoption, guest pointers, or thread IDs are cached. */
static void ios_cs2_record_start(void *owner, uint32_t pid, uint32_t tid, uint64_t lease,
    const uint16_t *image, size_t image_length, const uint16_t *command, size_t command_length,
    const char *search_root)
{
    struct ios_cs2_flags flags;
    struct ios_cs2_process *state = NULL;
    char path[IOS_CS2_PATH];
    size_t n, i;
    const char *middle;
    if (!ios_cs2_role(image, image_length) || !owner || !pid || !tid || !lease || pthread_mutex_trylock(&ios_cs2_mutex)) return;
    if (ios_cs2_find(owner, pid, lease)) { pthread_mutex_unlock(&ios_cs2_mutex); return; }
    for (i = 0; i < 4; i++) if (!ios_cs2_processes[i].owner) { state = &ios_cs2_processes[i]; break; }
    if (!state) { pthread_mutex_unlock(&ios_cs2_mutex); return; }
    state->pid = pid; state->lease = lease;
    if (ios_cs2_path(image, image_length, path))
    {
        static const char tail[] = "/game/bin/win64/cs2.exe";
        n = strlen(path);
        if (n >= sizeof(tail) - 1 && !strcmp(path + n - sizeof(tail) + 1, tail))
        {
            path[n - sizeof(tail) + 1] = 0; strcpy(state->game, path);
            if ((middle = strstr(path, "/steamapps/common/"))) { n = middle - path; memcpy(state->steam, path, n); state->steam[n] = 0; }
        }
    }
    if (search_root)
    {
        uint16_t wide[IOS_CS2_PATH];
        for (i = 0; i < IOS_CS2_PATH && search_root[i]; i++) wide[i] = (unsigned char)search_root[i];
        if (i < IOS_CS2_PATH && ios_cs2_path(wide, i, path)) strcpy(state->search, path);
    }
    __atomic_store_n(&state->owner, owner, __ATOMIC_RELEASE);
    flags = ios_cs2_parse(command, command_length);
    pthread_mutex_unlock(&ios_cs2_mutex);
    MADEIRA_CS2_EMIT("[cs2-launch-flags-v1] pid=%04x tid=%04x steam=%u condebug=%u joy=%u insecure=%u allow-third-party=%u argument-count=%u unknown-count=%u known-sequence=%s parse-complete=%u coverage=accepted-process-params\n",
        pid, tid, flags.flag[0], flags.flag[1], flags.flag[2], flags.flag[3], flags.flag[4], flags.arguments, flags.unknown, flags.sequence, flags.complete);
}
static void ios_cs2_record_map(void *owner, uint32_t pid, uint32_t tid, uint64_t lease,
    const uint16_t *image, size_t image_length, const uint16_t *name, size_t name_length,
    unsigned machine, int hybrid, int main_image)
{
    struct ios_cs2_process *state;
    char path[IOS_CS2_PATH], relative[96];
    const char *kind = "unknown", *hybrid_text = hybrid < 0 ? "unmeasured" : hybrid ? "1" : "0";
    unsigned sequence, unknown, dropped;
    if (!tid || !ios_cs2_role(image, image_length) || !(state = ios_cs2_find(owner, pid, lease))) return;
    if (pthread_mutex_trylock(&ios_cs2_mutex))
    {
        unsigned old = __atomic_load_n(&state->dropped, __ATOMIC_RELAXED);
        if (old < IOS_CS2_DROPS) __atomic_compare_exchange_n(&state->dropped, &old, old + 1, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
        return;
    }
    if (__atomic_load_n(&state->maps, __ATOMIC_RELAXED) >= IOS_CS2_MAPS) { pthread_mutex_unlock(&ios_cs2_mutex); return; }
    strcpy(relative, "redacted");
    if (ios_cs2_path(name, name_length, path)) ios_cs2_classify(state, path, &kind, relative);
    if (!strcmp(relative, "redacted")) state->unknown++;
    sequence = __atomic_load_n(&state->maps, __ATOMIC_RELAXED) + 1;
    __atomic_store_n(&state->maps, sequence, __ATOMIC_RELAXED);
    unknown = state->unknown;
    dropped = __atomic_load_n(&state->dropped, __ATOMIC_RELAXED);
    pthread_mutex_unlock(&ios_cs2_mutex);
    if (machine == 0x014c || machine == 0x8664 || machine == 0xaa64 || machine == 0xa641 || machine == 0xa64e)
        snprintf(path, sizeof(path), "%04x", machine);
    else strcpy(path, "unknown");
    MADEIRA_CS2_EMIT("[cs2-module-v1] pid=%04x tid=%04x path-class=%s relative=%s machine=%s hybrid=%s unknown-count=%u dropped-observed=%u sequence=%u limit=256 coverage=bounded-observed-load-events path-source=%s\n",
        pid, tid, kind, relative, path, hybrid_text, unknown, dropped, sequence, main_image ? "accepted-main-image" : "section-name");
}
#endif
#endif
