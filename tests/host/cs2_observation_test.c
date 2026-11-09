/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Actual passive-observer header fixtures. Host OS/emit plumbing is explicit;
 * this does not execute Steam, authenticate an account, or establish VAC trust. */
#include <assert.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pthread_mutex_t capture_lock = PTHREAD_MUTEX_INITIALIZER;
static char captured[1024][2048];
static size_t captured_count;
static void capture(const char *format, ...)
{
    va_list args;
    int length;
    pthread_mutex_lock(&capture_lock);
    assert(captured_count < sizeof(captured) / sizeof(*captured));
    va_start(args, format);
    length = vsnprintf(captured[captured_count], sizeof(*captured), format, args);
    va_end(args);
    assert(length > 0 && (size_t)length < sizeof(*captured));
    captured_count++;
    pthread_mutex_unlock(&capture_lock);
}
#define MADEIRA_CS2_EMIT(...) capture(__VA_ARGS__)
#define MADEIRA_CS2_OBSERVATION_IMPLEMENTATION
#include "cs2_observation.h"

static const char game_image[] = "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Counter-Strike Global Offensive\\game\\bin\\win64\\cs2.exe";
static const char private_value[] = "PRIVATE_OPAQUE_SENTINEL_76561198000000000_ticket@example.org";

static size_t wide(const char *text, uint16_t *out, size_t capacity)
{
    size_t count = strlen(text), i;
    assert(count < capacity);
    for (i = 0; i < count; i++) out[i] = (unsigned char)text[i];
    out[count] = 0;
    return count;
}
static struct ios_cs2_flags parse(const char *text)
{
    uint16_t input[32769];
    size_t length = wide(text, input, sizeof(input) / sizeof(*input));
    return ios_cs2_parse(input, length);
}
static void flags(const char *text, unsigned mask, unsigned count, unsigned unknown,
                  unsigned complete, const char *sequence)
{
    struct ios_cs2_flags result = parse(text);
    unsigned i;
    for (i = 0; i < 5; i++) assert(result.flag[i] == !!(mask & (1u << i)));
    assert(result.arguments == count);
    assert(result.unknown == unknown);
    assert(result.complete == complete);
    assert(!strcmp(result.sequence, sequence));
}
static void reset(void)
{
    pthread_mutex_lock(&ios_cs2_mutex);
    memset(ios_cs2_processes, 0, sizeof(ios_cs2_processes));
    pthread_mutex_unlock(&ios_cs2_mutex);
    pthread_mutex_lock(&capture_lock);
    memset(captured, 0, sizeof(captured));
    captured_count = 0;
    pthread_mutex_unlock(&capture_lock);
}
static void start(void *owner, unsigned pid, uint64_t lease, const char *image,
                  const char *command)
{
    uint16_t image_wide[IOS_CS2_PATH], command_wide[32769];
    size_t image_length = wide(image, image_wide, IOS_CS2_PATH);
    size_t command_length = wide(command, command_wide, sizeof(command_wide) / sizeof(*command_wide));
    ios_cs2_record_start(owner, pid, 0x340, lease, image_wide, image_length,
                         command_wide, command_length, "/owned/Madeira Search");
}
static void map(void *owner, unsigned pid, uint64_t lease, const char *name,
                unsigned machine, int hybrid, int main_image)
{
    uint16_t image_wide[IOS_CS2_PATH], name_wide[IOS_CS2_PATH];
    size_t image_length = wide(game_image, image_wide, IOS_CS2_PATH);
    size_t name_length = wide(name, name_wide, IOS_CS2_PATH);
    ios_cs2_record_map(owner, pid, 0x340, lease, image_wide, image_length,
                       name_wide, name_length, machine, hybrid, main_image);
}
static void private_excluded(void)
{
    size_t i;
    for (i = 0; i < captured_count; i++)
    {
        assert(!strstr(captured[i], private_value));
        assert(!strstr(captured[i], "76561198000000000"));
        assert(!strstr(captured[i], "@example.org"));
        assert(!strstr(captured[i], "C:\\"));
        assert(!strstr(captured[i], "/owned/"));
        assert(!strstr(captured[i], "0x12345"));
    }
}
static void parser_tests(void)
{
    struct ios_cs2_flags result;
    uint16_t embedded[64], unicode[64], input[32769];
    size_t length, i, at;
    char text[32769];
    flags("cs2.exe -steam -condebug -joy -insecure -allow_third_party_software", 31, 5, 0, 1, "0,1,2,3,4");
    flags("\"C:\\Program Files\\cs2.exe\" \"-steam\" -st\"ea\"m -JOY", 5, 3, 0, 1, "0,0,2");
    flags("\"C:\\folder\\\" -insecure", 8, 1, 0, 1, "3");
    flags("-insecure -steam", 1, 1, 0, 1, "0"); /* Never interpret argv[0] as a flag. */
    flags(" -insecure", 8, 1, 0, 1, "3"); /* CRT empty argv[0], no initial trim. */
    flags("\t-steam\t-joy", 5, 2, 0, 1, "0,2");
    flags("cs2.exe \" -steam\" \"-steam\"suffix --steam /steam -steam=value -steamx", 0, 6, 6, 1, "-");
    flags("cs2.exe \\\"-steam\\\" -st\\\"eam \"-st\"\"eam\"", 0, 3, 3, 1, "-");
    flags("cs2.exe \"\\\\\"\" -insecure\" -steam", 1, 2, 1, 1, "0");
    flags("cs2.exe \"\" \"\" -steam", 1, 3, 2, 1, "0");
    flags("cs2.exe \"-insecure", 0, 1, 1, 0, "-");
    flags("cs2.exe -steam\n-joy", 0, 1, 1, 1, "-"); /* Only space/tab delimit tokens. */
    snprintf(text, sizeof(text), "cs2.exe %s -steam", private_value);
    flags(text, 1, 2, 1, 1, "0");
    assert(!strstr(parse(text).sequence, private_value));

    /* Overflow consumes the entire token, preserving its quote state. A flag
     * inside it must never become a separate recognized argument. */
    strcpy(text, "cs2.exe \""); at = strlen(text);
    memset(text + at, 'x', 1000); at += 1000;
    strcpy(text + at, " -insecure\" -steam");
    flags(text, 1, 2, 1, 1, "0");
    strcpy(text, "cs2.exe "); at = strlen(text);
    memset(text + at, 'x', 64); strcpy(text + at + 64, " -joy");
    flags(text, 4, 2, 1, 1, "2");

    strcpy(text, "cs2.exe");
    for (i = 0; i < IOS_CS2_ARGS; i++) strcat(text, " -steam");
    result = parse(text);
    assert(result.complete && result.arguments == 128 && !result.unknown && result.flag[0]);
    assert(strlen(result.sequence) == 255);
    strcat(text, " -insecure"); result = parse(text);
    assert(!result.complete && result.arguments == 128 && !result.unknown && !result.flag[3]);
    strcpy(text, "cs2.exe");
    for (i = 0; i < IOS_CS2_ARGS; i++) strcat(text, " opaque");
    result = parse(text); assert(result.complete && result.unknown == 128 && !strcmp(result.sequence, "-"));

    length = wide("cs2.exe -steam", embedded, 64);
    embedded[8] = 0;
    result = ios_cs2_parse(embedded, length); assert(!result.complete && !result.flag[0]);
    length = wide("cs2.exe opaque -steam", unicode, 64);
    unicode[8] = 0xd800; /* Unknown UTF-16 content is never exported. */
    result = ios_cs2_parse(unicode, length);
    assert(result.complete && result.unknown == 1 && result.flag[0]);
    for (i = 0; i < 32768; i++) input[i] = 'x';
    result = ios_cs2_parse(input, 32768); assert(!result.complete && !result.arguments);
    result = ios_cs2_parse(input, 32767); assert(result.complete && !result.arguments);
    result = ios_cs2_parse(NULL, 10); assert(!result.complete);
    result = ios_cs2_parse(input, 0); assert(!result.complete);
}
static int path(const char *text, char out[IOS_CS2_PATH])
{
    uint16_t input[IOS_CS2_PATH];
    return ios_cs2_path(input, wide(text, input, IOS_CS2_PATH), out);
}
static void classification(const struct ios_cs2_process *state, const char *input,
                           const char *expected_kind, const char *expected_relative)
{
    char normalized[IOS_CS2_PATH], relative[96];
    const char *kind;
    assert(path(input, normalized));
    ios_cs2_classify(state, normalized, &kind, relative);
    assert(!strcmp(kind, expected_kind)); assert(!strcmp(relative, expected_relative));
}
static void path_tests(void)
{
    char out[IOS_CS2_PATH], huge[IOS_CS2_PATH];
    uint16_t input[IOS_CS2_PATH];
    size_t length, i;
    static const char *const bad[] = {
        "relative/ntdll.dll", "C:/Windows/../system32/ntdll.dll", "C:/Windows/./system32/ntdll.dll",
        "C:/Windows//system32/ntdll.dll", "C:/Windows/system32/..", "C:/Windows/system32/.",
        "C:/Windows/system32/ntdll.dll?ticket=private", "C:/user@example.org/ntdll.dll",
        "C:/Windows/%2e%2e/system32/ntdll.dll", "C:/Windows/#secret/ntdll.dll",
        "C:/Windows/\"secret\"/ntdll.dll", "\\\\server\\share\\ntdll.dll", "C:/Windows/\nntdll.dll"
    };
    assert(path("\\??\\C:\\WINDOWS\\system32\\ntdll.dll", out));
    assert(!strcmp(out, "c:/windows/system32/ntdll.dll"));
    assert(path("\\\\?\\C:\\Windows\\system32\\ntdll.dll", out));
    assert(!strcmp(out, "c:/windows/system32/ntdll.dll"));
    assert(path("\\??\\unix\\owned\\Madeira Search\\arm64ec-windows\\ntdll.dll", out));
    assert(!strcmp(out, "/owned/madeira search/arm64ec-windows/ntdll.dll"));
    for (i = 0; i < sizeof(bad) / sizeof(*bad); i++) assert(!path(bad[i], out));
    length = wide("C:/Windows/system32/ntdll.dll", input, IOS_CS2_PATH);
    input[5] = 0; assert(!ios_cs2_path(input, length, out));
    input[5] = 0x202e; assert(!ios_cs2_path(input, length, out));
    assert(!ios_cs2_path(NULL, 12, out));
    memset(huge, 'x', sizeof(huge));
    for (i = 0; i < IOS_CS2_PATH; i++) input[i] = huge[i];
    assert(!ios_cs2_path(input, IOS_CS2_PATH, out));

    reset(); start((void *)(uintptr_t)0x12345000, 0x324, 23, game_image, "cs2.exe -steam");
    assert(captured_count == 1);
    classification(&ios_cs2_processes[0], game_image, "game", "game/bin/win64/cs2.exe");
    classification(&ios_cs2_processes[0], "C:/Program Files (x86)/Steam/steamapps/common/Counter-Strike Global Offensive/game/csgo/bin/win64/client.dll", "game", "game/csgo/bin/win64/client.dll");
    classification(&ios_cs2_processes[0], "C:/Program Files (x86)/Steam/steamclient64.dll", "steam-client", "steamclient64.dll");
    classification(&ios_cs2_processes[0], "C:/Windows/sysWOW64/ntdll.dll", "system", "syswow64/ntdll.dll");
    classification(&ios_cs2_processes[0], "/owned/Madeira Search/arm64ec-windows/d3d11.dll", "search-root", "arm64ec-windows/d3d11.dll");
    classification(&ios_cs2_processes[0], "/owned/Madeira Search Other/arm64ec-windows/d3d11.dll", "private", "redacted");
    classification(&ios_cs2_processes[0], "D:/Windows/system32/ntdll.dll", "private", "redacted");
    classification(&ios_cs2_processes[0], "C:/Windows/system32/private.dll", "private", "redacted");
    classification(&ios_cs2_processes[0], "C:/Program Files (x86)/Steam Else/steamclient64.dll", "private", "redacted");
    classification(&ios_cs2_processes[0], "C:/Program Files (x86)/Steam/steamapps/common/Counter-Strike Global Offensive Other/game/bin/win64/cs2.exe", "private", "redacted");
    private_excluded();

    /* A rejected root must not publish the partial normalized prefix left
     * before its invalid character. It must not authorize later observations. */
    {
        uint16_t image_wide[IOS_CS2_PATH], command_wide[64];
        size_t image_length = wide(game_image, image_wide, IOS_CS2_PATH);
        size_t command_length = wide("cs2.exe -steam", command_wide, 64);
        reset();
        ios_cs2_record_start((void *)(uintptr_t)0x12345000, 0x324, 0x340, 23,
            image_wide, image_length, command_wide, command_length, "/private/token?secret");
        assert(!ios_cs2_processes[0].search[0]);
        classification(&ios_cs2_processes[0], "/private/token/arm64ec-windows/wintrust.dll", "private", "redacted");
        map((void *)(uintptr_t)0x12345000, 0x324, 23,
            "/private/token/arm64ec-windows/wintrust.dll", 0xa641, 1, 0);
        assert(captured_count == 2);
        assert(strstr(captured[1], "path-class=private relative=redacted"));
        assert(!strstr(captured[1], "/private/") && !strstr(captured[1], "token"));
    }
}
static void record_tests(void)
{
    void *owner = (void *)(uintptr_t)0x12345000;
    size_t before, i;
    char name[IOS_CS2_PATH], command[256];
    reset();
    snprintf(command, sizeof(command), "\"%s\" -steam -condebug %s", game_image, private_value);
    start(owner, 0x324, 23, game_image, command);
    assert(captured_count == 1 && strstr(captured[0], "steam=1 condebug=1 joy=0 insecure=0 allow-third-party=0"));
    assert(strstr(captured[0], "argument-count=3 unknown-count=1 known-sequence=0,1 parse-complete=1"));
    assert(ios_cs2_find(owner, 0x324, 23));
    assert(!ios_cs2_find(owner, 0x324, 24));
    assert(!ios_cs2_find(owner, 0x328, 23));
    assert(!ios_cs2_find((void *)(uintptr_t)0x12346000, 0x324, 23));
    start(owner, 0x324, 23, game_image, "cs2.exe -insecure");
    assert(captured_count == 1); /* A second observed thread cannot replace accepted parameters. */
    map(owner, 0x324, 24, game_image, 0x8664, 0, 1);
    map(owner, 0x328, 23, game_image, 0x8664, 0, 1);
    map((void *)(uintptr_t)0x12346000, 0x324, 23, game_image, 0x8664, 0, 1);
    assert(captured_count == 1); /* No adoption by equal/reused thread IDs. */
    map(owner, 0x324, 23, game_image, 0x8664, 0, 1);
    assert(strstr(captured[1], "path-class=game relative=game/bin/win64/cs2.exe machine=8664 hybrid=0"));
    assert(strstr(captured[1], "path-source=accepted-main-image"));
    map(owner, 0x324, 23, "C:/Windows/system32/d3d11.dll", 0xa641, 1, 0);
    assert(strstr(captured[2], "path-class=system relative=system32/d3d11.dll machine=a641 hybrid=1"));
    assert(strstr(captured[2], "path-source=section-name"));
    snprintf(name, sizeof(name), "C:/Users/PRIVATE_OPAQUE_SENTINEL_76561198000000000/private.dll");
    map(owner, 0x324, 23, name, 0x1234, -1, 0);
    assert(strstr(captured[3], "path-class=private relative=redacted machine=unknown hybrid=unmeasured unknown-count=1"));
    map(owner, 0x324, 23, "C:/Windows/../private.dll", 0x8664, 0, 0);
    assert(strstr(captured[4], "path-class=unknown relative=redacted"));
    private_excluded();

    /* Busy observer locks drop metadata only, without waiting on or altering
     * loader/guest state. The bounded counter is an observed lower bound. */
    before = captured_count;
    pthread_mutex_lock(&ios_cs2_mutex);
    for (i = 0; i < 200; i++) map(owner, 0x324, 23, game_image, 0x8664, 0, 0);
    pthread_mutex_unlock(&ios_cs2_mutex);
    assert(captured_count == before);
    assert(__atomic_load_n(&ios_cs2_processes[0].dropped, __ATOMIC_RELAXED) == 128);
    map(owner, 0x324, 23, game_image, 0x8664, 0, 0);
    assert(strstr(captured[captured_count - 1], "dropped-observed=128"));
    while (ios_cs2_processes[0].maps < 256) map(owner, 0x324, 23, game_image, 0x8664, 0, 0);
    before = captured_count;
    map(owner, 0x324, 23, game_image, 0x8664, 0, 0);
    assert(captured_count == before && ios_cs2_processes[0].maps == 256);

    reset(); start(owner, 0x324, 23, game_image, "cs2.exe -steam");
    for (i = 0; i < 256; i++) map(owner, 0x324, 23, "C:/PRIVATE_OPAQUE_SENTINEL_76561198000000000/module.dll", 0x8664, 0, 0);
    assert(captured_count == 257);
    assert(strstr(captured[256], "unknown-count=256 dropped-observed=0 sequence=256 limit=256"));
    map(owner, 0x324, 23, game_image, 0x8664, 0, 0);
    assert(captured_count == 257); private_excluded();

    reset();
    start(NULL, 0x324, 23, game_image, "cs2.exe -steam");
    start(owner, 0, 23, game_image, "cs2.exe -steam");
    start(owner, 0x324, 0, game_image, "cs2.exe -steam");
    start(owner, 0x324, 23, "C:/Steam/steam.exe", "steam.exe -steam");
    assert(!captured_count);
    for (i = 0; i < 4; i++) start((void *)(uintptr_t)(0x12345000 + i * 0x1000), 0x324 + i, 23 + i, game_image, "cs2.exe -steam");
    assert(captured_count == 4);
    start((void *)(uintptr_t)0x12349000, 0x328, 27, game_image, "cs2.exe -insecure");
    assert(captured_count == 4); /* Bounded diagnostics do not evict or reassign owners. */
}
static void *concurrent_maps(void *unused)
{
    size_t i;
    (void)unused;
    for (i = 0; i < 1000; i++) map((void *)(uintptr_t)0x12345000, 0x324, 23, "C:/Windows/system32/ntdll.dll", 0x8664, 0, 0);
    return NULL;
}
static void concurrency_tests(void)
{
    pthread_t threads[8];
    unsigned seen[257] = {0};
    size_t i;
    reset(); start((void *)(uintptr_t)0x12345000, 0x324, 23, game_image, "cs2.exe -steam");
    for (i = 0; i < sizeof(threads) / sizeof(*threads); i++) assert(!pthread_create(&threads[i], NULL, concurrent_maps, NULL));
    for (i = 0; i < sizeof(threads) / sizeof(*threads); i++) assert(!pthread_join(threads[i], NULL));
    assert(ios_cs2_processes[0].maps == 256 && captured_count == 257);
    assert(__atomic_load_n(&ios_cs2_processes[0].dropped, __ATOMIC_RELAXED) <= 128);
    for (i = 1; i < captured_count; i++)
    {
        unsigned sequence;
        const char *at = strstr(captured[i], " sequence=");
        assert(at && sscanf(at, " sequence=%u", &sequence) == 1 && sequence > 0 && sequence <= 256);
        assert(!seen[sequence]++);
        assert(strstr(captured[i], "path-class=system relative=system32/ntdll.dll"));
    }
    for (i = 1; i <= 256; i++) assert(seen[i] == 1);
    private_excluded();
}
int main(void)
{
    parser_tests(); path_tests(); record_tests(); concurrency_tests();
    puts("PASS actual CS2 observer: CRT flags, bounded unknowns, literal path classes, owner/lease isolation, concurrent map cap and privacy");
    return 0;
}
