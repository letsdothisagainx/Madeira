#!/usr/bin/env python3
"""Exercise production WASAPI queue snapshots and submissions without Apple SDKs.

Interleave a padding read with a producer submission and a real mixer pass. A
write-first snapshot used to underflow and report a full ring, blocking the next
submission. Also check wrapped and silent submissions reach the stereo bus and
that publishing audio does not call source-analysis timers or logging.
"""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
src = (root / "build/ntdll-unix/audio_null_ios.c").read_text()


def cut(start, end):
    a = src.index(start)
    return src[a:src.index(end, a)]


stream = cut("struct ios_stream {", "/* ml739: one stream object per client")
params = cut("struct get_render_buffer_params {", "struct get_capture_buffer_params {")
params += cut("struct get_current_padding_params {", "struct get_next_packet_size_params {")
mix = cut("static void ios_mix_stream(", "/* Core Audio real-time thread. See ios_mix_stream")
get_buffer = cut("static UINT32 ios_stream_padding(", "static NTSTATUS ios_release_render_buffer(")
release = cut("static NTSTATUS ios_release_render_buffer(", "static NTSTATUS ios_get_capture_buffer(")
get_padding = cut("static NTSTATUS ios_get_current_padding(", "static NTSTATUS ios_get_next_packet_size(")

harness = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>
typedef unsigned char BYTE;
typedef uint32_t UINT32, UInt32, UINT;
typedef uint64_t stream_handle;
typedef int HRESULT, NTSTATUS;
typedef void *HANDLE;
#define STATUS_SUCCESS 0
#define S_OK 0
#define E_FAIL ((HRESULT)0x80004005)
#define AUDCLNT_E_NOT_INITIALIZED ((HRESULT)0x88890001)
#define LOG_FN_CALL(idx, name) ((void)0)
""" + stream + params + r"""
static struct ios_stream s;
static struct ios_stream *stream_from_handle(stream_handle h) { return (void *)(uintptr_t)h; }
static int ios_stream_is_live(const struct ios_stream *s) { return s->mixable; }
static BYTE *ios_audio_alloc_scratch(UINT32 n, UINT32 f, int *g) { abort(); }
static void ios_audio_free_scratch(BYTE *p, int g) { abort(); }
""" + mix + r"""
static int interleave, loads, source_timer_calls, source_log_calls;
static uint64_t queue_load(const _Atomic uint64_t *p, memory_order order)
{
    uint64_t result = atomic_load_explicit(p, order);
    if (interleave && (p == &s.play_pos || p == &s.write_pos) && loads++ == 0) {
        /* Another producer submitted 100 frames after the first snapshot
         * load; the real callback consumed them before the second load. */
        float out[200] = {0};
        atomic_store_explicit(&s.write_pos, 200, memory_order_release);
        ios_mix_stream(&s, out, 100, 2, 44100);
    }
    return result;
}
#undef atomic_load_explicit
#undef atomic_load
#define atomic_load_explicit(p, order) queue_load(p, order)
#define atomic_load(p) queue_load(p, memory_order_seq_cst)
""" + get_buffer + get_padding + r"""
#undef atomic_load_explicit
#define atomic_load_explicit(p, order) __atomic_load_n((p), (order))
static time_t submission_time(time_t *t) { source_timer_calls++; return 20; }
static int submission_log(FILE *f, const char *format, ...) { source_log_calls++; return 0; }
#define time submission_time
#define fprintf submission_log
""" + release + r"""
#undef time
#undef fprintf
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d: %s\n", __LINE__, #x); return 1; } } while (0)
static void init(void)
{
    static float ring[2000], scratch[2000];
    memset(&s, 0, sizeof(s));
    memset(ring, 0, sizeof(ring)); memset(scratch, 0, sizeof(scratch));
    s.valid = s.started = s.mixable = s.is_float = 1;
    s.sample_bits = 32; s.sample_rate = 44100; s.channels = 2; s.frame_bytes = 8;
    s.buffer_frames = s.scratch_frames = 1000;
    s.ring = (BYTE *)ring; s.render_scratch = (BYTE *)scratch;
    s.mix_gain[0][0] = s.mix_gain[1][1] = 1;
    interleave = loads = 0;
}
int main(void)
{
    stream_handle h = (uintptr_t)&s;
    UINT32 pad = 9999;
    BYTE *data = NULL;
    struct get_current_padding_params gp = { .stream = h, .padding = &pad };
    struct get_render_buffer_params gb = { .stream = h, .frames = 100, .data = &data };
    struct release_render_buffer_params rb = { .stream = h, .written_frames = 100 };
    init();
    atomic_store(&s.write_pos, 100); atomic_store(&s.play_pos, 100);
    interleave = 1;
    ios_get_current_padding(&gp);
    CHECK(gp.result == S_OK && loads == 2 && pad == 100);
    CHECK(atomic_load_explicit(&s.play_pos, memory_order_acquire) == 200);

    init();
    atomic_store(&s.write_pos, 100); atomic_store(&s.play_pos, 100);
    interleave = 1;
    ios_get_render_buffer(&gb);
    CHECK(gb.result == S_OK && data == s.render_scratch && s.pending_frames == 100);
    CHECK(loads == 2);

    /* Stable empty/full snapshots, and stopped reset's transient play>write. */
    interleave = 0;
    atomic_store(&s.play_pos, 200); atomic_store(&s.write_pos, 200);
    ios_get_current_padding(&gp); CHECK(pad == 0);
    atomic_store(&s.write_pos, 1200);
    ios_get_current_padding(&gp); CHECK(pad == 1000);
    ios_get_render_buffer(&gb); CHECK(gb.result == (HRESULT)0x88890006 && !data);
    atomic_store(&s.write_pos, 0);
    ios_get_current_padding(&gp); CHECK(pad == 0);

    /* The real producer copies around the ring end, then release-publishes;
     * the real consumer must hear every frame in order. */
    init();
    atomic_store(&s.write_pos, 950); atomic_store(&s.play_pos, 950);
    ios_get_render_buffer(&gb); CHECK(gb.result == S_OK && data);
    for (int i = 0; i < 100; i++) {
        ((float *)data)[i * 2] = (float)i / 200;
        ((float *)data)[i * 2 + 1] = -(float)i / 200;
    }
    ios_release_render_buffer(&rb);
    CHECK(rb.result == S_OK && !s.pending_frames);
    CHECK(atomic_load_explicit(&s.write_pos, memory_order_acquire) == 1050);
    ios_get_current_padding(&gp); CHECK(pad == 100);
    float out[200] = {0};
    ios_mix_stream(&s, out, 100, 2, 44100);
    for (int i = 0; i < 100; i++) {
        CHECK(out[i * 2] == (float)i / 200);
        CHECK(out[i * 2 + 1] == -(float)i / 200);
    }
    ios_get_current_padding(&gp); CHECK(pad == 0);

    ios_get_render_buffer(&gb); CHECK(gb.result == S_OK && data);
    memset(data, 0x7f, 100 * 8);
    rb.flags = 2; ios_release_render_buffer(&rb);
    memset(out, 0, sizeof(out)); ios_mix_stream(&s, out, 100, 2, 44100);
    for (int i = 0; i < 200; i++) CHECK(out[i] == 0);
    CHECK(source_timer_calls == 0 && source_log_calls == 0);
    puts("ok");
    return 0;
}
"""

with tempfile.TemporaryDirectory() as tmp:
    c = Path(tmp) / "queue.c"
    c.write_text(harness)
    exe = Path(tmp) / "queue"
    subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra",
                    "-Wno-unused-function", "-Wno-unused-parameter", "-Werror",
                    "-fsanitize=address,undefined", str(c), "-o", str(exe)], check=True)
    out = subprocess.run([str(exe)], capture_output=True, text=True)
    assert out.returncode == 0 and out.stdout.strip() == "ok", (out.returncode, out.stdout, out.stderr)
    # Restore the original write-first/unsigned-subtraction semantics. The
    # real callback interleaving must reproduce the invalid padding result.
    before = """    uint64_t play = atomic_load_explicit(&s->play_pos, memory_order_acquire);
    uint64_t wr = atomic_load_explicit(&s->write_pos, memory_order_acquire);
    uint64_t pad = wr > play ? wr - play : 0;"""
    after = """    uint64_t wr = atomic_load_explicit(&s->write_pos, memory_order_acquire);
    uint64_t play = atomic_load_explicit(&s->play_pos, memory_order_acquire);
    uint64_t pad = wr - play;"""
    assert harness.count(before) == 1
    c.write_text(harness.replace(before, after, 1))
    subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra",
                    "-Wno-unused-function", "-Wno-unused-parameter", "-Werror",
                    str(c), "-o", str(exe)], check=True)
    old = subprocess.run([str(exe)], capture_output=True, text=True)
    assert old.returncode != 0 and "pad == 100" in old.stdout + old.stderr, (old.returncode, old.stdout, old.stderr)
print("PASS: concurrent queue snapshots cannot underflow; wrapped/silent submissions publish and render without source-analysis timers or logging")
print("PASS: old write-first padding mutation reproduces the callback race")
