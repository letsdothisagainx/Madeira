#!/usr/bin/env python3
"""Execute the staged production wait with a deterministic clock/park backend.

Production keeps the d73 wait implementation; the corrected overlay is dormant.
The real fast-wait body, adaptive budget, token/generation operations and public
wait dispatchers are compiled with hosted OS time/lookup/park/server backends.
The actual b832 function must fail the inactive fallback contract; historical
d73 and the dormant corrected helper must pass it.
"""
from pathlib import Path
import hashlib
import importlib.util
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("fastsync_timeout", ROOT / "tools/build/stage-fastsync-timeout.py")
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


def function(source, signature):
    assert source.count(signature) == 1, signature
    start = source.index(signature)
    return source[start:source.index("\n}\n", start) + 3]


def production_header(source):
    names = ("MADEIRA_FAST_SPIN", "MADEIRA_SPIN_CREDIT_MAX", "MADEIRA_SPIN_CREDIT_UP",
             "MADEIRA_SPIN_PROBE_EVERY", "MADEIRA_SPIN_PROBE_SHIFT", "MADEIRA_SPIN_CREDIT_REARM")
    result = "\n".join(re.search(r"^#define " + name + r"[ \t]+.*$", source, re.M)[0] for name in names) + "\n"
    for signature in ("static inline unsigned long long madeira_fast_spin_budget_ns(",
                      "static inline void madeira_fast_spin_credit_add(",
                      "static inline int madeira_cell_alive(",
                      "static inline int madeira_fast_try("):
        result += function(source, signature).replace("madeira_fast_try(", "production_fast_try(", 1) + "\n"
    # The instruction barrier is the only architecture-specific instruction in
    # the extracted body. Its hosted equivalent advances our deterministic clock.
    body = function(source, stage.SIGNATURE)
    assert body.count('__asm__ __volatile__( "isb" ::: "memory" );') == 2
    result += body.replace('__asm__ __volatile__( "isb" ::: "memory" );', 'host_isb();')
    for name in ("NtWaitForSingleObject", "NtWaitForMultipleObjects"):
        result += function(source, "NTSTATUS WINAPI " + name + "(") + "\n"
    return result


if __name__ == "__main__":
    build = (ROOT / "build/ntdll-unix/build.sh").read_text()
    assert 'python3 "$REPO_ROOT/tools/build/stage-fastsync-timeout.py"' not in build, "production timeout overlay must remain disabled for startup recovery"
    original = (ROOT / "wine/dlls/ntdll/unix/sync.c").read_text()
    # Recorded from d73f2583 (the unchanged df1c5ea5 Wine pin). These hashes
    # include the original server fallback and both complete public dispatchers.
    historical = {
        stage.SIGNATURE: "b7681cc32b79d39ff1a8b7d9f29dae4b51eaa1cb1de46bb2c03dee25e513b8d2",
        "NTSTATUS WINAPI NtWaitForSingleObject(": "1fc225af27877143026722c96da143d1cea4eba37f36e5dfb171fafbc78b06f6",
        "NTSTATUS WINAPI NtWaitForMultipleObjects(": "f8afe5e3632b7176719dca94389bae700f7cde88071a85c6d0c729e68f48138b",
    }
    for signature, digest in historical.items():
        assert hashlib.sha256(function(original, signature).encode()).hexdigest() == digest, "production d73 wait/fallback bytes changed"
    server = (ROOT / "build/ntdll-unix/server_ios.c").read_text()
    signature = "unsigned int server_wait( const union select_op *select_op, data_size_t size, UINT flags,"
    assert hashlib.sha256(function(server, signature).encode()).hexdigest() == "1db01c3e60c1524b272047e73872b89b849fd8b7441b1b59862f7bfc2bfea927", "production d73 server-wait/APC fallback changed"
    staged = stage.stage(original)
    for invalid in (staged, original.replace(stage.SIGNATURE, "missing_function(", 1),
                    original + "\n" + stage.SIGNATURE,
                    original.replace("    t0 = madeira_now_ns();\n    for (rounds", "    changed_clock();\n    for (rounds", 1)):
        try:
            stage.stage(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("missing, ambiguous or already staged timeout source accepted")
    # Existing iOS overlays compose on this same generated translation unit.
    for name in ("native-thread-exit", "htmlipc-section-trace"):
        overlay_spec = importlib.util.spec_from_file_location(name, ROOT / ("tools/build/stage-" + name + ".py"))
        overlay = importlib.util.module_from_spec(overlay_spec)
        overlay_spec.loader.exec_module(overlay)
        original = overlay.stage(original, ROOT / 'build/ntdll-unix/htmlipc_section_trace.h') if name == "htmlipc-section-trace" else overlay.stage(original)
    for signature, digest in historical.items():
        assert hashlib.sha256(function(original, signature).encode()).hexdigest() == digest, "production overlays changed d73 wait/fallback bytes"
    assert function(stage.stage(original), stage.SIGNATURE) == function(staged, stage.SIGNATURE)
    # Public dispatchers are byte-identical: no new local timeout/error/APC result.
    pinned = (ROOT / "wine/dlls/ntdll/unix/sync.c").read_text()
    # Everything before a cell actually starts spinning is the pinned source,
    # apart from extra automatic variable declarations. No new clock or store.
    old_body = function(pinned, stage.SIGNATURE)
    new_body = function(staged, stage.SIGNATURE)
    old_prefix = old_body[:old_body.index("    for (i = 0; i < MADEIRA_FAST_SPIN; i++)")]
    new_prefix = new_body[:new_body.index("    " + stage.MARKER)].replace(
        "    unsigned long long t0, spent = 0, budget_ns, wait_t0 = 0, timeout_ticks = 0;",
        "    unsigned long long t0, spent = 0, budget_ns;")
    assert new_prefix == old_prefix, "inactive/ready/zero fast-wait paths changed"
    for name in ("NtWaitForSingleObject", "NtWaitForMultipleObjects"):
        assert function(staged, "NTSTATUS WINAPI " + name + "(") == function(pinned, "NTSTATUS WINAPI " + name + "(")

    with tempfile.TemporaryDirectory(prefix="madeira-fastsync-timeout-") as directory:
        tmp = Path(directory)
        binary = tmp / "fastsync-timeout"
        compile_args = [os.environ.get("CC", "cc"), "-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
                        "-Wno-unused-function", "-Wno-unused-parameter", "-Wno-sign-compare",
                        "-fno-strict-aliasing", "-fsanitize=address,undefined",
                        "-fno-sanitize-recover=all", "-I", str(tmp), "-I", str(ROOT / "wine/include"),
                        str(ROOT / "tests/host/fastsync-timeout-test.c"), "-o", str(binary)]
        (tmp / "production-fastsync-timeout.h").write_text(production_header(pinned))
        subprocess.run(compile_args, check=True)
        subprocess.run([str(binary), "fallback-contract"], check=True, timeout=15)
        before = subprocess.run([str(binary), "original"], capture_output=True, text=True, timeout=15)
        assert before.returncode == 1 and "REGRESSION: initial spin exceeded relative deadline" in before.stdout, before.stdout + before.stderr
        print("PASS original production function reproduces relative timeout extension", flush=True)
        # This is the actual function emitted by the b832 owned stager, rather
        # than a modeled mutation. Keep its capture fixed and fail on its exact
        # inactive timeout-pointer/clock regression before accepting the repair.
        capture = (ROOT / "tests/host/fixtures/fastsync-timeout-b832.c").read_text()
        b832_body = function(capture, stage.SIGNATURE)
        assert hashlib.sha256(b832_body.encode()).hexdigest() == "bd16c566136a9184225b2f2915331e389d31fa5c040c96911eee9ff1567229d7"
        b832_source = staged.replace(new_body, b832_body, 1)
        (tmp / "production-fastsync-timeout.h").write_text(production_header(b832_source))
        subprocess.run(compile_args, check=True)
        b832 = subprocess.run([str(binary), "fallback-contract"], capture_output=True, text=True, timeout=15)
        assert b832.returncode == 1 and "REGRESSION: inactive fallback retains original pointer/value with zero clock calls" in b832.stdout, b832.stdout + b832.stderr
        print("PASS actual b832 production function fails inactive fallback contract", flush=True)
        (tmp / "production-fastsync-timeout.h").write_text(production_header(staged))
        subprocess.run(compile_args, check=True)
        subprocess.run([str(binary)], check=True, timeout=15)
        print("PASS owned fastsync timeout overlay composes and rejects stale source")
