#!/usr/bin/env python3
"""Execute the staged production wait with a deterministic clock/park backend.

The real fast-wait body, adaptive budget, token/generation operations and
public single/multiple wait dispatchers are extracted from Wine. Only OS time,
handle lookup, parking and server completion are hosted. The unchanged original
must demonstrate the regression before the staged source can pass.
"""
from pathlib import Path
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
    original = (ROOT / "wine/dlls/ntdll/unix/sync.c").read_text()
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
    assert function(stage.stage(original), stage.SIGNATURE) == function(staged, stage.SIGNATURE)
    # Public dispatchers are byte-identical: no new local timeout/error/APC result.
    pinned = (ROOT / "wine/dlls/ntdll/unix/sync.c").read_text()
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
        before = subprocess.run([str(binary), "original"], capture_output=True, text=True, timeout=15)
        assert before.returncode == 1 and "REGRESSION: initial spin exceeded relative deadline" in before.stdout, before.stdout + before.stderr
        print("PASS original production function reproduces relative timeout extension", flush=True)
        (tmp / "production-fastsync-timeout.h").write_text(production_header(staged))
        subprocess.run(compile_args, check=True)
        subprocess.run([str(binary)], check=True, timeout=15)
        print("PASS owned fastsync timeout overlay composes and rejects stale source")
