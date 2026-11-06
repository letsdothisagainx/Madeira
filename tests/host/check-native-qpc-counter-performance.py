#!/usr/bin/env python3
"""Measure actual staged Wine QPC source with real Apple ARM64 Mach faults.

The source-built QPC function, counter layout, getter and initializer come from
the production overlay. Only PE symbol addresses and the ordinary clock/thread
APIs are adapted to this macOS process. This is not execution of the packaged
Windows COFF image and is not an on-device Steam acceptance test.
"""
from pathlib import Path
import argparse
import importlib.util
import os
import platform
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def generate(work: Path) -> None:
    spec = importlib.util.spec_from_file_location("counter_stager", ROOT / "tools/build/stage-native-counter-writes.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    staged = module.stage({name: (ROOT / "wine" / name).read_text() for name in module.FILES})
    header = staged["dlls/ntdll/ntdll_misc.h"]
    first = header.index("struct ios_xp_nt_qpc {")
    last = header.index("extern struct ios_xp_nt ios_xp_nt;", first)
    types = header[first:last]
    first = header.index("struct ios_xp_nt_write_contract\n")
    last = header.index("extern struct ios_xp_nt_write_contract", first)
    types += header[first:last]
    (work / "production-qpc-types.h").write_text(types)

    def function(source: str, name: str) -> str:
        match = re.search(r"(?m)^(?:static inline )?(?:void|ULONGLONG|struct ios_xp_nt \*) ?" + re.escape(name) + r"\(.*", source)
        assert match, name
        return source[match.start():source.index("\n}", match.start()) + 2] + "\n"

    getter = function(header, "ios_xp_nt_writer")
    # Fixture relocation of two exported symbol addresses only. The actual
    # acquire load, NULL fallback and every caller remain unchanged.
    assert getter.count("&ios_xp_nt_write_contract.writer") == 1
    assert getter.count("&ios_xp_nt;") == 1
    getter = getter.replace("&ios_xp_nt_write_contract.writer", "&fixture_contract_rx->writer")
    getter = getter.replace("&ios_xp_nt;", "fixture_counter_rx;")
    init = function(staged["dlls/ntdll/sync.c"], "ios_xp_nt_init")
    time_source = staged["dlls/ntdll/time.c"]
    first = time_source.index("static ULONGLONG qpc_freq, qpc_last_sync;")
    last = time_source.index("\n#else\nBOOL WINAPI DECLSPEC_HOTPATCH RtlQueryPerformanceCounter", first)
    qpc = time_source[first:last]
    assert "q = &ios_xp_nt_writer()->qpc[" in qpc
    assert "q->hist[d < t1 ? 0 :" in qpc and "q->calls++;" in qpc
    (work / "production-qpc-body.h").write_text(getter + init + qpc + "\n")

    source = (ROOT / "build/ntdll-unix/signal_arm64_ios.c").read_text()

    def helper(name: str) -> str:
        match = re.search(r"(?m)^static int " + name + r"\(", source)
        assert match, name
        return source[match.start():source.index("\n}", match.start()) + 2] + "\n"

    def branch(start: str, end: str) -> str:
        first = source.index(start)
        return source[first:source.index(end, first)].replace("else if", "if", 1)

    branches = branch("                    else if ((insn & 0xffc00000) == 0xf9000000)",
                      "                    /* STLR (Store-Release Register, 64-bit):")
    immediate = branch("                    else if ((insn & 0x3fe00000u) == 0x38000000u && ((insn >> 10) & 3) != 2)",
                       "                    /* SIMD/FP STR (immediate, post/pre-index, D-reg")
    emulation = helper("ios_alias_write") + helper("ios_alias_store_pair") + helper("ios_alias_store_immediate")
    emulation += r'''
static int emulate_qpc_store(uint32_t insn, uintptr_t fault_pc, uintptr_t fault_addr, arm_thread_state64_t *input)
{
    arm_thread_state64_t state = *input;
    uintptr_t alias_fault = 0;
    int emulated = 0, honor_guest_prot = 1;
#define IOS_STORE_SRC(r) ((r) == 31 ? 0ULL : state.__x[r])
''' + branches + immediate.replace("if (", "else if (", 1) + r'''
#undef IOS_STORE_SRC
    *input = state;
    return emulated;
}
'''
    (work / "production-qpc-emulation.h").write_text(emulation)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-arm64-darwin", action="store_true")
    parser.add_argument("--check-source", action="store_true", help="validate extraction only; no hardware claim")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="madeira-native-qpc-") as folder:
        work = Path(folder)
        generate(work)
        if args.check_source:
            print("PASS staged QPC/layout/getter/initializer and production GPR/pair extraction (source only)")
            return
        if platform.system() != "Darwin" or platform.machine().lower() not in ("arm64", "aarch64"):
            if args.require_arm64_darwin:
                raise SystemExit("FAIL: QPC counter benchmark requires actual Apple ARM64 Mach exceptions")
            print("SKIP QPC counter hardware throughput: actual Apple ARM64/Mach execution required")
            return
        binary = work / "native-qpc-counter-throughput"
        subprocess.run([os.environ.get("CC", "clang"), "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-pthread",
                        "-I", str(work), "-I", str(ROOT / "build/ntdll-unix"),
                        str(ROOT / "tests/host/native-qpc-counter-performance.c"), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=60)


if __name__ == "__main__":
    main()
