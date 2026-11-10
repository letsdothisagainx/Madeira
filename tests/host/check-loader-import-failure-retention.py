#!/usr/bin/env python3
"""Execute Wine's production import-failure and retry control flow.

The four loader functions are extracted unchanged from loader.c and compiled
against Wine's real headers. The fixture supplies PE bytes, import results,
mapping calls, module allocation and address-index registration; real loader
list removal and same-file lookup are exercised. A second fixture executes
virtual_ios.c's actual reload, ledger and owner-reclamation functions with
Mach, bitmap and external lifecycle boundaries stubbed. This is a host
ownership regression, not an iOS or emulator execution test.
"""

from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests/host/fixtures"
SPLIT = "/* INSERT_UNMODIFIED_PRODUCTION_CODE */"


def extract_entity(source, marker):
    """Return a complete C definition, excluding declarations and comments."""
    starts = [match.start() for match in re.finditer(re.escape(marker), source)]
    for start in starts:
        brace = source.find("{", start)
        if brace == -1 or ";" in source[start:brace]:
            continue
        depth, state, index = 0, "code", brace
        while index < len(source):
            char, pair = source[index], source[index:index + 2]
            if state == "code":
                if pair in ("/*", "//"):
                    state = "comment" if pair == "/*" else "line"
                    index += 2
                    continue
                if char == '"':
                    state = "string"
                elif char == "'":
                    state = "char"
                elif char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        end = index + 1
                        if source[end:end + 1] == ";":
                            end += 1
                        return source[start:end]
            elif state == "comment":
                if pair == "*/":
                    state = "code"
                    index += 2
                    continue
            elif state == "line":
                if char == "\n":
                    state = "code"
            else:
                if char == "\\":
                    index += 2
                    continue
                if (state == "string" and char == '"') or (state == "char" and char == "'"):
                    state = "code"
            index += 1
    raise AssertionError(f"C definition not found: {marker}")


def compile_and_run(directory, name, fixture, insertions, *, extra_flags=(), arguments=((),)):
    template = fixture.read_text()
    for marker, code in insertions.items():
        assert template.count(marker) == 1, (fixture, marker)
        template = template.replace(marker, code)
    source = directory / (name + ".c")
    binary = directory / name
    source.write_text(template)
    subprocess.run([
        *shlex.split(os.environ.get("CC", "cc")),
        "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-sign-compare",
        "-g", "-O1", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
        "-fno-omit-frame-pointer", "-I" + str(ROOT / "wine/include"),
        *extra_flags, str(source), "-o", str(binary),
    ], check=True)
    for args in arguments:
        subprocess.run([str(binary), *args], check=True)


def main():
    loader = (ROOT / "wine/dlls/ntdll/loader.c").read_text()
    functions = [extract_entity(loader, marker) for marker in (
        "static WINE_MODREF *find_existing_module( ",
        "static NTSTATUS fixup_imports( ",
        "static NTSTATUS build_module( ",
        "static NTSTATUS load_native_dll( ",
    )]
    virtual = (ROOT / "build/ntdll-unix/virtual_ios.c").read_text()
    pool_functions = [extract_entity(virtual, marker) for marker in (
        "static int ios_pool_image_range_fits( ",
        "static int ios_pool_free_put( ",
        "static int ios_pool_best_fit( ",
        "static int ios_image_reload_mode(void)",
        "static void ios_jit_note_image_unmapped( ",
        "static int ios_jit_reload_choice( ",
        "static int ios_pool_ledger_holds( ",
        "void ios_jit_reclaim_process( ",
    )]
    with tempfile.TemporaryDirectory(prefix="madeira-loader-retention-") as folder:
        directory = Path(folder)
        compile_and_run(directory, "wine-loader", FIXTURES / "loader-import-failure-wine.c",
                        {SPLIT: "\n\n".join(functions)})
        compile_and_run(directory, "pool-retention", FIXTURES / "loader-import-failure-pool.c", {
            "/* PRODUCTION_MAPPING_STRUCT */": extract_entity(virtual, "struct ios_jit_mapping {"),
            "/* PRODUCTION_FUNCTIONS */": "\n\n".join(pool_functions),
        }, extra_flags=("-pthread",), arguments=(("0",), ("1",)))


if __name__ == "__main__":
    main()
