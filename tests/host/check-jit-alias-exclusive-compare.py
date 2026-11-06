#!/usr/bin/env python3
"""Replay seven exact shipped DXMT strong-CAS loops through the real handler."""
from pathlib import Path
import hashlib
import os
import runpy
import struct
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
common = runpy.run_path(str(root / "tests/host/check-jit-alias-exclusive-conditional.py"),
                        run_name="compare_fixture_base")
header = common["header"]
# Probe retirement during a selected query in the compare helper. Generation
# tests invoke that helper directly so earlier rejected helpers cannot consume
# this injection before the new helper acquires its initial publication token.
header = header.replace("static unsigned mutate_generation;",
                        "static unsigned mutate_generation; static uintptr_t mutate_at;")
old = "if (mutate_generation && *address == (uintptr_t)rx + 0x100) change_generation();"
assert header.count(old) == 1
header = header.replace(old, "if (mutate_generation && (!mutate_at || *address == mutate_at)) change_generation();")
image = (root / "app/Madeira/arm64ec-windows/d3d11.dll").read_bytes()
pin = "08e2eccae5a758ed6c15a3e8ca34de0d56266565aa69f1d0e87d07449d318671"
assert hashlib.sha256(image).hexdigest() == pin, "review new packaged image before updating exact witnesses"
pe = struct.unpack_from("<I", image, 0x3c)[0]
count = struct.unpack_from("<H", image, pe + 6)[0]
table = pe + 24 + struct.unpack_from("<H", image, pe + 20)[0]
def read(rva, size):
    for n in range(count):
        virtual, start, raw, offset = struct.unpack_from("<IIII", image, table + n * 40 + 8)
        if start <= rva and rva - start + size <= raw:
            at = offset + rva - start
            assert at + size <= len(image)
            return image[at:at + size]
    raise AssertionError((hex(rva), size))
def sext(n, bits):
    return n - (1 << bits) if n & (1 << (bits - 1)) else n
sites = [0x678cc, 0xff3bc, 0x100f1c, 0x101220, 0x102e6c, 0x1197a8, 0x11ba04]
records = []
for pc in sites:
    start = pc - 20
    core = struct.unpack("<7I", read(start, 28))
    mismatch = pc - 8 + sext((core[3] >> 5) & 0x7ffff, 19) * 4
    cleanup = struct.unpack("<2I", read(mismatch, 8))
    continuation = mismatch + 4 + sext(cleanup[1] & 0x3ffffff, 26) * 4
    assert cleanup[0] == 0xd5033f5f and pc + 8 <= continuation < mismatch
    assert core[6] == 0x35ffff60 | ((core[5] >> 16) & 31)
    roles = [(core[0] >> 5) & 31, core[0] & 31, core[1] & 31,
             (core[2] >> 16) & 31, core[5] & 31, (core[5] >> 16) & 31]
    records.append("{%s,%s,{%s},{%s},%s,{%s}}" %
        (hex(mismatch - start), hex(continuation - start), ",".join(hex(x) for x in core),
         ",".join(hex(x) for x in cleanup), hex(struct.unpack("<I", read(continuation, 4))[0]),
         ",".join(str(x) for x in roles)))
witness = """
struct compare_witness {size_t mismatch,continuation;uint32_t core[7],cleanup[2],next;unsigned roles[6];};
static const struct compare_witness witnesses[]={
""" + ",\n".join(records) + "\n};\n"
with tempfile.TemporaryDirectory(prefix="madeira-exclusive-compare-") as folder:
    directory = Path(folder)
    (directory / "compare-production.h").write_text(header + witness)
    binary = directory / "compare"
    subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-pthread",
                    "-I" + str(directory), str(root / "tests/host/jit_alias_exclusive_compare_test.c"),
                    "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("PASS exact shipped PE proof: SHA256=" + pin + ";7 strong-CAS cores, native mismatch cleanup and continuation read directly from image")
