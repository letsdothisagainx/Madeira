#!/usr/bin/env python3
"""Stage the private, source-built ntdll diagnostic-counter writer contract.

Counter/history accesses use their private writer, and shared SRW release omits
an exclusive wake when no exclusive contender exists. Counter layout/exports,
QPC arithmetic and synchronization results are retained. Ordinary live LFH
size queries avoid an unrelated shared-heap lock; validation and other heap
paths retain their original locking. Restore refuses
unrelated edits; the pinned Wine worktree is never committed with this overlay.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[2]
FILES = ("dlls/ntdll/time.c", "dlls/ntdll/sync.c", "dlls/ntdll/ntdll_misc.h", "dlls/ntdll/ntdll.spec", "dlls/ntdll/heap.c")
ABI_NAME = "dlls/ntdll/madeira_native_counter_alias_abi.h"
ABI_SOURCE = ROOT / "build/ntdll-unix/native_counter_alias_abi.h"
MARKER = "/* Madeira native counter writer: unpublished-copy binding only. */"

_srw_spec = importlib.util.spec_from_file_location("native_srw_wake", ROOT / "tools/build/stage-native-srw-wake.py")
_srw_wake = importlib.util.module_from_spec(_srw_spec)
_srw_spec.loader.exec_module(_srw_wake)

_lfh_spec = importlib.util.spec_from_file_location("native_lfh_size", ROOT / "tools/build/stage-native-lfh-size.py")
_lfh_size = importlib.util.module_from_spec(_lfh_spec)
_lfh_spec.loader.exec_module(_lfh_size)


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise ValueError(f"{label}: expected one source anchor")
    return text.replace(old, new, 1)


def stage(sources: dict[str, str]) -> dict[str, str]:
    if set(sources) != set(FILES):
        raise ValueError("native overlay requires its exact source files")
    if any(MARKER in value for value in sources.values()):
        raise ValueError("counter overlay is already staged")
    out = dict(sources)
    header = '''
/* Madeira native counter writer: unpublished-copy binding only. */
#include "madeira_native_counter_alias_abi.h"
struct ios_xp_nt_write_contract
{
    ULONGLONG magic;
    ULONG size, reserved;
    void *writer;
};
extern struct ios_xp_nt_write_contract ios_xp_nt_write_contract;
#ifdef _WIN64
C_ASSERT( sizeof(struct ios_xp_nt) == MADEIRA_NATIVE_COUNTER_BYTES );
C_ASSERT( sizeof(struct ios_xp_nt_write_contract) == MADEIRA_NATIVE_COUNTER_CONTRACT_BYTES );
C_ASSERT( FIELD_OFFSET(struct ios_xp_nt_write_contract, writer) == MADEIRA_NATIVE_COUNTER_WRITER_OFFSET );
#endif
static inline struct ios_xp_nt *ios_xp_nt_writer(void)
{
    struct ios_xp_nt *writer = __atomic_load_n( &ios_xp_nt_write_contract.writer, __ATOMIC_ACQUIRE );
    return writer ? writer : &ios_xp_nt;
}
'''
    out[FILES[2]] = replace_once(out[FILES[2]], "extern struct ios_xp_nt ios_xp_nt;\n", "extern struct ios_xp_nt ios_xp_nt;\n" + header, FILES[2])
    out[FILES[1]] = replace_once(out[FILES[1]], "struct ios_xp_nt ios_xp_nt;   /* layout: ntdll_misc.h */", '''struct ios_xp_nt ios_xp_nt;   /* layout: ntdll_misc.h */
/* Madeira native counter writer: unpublished-copy binding only. */
struct ios_xp_nt_write_contract ios_xp_nt_write_contract =
{
    MADEIRA_NATIVE_COUNTER_ABI_V1, sizeof(ios_xp_nt), 0, NULL
};''', FILES[1])
    for path in FILES[:2]:
        if not re.search(r"\bios_xp_nt\.", out[path]):
            raise ValueError(f"{path}: diagnostic counter accesses missing")
        out[path] = re.sub(r"\bios_xp_nt\.", "ios_xp_nt_writer()->", out[path])
    out[FILES[3]] = replace_once(out[FILES[3]], "@ extern -private ios_xp_nt\n", "@ extern -private ios_xp_nt\n@ extern -private ios_xp_nt_write_contract\n", FILES[3])
    # The captured hot PCs are the diagnostic SRW ring, not the lock itself:
    # an index increment and two history stores for every acquire/release.
    # Keep all events and the existing LONG/entry layout. Only the private
    # writer addresses change; Windows SRW operations remain byte-for-byte.
    out[FILES[1]] = replace_once(out[FILES[1]],
        "static struct ios_srw_ring_ent ios_srw_ring[512];\nstatic LONG ios_srw_ring_idx;",
        '''struct ios_srw_ring_ent ios_srw_ring[512];
LONG ios_srw_ring_idx;
struct ios_srw_history_write_contract
{
    ULONGLONG magic;
    ULONG ring_bytes, entry_bytes;
    void *ring_writer, *index_writer;
};
struct ios_srw_history_write_contract ios_srw_history_write_contract =
{
    MADEIRA_NATIVE_SRW_ABI_V1, sizeof(ios_srw_ring), sizeof(ios_srw_ring[0]), NULL, NULL
};
#ifdef _WIN64
C_ASSERT( sizeof(ios_srw_ring) == MADEIRA_NATIVE_SRW_RING_BYTES );
C_ASSERT( sizeof(ios_srw_ring[0]) == MADEIRA_NATIVE_SRW_ENTRY_BYTES );
C_ASSERT( sizeof(struct ios_srw_history_write_contract) == MADEIRA_NATIVE_SRW_CONTRACT_BYTES );
C_ASSERT( FIELD_OFFSET(struct ios_srw_history_write_contract, ring_writer) == MADEIRA_NATIVE_SRW_RING_WRITER_OFFSET );
C_ASSERT( FIELD_OFFSET(struct ios_srw_history_write_contract, index_writer) == MADEIRA_NATIVE_SRW_INDEX_WRITER_OFFSET );
#endif
static inline struct ios_srw_ring_ent *ios_srw_ring_writer(void)
{
    void *writer = __atomic_load_n( &ios_srw_history_write_contract.ring_writer, __ATOMIC_ACQUIRE );
    return writer ? writer : ios_srw_ring;
}
static inline LONG *ios_srw_index_writer(void)
{
    void *writer = __atomic_load_n( &ios_srw_history_write_contract.index_writer, __ATOMIC_ACQUIRE );
    return writer ? writer : &ios_srw_ring_idx;
}''', FILES[1])
    out[FILES[1]] = replace_once(out[FILES[1]],
        "i = (ULONG)InterlockedIncrement( &ios_srw_ring_idx );",
        "i = (ULONG)InterlockedIncrement( ios_srw_index_writer() );", FILES[1])
    if out[FILES[1]].count("ios_srw_ring[i & 511]") != 2:
        raise ValueError("SRW history must retain exactly two event stores")
    out[FILES[1]] = out[FILES[1]].replace("ios_srw_ring[i & 511]", "ios_srw_ring_writer()[i & 511]")
    out[FILES[1]] = replace_once(out[FILES[1]],
        "ULONG i = (ULONG)ios_srw_ring_idx;",
        "ULONG i = (ULONG)*ios_srw_index_writer();", FILES[1])
    out[FILES[1]] = replace_once(out[FILES[1]],
        "&ios_srw_ring[(i - n) & 511]", "&ios_srw_ring_writer()[(i - n) & 511]", FILES[1])
    out[FILES[3]] += "\n@ extern -private ios_srw_ring\n@ extern -private ios_srw_ring_idx\n@ extern -private ios_srw_history_write_contract\n"
    out[FILES[1]] = _srw_wake.stage(out[FILES[1]])
    out["dlls/ntdll/heap.c"] = _lfh_size.stage(out["dlls/ntdll/heap.c"])
    return out


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def apply(wine: Path, backup: Path) -> None:
    if backup.exists() and any(backup.iterdir()):
        raise ValueError("counter overlay backup must be empty")
    if (wine / ABI_NAME).exists():
        raise ValueError("refusing to overwrite an existing counter ABI header")
    subprocess.run(["git", "-C", str(wine), "diff", "--quiet", "HEAD", "--", *FILES], check=True)
    originals = {p: (wine / p).read_bytes() for p in FILES}
    staged = {p: v.encode() for p, v in stage({p: v.decode() for p, v in originals.items()}).items()}
    abi = ABI_SOURCE.read_bytes()
    backup.mkdir(parents=True, exist_ok=True)
    for path, data in originals.items():
        target = backup / "original" / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    manifest = {"version": 1, "files": {p: {"original": digest(originals[p]), "staged": digest(staged[p])} for p in FILES}, "abi": digest(abi)}
    (backup / "manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
    # Record all exact before/after hashes first, so EXIT recovery also handles
    # an interrupted application without adopting unrelated source changes.
    try:
        (wine / ABI_NAME).write_bytes(abi)
        for path, data in staged.items():
            (wine / path).write_bytes(data)
    except BaseException:
        restore(wine, backup)
        raise


def restore(wine: Path, backup: Path) -> None:
    manifest_path = backup / "manifest.json"
    if not manifest_path.exists():
        return
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("version") != 1 or set(manifest.get("files", {})) != set(FILES):
        raise ValueError("unrecognized counter overlay ownership manifest")
    originals = {}
    for path in FILES:
        data = (backup / "original" / path).read_bytes()
        expected = manifest["files"][path]
        if digest(data) != expected["original"] or digest((wine / path).read_bytes()) not in (expected["original"], expected["staged"]):
            raise ValueError(f"refusing to overwrite unrelated source changes: {path}")
        originals[path] = data
    header = wine / ABI_NAME
    if header.exists() and digest(header.read_bytes()) != manifest["abi"]:
        raise ValueError("refusing to remove an unrelated counter ABI header")
    for path, data in originals.items():
        (wine / path).write_bytes(data)
    if header.exists():
        header.unlink()
    manifest_path.unlink()


def verify_pe(path: Path, expected_machine: str) -> dict[str, int]:
    """Check the actual packaged PE, including zero-fill and DIR64 coverage."""
    data = path.read_bytes()
    def read(fmt: str, off: int):
        if off < 0 or off + struct.calcsize(fmt) > len(data):
            raise ValueError("truncated native ntdll PE")
        return struct.unpack_from(fmt, data, off)
    if data[:2] != b"MZ":
        raise ValueError("native ntdll has no MZ header")
    pe, = read("<I", 0x3c)
    if data[pe:pe+4] != b"PE\0\0":
        raise ValueError("native ntdll has no PE header")
    machine, count, _, _, _, optional_bytes, _ = read("<HHIIIHH", pe + 4)
    allowed = {"aarch64": (0xaa64,), "arm64ec": (0x8664, 0xa641)}[expected_machine]
    if machine not in allowed or read("<H", pe+24)[0] != 0x20b or optional_bytes < 240:
        raise ValueError("incorrect native ntdll architecture")
    size, headers = read("<II", pe+24+56)
    if not 0 < size <= 0x1000000 or not 0 < headers <= min(size, len(data)) or read("<I", pe+24+108)[0] < 6:
        raise ValueError("invalid native ntdll image bounds")
    mapped = bytearray(size)
    mapped[:headers] = data[:headers]
    sections = []
    for index in range(count):
        off = pe + 24 + optional_bytes + index * 40
        vsize, rva, rawsize, rawoff = read("<IIII", off+8)
        flags, = read("<I", off+36)
        span = max(vsize, rawsize)
        if not span or rva > size or span > size-rva or rawoff > len(data) or rawsize > len(data)-rawoff:
            raise ValueError("invalid native ntdll section bounds")
        if any(rva < oldrva+oldspan and oldrva < rva+span for oldrva, oldspan, _, _ in sections):
            raise ValueError("overlapping native ntdll sections")
        mapped[rva:rva+rawsize] = data[rawoff:rawoff+rawsize]
        sections.append((rva, span, flags, vsize or rawsize))
    def u32(off):
        if off < 0 or off > size-4: raise ValueError("PE RVA out of bounds")
        return struct.unpack_from("<I", mapped, off)[0]
    def span_ok(rva, n, rw=False):
        if not n or rva < 0 or rva > size-n: return False
        return any(rva >= start and rva+n <= start+(data_span if rw else span) and (not rw or flags & 0xf2000000 == 0xc0000000) for start, span, flags, data_span in sections)
    def name_at(rva):
        if not span_ok(rva,1): raise ValueError("export name outside image sections")
        end = mapped.find(0, rva, min(size, rva+256))
        if end < 0 or not span_ok(rva,end-rva+1): raise ValueError("unterminated export name")
        return bytes(mapped[rva:end]).decode("ascii")
    export_rva, export_bytes = read("<II", pe+24+112)
    if not span_ok(export_rva, export_bytes) or export_bytes < 40:
        raise ValueError("invalid native ntdll exports")
    functions, names = u32(export_rva+20), u32(export_rva+24)
    ftable, ntable, otable = u32(export_rva+28),u32(export_rva+32),u32(export_rva+36)
    if not span_ok(ftable, functions*4) or not span_ok(ntable,names*4) or not span_ok(otable,names*2):
        raise ValueError("invalid native ntdll export tables")
    exports = {}
    for index in range(names):
        name = name_at(u32(ntable+index*4))
        ordinal = struct.unpack_from("<H", mapped, otable+index*2)[0]
        if ordinal >= functions: raise ValueError("invalid native ntdll export ordinal")
        value = u32(ftable+ordinal*4)
        if name in ("ios_xp_nt", "ios_xp_nt_write_contract", "ios_srw_ring", "ios_srw_ring_idx", "ios_srw_history_write_contract"):
            if name in exports or export_rva <= value < export_rva+export_bytes:
                raise ValueError("duplicate or forwarded counter export")
            exports[name] = value
    if set(exports) != {"ios_xp_nt", "ios_xp_nt_write_contract", "ios_srw_ring", "ios_srw_ring_idx", "ios_srw_history_write_contract"}:
        raise ValueError("native counter/history contract exports missing")
    counter, contract = exports["ios_xp_nt"], exports["ios_xp_nt_write_contract"]
    if not span_ok(counter,24712,True) or not span_ok(contract,24,True) or (counter < contract+24 and contract < counter+24712):
        raise ValueError("native counter contract is not disjoint nonexecutable RW data")
    magic, n, reserved, writer = struct.unpack_from("<QIIQ", mapped, contract)
    abi_text = ABI_SOURCE.read_text()
    wanted_magic = int(re.search(r"#define MADEIRA_NATIVE_COUNTER_ABI_V1 (0x[0-9a-fA-F]+)ULL", abi_text)[1],16)
    if (magic,n,reserved,writer) != (wanted_magic,24712,0,0):
        raise ValueError("native counter contract contents differ from source ABI")
    ring, index, history = (exports[k] for k in ("ios_srw_ring", "ios_srw_ring_idx", "ios_srw_history_write_contract"))
    history_magic = int(re.search(r"#define MADEIRA_NATIVE_SRW_ABI_V1 (0x[0-9a-fA-F]+)ULL", abi_text)[1],16)
    spans = ((counter,24712),(contract,24),(ring,8192),(index,4),(history,32))
    for i,(start,length) in enumerate(spans):
        if not span_ok(start,length,True) or start & (3 if length == 4 else 7):
            raise ValueError("native private history span is unaligned or not complete RW data")
        if any(start < other+bytes_ and other < start+length for other,bytes_ in spans[:i]):
            raise ValueError("native counter/history spans overlap")
    if struct.unpack_from("<QIIQQ",mapped,history) != (history_magic,8192,16,0,0):
        raise ValueError("native SRW history contents differ from source ABI")
    writer_slots = (contract+16,history+16,history+24)
    reloc_rva, reloc_size = read("<II",pe+24+112+5*8)
    if bool(reloc_rva) != bool(reloc_size) or reloc_size and not span_ok(reloc_rva,reloc_size):
        raise ValueError("invalid native ntdll relocations")
    cursor, end = reloc_rva, reloc_rva+reloc_size
    while cursor < end:
        if cursor > end-8: raise ValueError("truncated native ntdll relocation block")
        page, block = u32(cursor), u32(cursor+4)
        if block < 8 or block % 2 or block > end-cursor: raise ValueError("invalid native ntdll relocation block")
        for entry in range(cursor+8,cursor+block,2):
            value = struct.unpack_from("<H",mapped,entry)[0]
            if value >> 12 == 10:
                target = page+(value & 0xfff)
                if any(target < slot+8 and slot < target+8 for slot in writer_slots):
                    raise ValueError("private writer unexpectedly has a DIR64 relocation")
        cursor += block
    result = {"machine": machine, "image_bytes": size, "counter_rva": counter, "counter_bytes": n, "contract_rva": contract,
              "srw_ring_rva": ring, "srw_index_rva": index, "srw_contract_rva": history}
    print(f"native-counter-contract: machine={machine:04x} bytes={n} srw-entries=512 writers=null relocation=none")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for action in ("apply", "restore"):
        child = commands.add_parser(action)
        child.add_argument("--wine", type=Path, required=True)
        child.add_argument("--backup", type=Path, required=True)
    verify = commands.add_parser("verify-pe")
    verify.add_argument("--machine", choices=("aarch64","arm64ec"), required=True)
    verify.add_argument("image", type=Path)
    args = parser.parse_args()
    if args.command == "verify-pe": verify_pe(args.image,args.machine)
    elif args.command == "apply": apply(args.wine,args.backup)
    else: restore(args.wine,args.backup)


if __name__ == "__main__":
    main()
