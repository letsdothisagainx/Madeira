#!/usr/bin/env python3
"""Exercise the production counter stager, ownership restoration and PE gate."""
from __future__ import annotations
import contextlib
import importlib.util
import io
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("native_counter_stage", ROOT / "tools/build/stage-native-counter-writes.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
checks = 0


def ok(value, label):
    global checks
    assert value, label
    checks += 1


def reject(call, label):
    global checks
    try:
        call()
    except (ValueError, subprocess.CalledProcessError):
        checks += 1
    else:
        raise AssertionError(label)


sources = {p: (ROOT / "wine" / p).read_text() for p in module.FILES}
staged = module.stage(sources)
ok(set(staged) == set(sources), "only owned source files staged")
for path in module.FILES[:2]:
    ok("ios_xp_nt." not in staged[path], f"all {path} counter producers use writer")
    ok(staged[path].count("ios_xp_nt_writer()->") == sources[path].count("ios_xp_nt."), "exact counter member replacement")
ok("struct ios_xp_nt ios_xp_nt;   /* layout: ntdll_misc.h */" in staged[module.FILES[1]], "existing exported block retained")
ok("MADEIRA_NATIVE_COUNTER_ABI_V1, sizeof(ios_xp_nt), 0, NULL" in staged[module.FILES[1]], "writer NULL has no source pointer relocation")
ok(staged[module.FILES[3]].replace("@ extern -private ios_xp_nt_write_contract\n", "") == sources[module.FILES[3]], "spec adds only private data export")
ok(staged[module.FILES[0]].replace("ios_xp_nt_writer()->", "ios_xp_nt.") == sources[module.FILES[0]], "all QPC arithmetic and status untouched")
reject(lambda: module.stage(staged), "double application must fail")
reject(lambda: module.stage({p:v for p,v in sources.items() if p != module.FILES[0]}), "missing source must fail")
wrong = dict(sources); wrong[module.FILES[3]] += "@ extern -private ios_xp_nt\n"
reject(lambda: module.stage(wrong), "ambiguous export anchor must fail")

with tempfile.TemporaryDirectory(prefix="madeira-counter-stage-") as scratch:
    tmp = Path(scratch); wine = tmp / "wine"; wine.mkdir()
    for path, text in sources.items():
        p = wine / path; p.parent.mkdir(parents=True,exist_ok=True); p.write_text(text)
    # A concurrently staged SCM file is intentionally outside this ownership.
    unrelated = wine / "dlls/ntdll/loader.c"; unrelated.write_text("original loader\n")
    subprocess.run(["git","init","-q",str(wine)],check=True)
    subprocess.run(["git","-C",str(wine),"add","."],check=True)
    subprocess.run(["git","-C",str(wine),"-c","user.name=Counter overlay test","-c","user.email=counter@example.invalid","commit","-qm","fixture"],check=True)
    unrelated.write_text("SCM independently staged\n")
    backup = tmp / "backup"
    module.apply(wine,backup)
    ok(all((wine/p).read_text()==staged[p] for p in sources), "actual apply uses production pure stage")
    ok((wine/module.ABI_NAME).read_bytes()==module.ABI_SOURCE.read_bytes(), "exact ABI header staged")
    # Interrupted application: any owned file may still be original and the
    # copied header may not have been written yet. Recovery remains exact.
    (wine/module.FILES[0]).write_text(sources[module.FILES[0]])
    (wine/module.ABI_NAME).unlink()
    module.restore(wine,backup)
    ok(all((wine/p).read_text()==sources[p] for p in sources), "interrupted application restores all exact originals")
    ok(not (wine/module.ABI_NAME).exists(), "owned temporary header removed")
    ok(unrelated.read_text()=="SCM independently staged\n", "independent SCM source overlay preserved")
    shutil.rmtree(backup)
    module.apply(wine,backup)
    changed = wine / module.FILES[0]
    changed.write_text(changed.read_text()+"/* unrelated user edit */\n")
    reject(lambda: module.restore(wine,backup), "restore must not overwrite unrelated edits")
    ok((wine/module.FILES[1]).read_text()==staged[module.FILES[1]], "failed restore is preflighted before writing any original")
    changed.write_text(staged[module.FILES[0]])
    module.restore(wine,backup)
    ok(all((wine/p).read_text()==sources[p] for p in sources), "verified restoration succeeds after mutation resolved")
    shutil.rmtree(backup)
    (wine/module.ABI_NAME).write_text("unowned header")
    reject(lambda: module.apply(wine,backup), "unowned header must not be overwritten")
    (wine/module.ABI_NAME).unlink()
    changed.write_text(changed.read_text()+"/* dirty original */\n")
    reject(lambda: module.apply(wine,backup), "dirty original must not be staged")
    changed.write_text(sources[module.FILES[0]])
    module.apply(wine,backup)
    (wine/module.ABI_NAME).write_text("changed during build")
    reject(lambda: module.restore(wine,backup), "unowned ABI replacement must not be removed")
    (wine/module.ABI_NAME).write_bytes(module.ABI_SOURCE.read_bytes())
    module.restore(wine,backup)
    ok(all((wine/p).read_text()==sources[p] for p in sources), "second successful apply/restore is exact")

# Compile the actual staged struct and getter with native Windows-width aliases.
# The C fixture verifies ABI offsets and the only mutable address choice;
# no QPC implementation is re-created in this test.
with tempfile.TemporaryDirectory(prefix="madeira-counter-getter-") as scratch:
    tmp = Path(scratch)
    header = staged[module.FILES[2]]
    block_start = header.index("struct ios_xp_nt_qpc")
    block_end = header.index("extern void ios_xp_nt_init(void);")
    block = header[block_start:block_end]
    (tmp / "madeira_native_counter_alias_abi.h").write_bytes(module.ABI_SOURCE.read_bytes())
    c = '''#include <stddef.h>
#include <stdint.h>
#include <string.h>
#define _WIN64 1
typedef uint32_t DWORD, ULONG;
typedef uint64_t ULONGLONG, ULONG_PTR;
typedef int64_t LONG64;
#define C_ASSERT(expr) _Static_assert(expr,#expr)
#define FIELD_OFFSET(type,field) offsetof(type,field)
''' + block + '''
struct ios_xp_nt ios_xp_nt;
struct ios_xp_nt_write_contract ios_xp_nt_write_contract = {MADEIRA_NATIVE_COUNTER_ABI_V1,sizeof(ios_xp_nt),0,NULL};
int main(void) {
    struct ios_xp_nt alias;
    memset(&alias,0,sizeof(alias));
    if (ios_xp_nt_writer()!=&ios_xp_nt) return 1;
    __atomic_store_n(&ios_xp_nt_write_contract.writer,&alias,__ATOMIC_RELEASE);
    ios_xp_nt_writer()->qpc[7].calls=123;
    if (alias.qpc[7].calls!=123 || ios_xp_nt.qpc[7].calls!=0) return 2;
    if (ios_xp_nt_write_contract.size!=24712) return 3;
    return 0;
}
'''
    source = tmp / "fixture.c"; source.write_text(c)
    compiler = shutil.which("cc"); ok(compiler is not None,"native C compiler available")
    subprocess.run([compiler,"-std=c11","-Wall","-Wextra","-Werror","-I",str(tmp),str(source),"-o",str(tmp/"fixture")],check=True)
    subprocess.run([str(tmp/"fixture")],check=True)
    ok(True,"actual staged native getter/struct compiles and redirects only counter writers")


def pe_fixture(machine):
    b = bytearray(0xc400)
    def put(fmt, off, *values): struct.pack_into(fmt,b,off,*values)
    b[:2]=b"MZ"; put("<I",0x3c,0x80); b[0x80:0x84]=b"PE\0\0"
    put("<HHIIIHH",0x84,machine,4,0,0,0,240,0x2022)
    opt=0x98; put("<H",opt,0x20b); put("<Q",opt+24,0x180000000)
    put("<II",opt+56,0x10000,0x400); put("<I",opt+108,16)
    put("<II",opt+112,0x1000,0x300); put("<II",opt+152,0xe000,12)
    for idx,(name,rva,raw,size,flags) in enumerate(((b".edata",0x1000,0x400,0x1000,0x40000040),(b".text",0x2000,0x1400,0x1000,0x60000020),(b".data",0x4000,0x2400,0x9000,0xc0000040),(b".reloc",0xe000,0xb400,0x1000,0x42000040))):
        off=opt+240+idx*40; b[off:off+len(name)]=name
        put("<IIII",off+8,size,rva,size,raw); put("<I",off+36,flags)
    # RVAs inside each section map to raw position by this fixture's layout.
    def raw(rva):
        for start,base,size in ((0x1000,0x400,0x1000),(0x2000,0x1400,0x1000),(0x4000,0x2400,0x9000),(0xe000,0xb400,0x1000)):
            if start <= rva < start+size: return base+rva-start
        raise AssertionError(rva)
    put("<IIIII",raw(0x1000)+20,2,2,0x1100,0x1120,0x1140)
    put("<II",raw(0x1100),0x4000,0xa100)
    put("<II",raw(0x1120),0x1180,0x11a0)
    put("<HH",raw(0x1140),0,1)
    b[raw(0x1180):raw(0x1180)+10]=b"ios_xp_nt\0"
    name=b"ios_xp_nt_write_contract\0"; b[raw(0x11a0):raw(0x11a0)+len(name)]=name
    put("<QIIQ",raw(0xa100),0x315752544e505849,24712,0,0)
    put("<IIHH",raw(0xe000),0xa000,12,0,0)
    return b,raw


with tempfile.TemporaryDirectory(prefix="madeira-counter-pe-") as scratch:
    path=Path(scratch)/"ntdll.dll"
    for machine,arch in ((0xaa64,"aarch64"),(0x8664,"arm64ec"),(0xa641,"arm64ec")):
        original,raw = pe_fixture(machine); path.write_bytes(original)
        with contextlib.redirect_stdout(io.StringIO()): result=module.verify_pe(path,arch)
        ok(result["counter_bytes"]==24712 and result["machine"]==machine,"native packaged contract accepted for correct architecture")
    base,raw=pe_fixture(0xaa64)
    def bad(mutator,label):
        data=bytearray(base); mutator(data); path.write_bytes(data)
        reject(lambda: module.verify_pe(path,"aarch64"),label)
    def write(fmt,off,*v): return lambda data: struct.pack_into(fmt,data,off,*v)
    bad(write("<H",0x84,0x14c),"I386 contract cannot pass native package gate")
    bad(write("<H",0x84,0x8664),"EC ntdll cannot be packaged as AA64")
    bad(write("<Q",raw(0xa100),0),"contract ABI magic enforced")
    bad(write("<I",raw(0xa100)+8,20616),"native counter bytes enforced")
    bad(write("<I",raw(0xa100)+12,1),"reserved bits enforced")
    bad(write("<Q",raw(0xa100)+16,0x300004000),"file writer must be NULL")
    bad(write("<H",raw(0xe000)+8,0xa110),"NULL writer cannot carry DIR64 relocation")
    bad(write("<I",raw(0x1100)+4,0x4008),"counter and contract cannot overlap")
    bad(write("<I",0x98+240+2*40+36,0xe0000040),"executable data cannot carry mutable diagnostic block")
    bad(write("<I",0x98+240+2*40+36,0xd0000040),"shared data section cannot carry private writer")
    bad(write("<I",0x98+240+2*40+36,0xc2000040),"discardable data cannot carry persistent writer")
    bad(write("<I",raw(0x1100),0xc000),"whole 24712-byte counter block must fit")
    bad(write("<I",raw(0x1100)+4,0x1180),"forwarded contract must be rejected")
    bad(write("<I",raw(0xe000)+4,0x1002),"malformed relocation block must be rejected")
    path.write_bytes(base[:0x100]); reject(lambda:module.verify_pe(path,"aarch64"),"truncated packaged PE rejected")

print(f"native counter staging: {checks} checks passed; exact source restore and A64/EC packaged contract validated")
