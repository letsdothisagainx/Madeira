#!/usr/bin/env python3
"""Run the production native COFF opcode gate against owned object fixtures."""
from pathlib import Path
import contextlib
import importlib.util
import io
import struct
import tempfile

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('subfloor_atomics',ROOT/'tools/check-fex-subfloor-atomics.py')
GATE=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(GATE)
# Pin the external COFF ABI independently of the implementation under test.
BIGOBJ_MAGIC=bytes((0xc7,0xa1,0xba,0xd1,0xee,0xba,0xa9,0x4b,0xaf,0x20,0xfa,0xf6,0x6a,0xa4,0xdc,0xb8))
assert GATE.BIGOBJ_ID==BIGOBJ_MAGIC


def fixture(big=False):
    callback=b'#BTCpu64IosAddAliasMapping';retire=b'#IosSubfloorRetireMapping'
    text=struct.pack('<6I',0xc8e0fc20,0x88e0fc20,0x889ffc22,0xd65f03c0,0x88e0fc20,0xd65f03c0)
    header=56 if big else 20;symbol_size=20 if big else 18;raw=(header+40+15)&~15
    symbols=raw+len(text);strings=b'\0\0\0\0'+callback+b'\0'+retire+b'\0'
    strings=struct.pack('<I',len(strings))+strings[4:]
    data=bytearray(symbols+2*symbol_size+len(strings))
    if big:
        struct.pack_into('<HHHHI',data,0,0,0xffff,2,0xa641,0);data[12:28]=BIGOBJ_MAGIC
        struct.pack_into('<III',data,44,1,symbols,2)
    else:struct.pack_into('<HHIIIHH',data,0,0xa641,1,0,symbols,2,0,0)
    data[header:header+5]=b'.text';struct.pack_into('<II',data,header+16,len(text),raw)
    struct.pack_into('<I',data,header+36,0x60000020);data[raw:raw+len(text)]=text
    for index,(name,offset,name_offset) in enumerate(((callback,0,4),(retire,16,5+len(callback)))):
        entry=symbols+index*symbol_size;struct.pack_into('<III',data,entry,0,name_offset,offset)
        struct.pack_into('<iHBB' if big else '<hHBB',data,entry+12,1,0x20,2,0)
    data[symbols+2*symbol_size:]=strings
    return data,{'header':header,'raw':raw,'symbols':symbols,'symbol_size':symbol_size}


with tempfile.TemporaryDirectory(prefix='madeira-subfloor-opcodes-') as folder:
    root=Path(folder);obj=root/'IosJitAlias.cpp.obj';count=0
    for big in (False,True):
        base,where=fixture(big);obj.write_bytes(base)
        with contextlib.redirect_stdout(io.StringIO()):result=GATE.verify_object(obj)
        assert result['casal_widths']==[32,64] and result['release32']==1
    base,where=fixture()
    def bad(edit,label):
        global count
        data=bytearray(base);edit(data);obj.write_bytes(data)
        try:GATE.verify_object(obj)
        except (ValueError,UnicodeError,struct.error):count+=1
        else:raise AssertionError('accepted invalid '+label)
    raw=where['raw'];symbols=where['symbols']
    bad(lambda b:struct.pack_into('<I',b,raw,0xd503201f),'missing64bit CASAL')
    bad(lambda b:struct.pack_into('<I',b,raw,0xc8a07c20),'weaker-than-required64bit CAS')
    bad(lambda b:struct.pack_into('<I',b,raw+4,0xd503201f) or struct.pack_into('<I',b,raw+16,0xd503201f),'missing32bit CASAL')
    bad(lambda b:struct.pack_into('<I',b,raw+8,0xd503201f),'missingrelease publication')
    for opcode in (0xc80afd28,0x8809fc08,0xc80f7d89,0xc8200000):
        bad(lambda b,opcode=opcode:struct.pack_into('<I',b,raw+8,opcode),'exclusive store family')
    bad(lambda b:struct.pack_into('<H',b,0,0x8664),'AMD64 object')
    bad(lambda b:struct.pack_into('<I',b,where['header']+36,0xc0000040),'DATA pretending native code')
    bad(lambda b:struct.pack_into('<H',b,symbols+where['symbol_size']+14,0),'retire name without typed function definition')
    bad(lambda b:struct.pack_into('<I',b,symbols+8,1),'unalignednative function')
    bad(lambda b:struct.pack_into('<I',b,where['header']+16,0xfffffff0),'outofbounds code')
    bad(lambda b:struct.pack_into('<I',b,12,0xffffffff),'outofbounds symbols')
    bad(lambda b:struct.pack_into('<I',b,symbols+2*18,0xffffffff),'outofbounds strings')
    obj.write_bytes(base[:24])
    try:GATE.verify_object(obj)
    except ValueError:count+=1
    else:raise AssertionError('accepted truncatedobject')
    directory=root/'build/Source/Windows/ARM64EC/CMakeFiles/arm64ecfex.dir';directory.mkdir(parents=True)
    actual=directory/'IosJitAlias.cpp.obj';actual.write_bytes(base)
    assert GATE.build_object(root/'build')==actual
    other=root/'build/duplicate/arm64ecfex.dir/IosJitAlias.cpp.obj';other.parent.mkdir(parents=True);other.write_bytes(base)
    try:GATE.build_object(root/'build')
    except ValueError:count+=1
    else:raise AssertionError('accepted ambiguousnative object')
    build=(ROOT/'build/fex-arm64ec/build.sh').read_text()
    patch=(ROOT/'build/fex-compat/subfloor-domain.patch').read_text()
    assert 'set_property(SOURCE IosJitAlias.cpp APPEND PROPERTY COMPILE_OPTIONS ${FEX_TUNE_COMPILE_FLAGS})' in patch
    assert build.index('cmake --build')<build.index('check-fex-subfloor-atomics.py')<build.index('cp "$B/Bin/libarm64ecfex.dll"')
    print(f'PASS production COFF instruction gate: normal/bigobj native32+64CASAL/STLR accepted; {count} stale/malformed/exclusive-store cases rejected; actual object is checked before CPU publication')
