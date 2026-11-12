#!/usr/bin/env python3
"""Exercise actual stripped-PE SRW compiler-code attestation (structural only)."""
import importlib.util
from pathlib import Path
import struct
import tempfile

ROOT = Path(__file__).resolve().parents[2]
def module(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
CHECK=module('native_srw_code',ROOT/'tools/check-native-srw-code.py')
FIXTURE=module('srw_owned_pe',ROOT/'tests/host/check-native-registration-tools.py')
BODY=struct.pack('<IIII',0x7100001f,0x54000060,0xd503201f,0xd65f03c0)

def object_bytes(machine):
    name=CHECK.FUNCTION.encode()+b'\0'
    offset=60+len(BODY)
    header=struct.pack('<HHIIIHH',machine,1,0,offset,2,0,0)
    section=bytearray(40);section[:5]=b'.text'
    struct.pack_into('<III',section,16,len(BODY),60,0)
    struct.pack_into('<I',section,36,0x60000020)
    symbol=struct.pack('<IIIhHBB',0,4,0,1,0x20,2,1)
    auxiliary=bytearray(18);struct.pack_into('<I',auxiliary,4,len(BODY))
    return header+section+BODY+symbol+auxiliary+struct.pack('<I',4+len(name))+name

def pe_bytes(farm):
    data=bytearray(FIXTURE.fixture(farm));dirs=0x98+112
    # Actual export and ARM64EC redirection table layouts, deliberately not a
    # working DLL. No fixture function supplies a synchronization result.
    struct.pack_into('<II',data,dirs,0x2000,0xa0)
    struct.pack_into('<IIHHIIIIIII',data,0x600,0,0,0,0,0,1,1,1,0x2040,0x2050,0x2060)
    struct.pack_into('<I',data,0x640,0x1080 if farm=='arm64ec-windows' else 0x1000)
    struct.pack_into('<I',data,0x650,0x2070);struct.pack_into('<H',data,0x660,0)
    name=CHECK.FUNCTION.encode()+b'\0';data[0x670:0x670+len(name)]=name
    data[0x400:0x400+len(BODY)]=BODY
    if farm=='arm64ec-windows':
        struct.pack_into('<I',data,0xd00+16,0x2760)
        struct.pack_into('<I',data,0xd00+52,1)
        struct.pack_into('<II',data,0xd60,0x1080,0x1000)
    return data

with tempfile.TemporaryDirectory(prefix='madeira-srw-code-')as directory:
    path=Path(directory)
    for machine,farm,object_machine in [('aarch64','aarch64-windows',0xaa64),('arm64ec','arm64ec-windows',0xa641)]:
        obj=path/'sync.o';image=path/'ntdll.dll';obj.write_bytes(object_bytes(object_machine));base=pe_bytes(farm);image.write_bytes(base)
        CHECK.check(image,obj,machine)
        # Old code differs in a nonrelocated condition instruction. Data-only
        # alias contracts or a correct PE machine must never bless it.
        bad=bytearray(base);bad[0x400]^=1;image.write_bytes(bad)
        try:CHECK.check(image,obj,machine)
        except AssertionError as error:assert 'differs from the rebuilt' in str(error)
        else:raise AssertionError('stale compiled SRW code accepted')
        if machine=='arm64ec':
            bad=bytearray(base);struct.pack_into('<I',bad,0xd60+4,0x1800);image.write_bytes(bad)
            try:CHECK.check(image,obj,machine)
            except AssertionError:pass
            else:raise AssertionError('invalid EC native redirection accepted')
print('PASS actual object/stripped-PE proof checker: A64+EC native export routing, old-code mismatch and invalid hybrid target rejection; structural fixture supplies no lock or gameplay result')
