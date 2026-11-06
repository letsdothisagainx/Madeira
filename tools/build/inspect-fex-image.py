#!/usr/bin/env python3
"""Inspect the exact packaged WoW64 CPU image; no third-party PE package needed."""
import argparse
import hashlib
from pathlib import Path
import shutil
import struct
import subprocess

TARGETS = (0x108d5c,0x1088fc,0xa3a0,0xa118,0x9f8c,0x14650,0x141e0,0x146ec,
           0x143c8,0x107f04,0x1020e8,0x107a04,0x105304,0x13daec,0x2d44,
           0xac6e4,0x17fe4,0x17820,0x18d4c,0xb1134)


def inspect(path, verify=False, code_targets=None, data_targets=(), context=16):
    data=path.read_bytes()
    def unpack(fmt,offset):
        assert 0<=offset<=len(data)-struct.calcsize(fmt),'PE field outside image'
        return struct.unpack_from(fmt,data,offset)
    assert data[:2]==b'MZ','missing MZ signature'
    pe,=unpack('<I',0x3c)
    assert data[pe:pe+4]==b'PE\0\0','missing PE signature'
    machine,count,stamp,sym,n,opt,flags=unpack('<HHIIIHH',pe+4)
    # The packaged ARM64EC xtajit64.dll uses the AMD64-compatible machine ID.
    # Inspection is read-only; requested RVAs identify its native ARM64 code.
    assert machine in (0xaa64,0xa641,0x8664) and unpack('<H',pe+24)[0]==0x20b,'expected native/hybrid PE32+'
    size,=unpack('<I',pe+24+56)
    print(f'image={path.name} sha256={hashlib.sha256(data).hexdigest()} bytes={len(data):#x} machine={machine:04x} image-size={size:#x} timestamp={stamp:08x} coff-symbols={n}')
    assert 0<count<=96 and sym and n<=1000000 and sym+n*18+4<=len(data),'missing/invalid COFF symbols'
    sections=[]
    for i in range(count):
        offset=pe+24+opt+40*i
        name=data[offset:offset+8].rstrip(b'\0').decode('ascii','replace')
        vs,rva,rawsize,raw=unpack('<IIII',offset+8)
        characteristics,=unpack('<I',offset+36)
        sections.append((name,rva,max(vs,rawsize),raw,rawsize,characteristics))
    strings=sym+n*18
    string_size,=unpack('<I',strings)
    assert 4<=string_size<=len(data)-strings,'invalid COFF string table'
    rows=[];all_rows=[];i=0
    while i<n:
        offset=sym+i*18;rawname=data[offset:offset+8]
        if rawname[:4]==bytes(4):
            index,=struct.unpack_from('<I',rawname,4)
            assert 4<=index<string_size,'invalid symbol string offset'
            end=data.find(b'\0',strings+index,strings+string_size)
            assert end>=0,'unterminated symbol name'
            name=data[strings+index:end].decode('utf8','replace')
        else:name=rawname.rstrip(b'\0').decode('utf8','replace')
        value,section,kind,storage,aux=unpack('<IhHBB',offset+8)
        assert i+aux<n,'auxiliary symbol outside table'
        if 0<section<=count:
            row=(sections[section-1][1]+value,name,section)
            all_rows.append(row)
            if kind&0x20 and sections[section-1][5]&0x20000000:
                rows.append(row)
        i+=aux+1
    rows.sort()
    data_targets=tuple(data_targets)+tuple(r[0] for r in all_rows if r[1] in ('fex_ios_rpm_owner','fex_ios_rpm_depth','fex_ios_rpm_enabled'))
    assert rows,'no function symbols in executable sections'
    def code(rva,nbytes):
        for _,base,_,raw,rawsize,_ in sections:
            if base<=rva and rva-base+nbytes<=rawsize and raw+rva-base+nbytes<=len(data):
                return data[raw+rva-base:raw+rva-base+nbytes]
        return b''
    if verify:
        assert code(0x108d5c,4)==bytes.fromhex('200040d4'),'artifact does not match captured HLT at RVA108d5c'
        assert code(0x1088f8,4)==bytes.fromhex('19010094'),'artifact does not match captured caller BL at RVA1088f8'
        print('PASS exact captured native HLT and caller BL bytes match this image')
    targets=TARGETS if code_targets is None else code_targets
    selected=[]
    for target in targets:
        candidates=[r for r in rows if r[0]<=target]
        selected.append(candidates[-1] if candidates else None)
    data_selected=[]
    for target in data_targets:
        candidates=[r for r in all_rows if r[0]<=target and
                    sections[r[2]-1][1]<=target<sections[r[2]-1][1]+sections[r[2]-1][2] and
                    not sections[r[2]-1][5]&0x20000000 and not r[1].startswith('.')]
        candidates.sort()
        data_selected.append(candidates[-5:])
    names=[r[1] for r in selected if r]+[r[1] for group in data_selected for r in group]
    filt=shutil.which('c++filt') or shutil.which('llvm-cxxfilt')
    demangled={}
    if filt:
        result=subprocess.run([filt],input='\n'.join(names)+'\n',text=True,capture_output=True,check=True)
        demangled=dict(zip(names,result.stdout.splitlines()))
    for target,row in zip(targets,selected):
        if row:
            start,name,section=row
            print(f'RVA {target:#x}: function={name} start={start:#x} offset={target-start:#x} section={sections[section-1][0]}')
            print('  '+demangled.get(name,name))
        else:print(f'RVA {target:#x}: function unavailable')
        print(f'  code[-{context}..+{context}] '+code(max(0,target-context),context*2).hex(' '))
        try:
            import capstone
        except ImportError:
            pass
        else:
            decoder=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_LITTLE_ENDIAN)
            for insn in decoder.disasm(code(max(0,target-context),context*2),max(0,target-context)):
                print(f'  {"=>" if insn.address==target else "  "} {insn.address:#x}: {insn.bytes.hex()} {insn.mnemonic} {insn.op_str}')
    for target,group in zip(data_targets,data_selected):
        section=next((s for s in sections if s[1]<=target<s[1]+s[2]),None)
        print(f'DATA RVA {target:#x}: section={section[0] if section else "unmapped"}')
        for start,name,index in reversed(group):
            print(f'  candidate={demangled.get(name,name)} start={start:#x} offset={target-start:#x} section={sections[index-1][0]}')
        raw=code(target,32)
        print('  bytes='+raw.hex(' ') if raw else '  no raw bytes (virtual zero-filled data or outside file)')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image',type=Path)
    parser.add_argument('--assert-known-fault',action='store_true')
    parser.add_argument('--code-rva',action='append',type=lambda value:int(value,0),default=None)
    parser.add_argument('--data-rva',action='append',type=lambda value:int(value,0),default=[])
    parser.add_argument('--context',type=int,default=16,choices=range(4,257,4))
    args=parser.parse_args()
    inspect(args.image,args.assert_known_fault,args.code_rva,args.data_rva,args.context)
