#!/usr/bin/env python3
"""Inspect the exact packaged WoW64 CPU image; no third-party PE package needed."""
import argparse
import hashlib
from pathlib import Path
import re
import shutil
import struct
import subprocess

TARGETS = (0x108d5c,0x1088fc,0xa3a0,0xa118,0x9f8c,0x14650,0x141e0,0x146ec,
           0x143c8,0x107f04,0x1020e8,0x107a04,0x105304,0x13daec,0x2d44,
           0xac6e4,0x17fe4,0x17820,0x18d4c,0xb1134)


def inspect(path, verify=False, code_targets=None, data_targets=(), context=16, log_symbols=False):
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
    assert 0<count<=96 and n<=1000000,'invalid PE sections or COFF symbol count'
    if n:assert sym and sym+n*18+4<=len(data),'invalid COFF symbols'
    sections=[]
    for i in range(count):
        offset=pe+24+opt+40*i
        name=data[offset:offset+8].rstrip(b'\0').decode('ascii','replace')
        vs,rva,rawsize,raw=unpack('<IIII',offset+8)
        characteristics,=unpack('<I',offset+36)
        sections.append((name,rva,max(vs,rawsize),raw,rawsize,characteristics))
    strings=sym+n*18
    string_size=0
    if n:
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
    def code(rva,nbytes):
        for _,base,_,raw,rawsize,_ in sections:
            if base<=rva and rva-base+nbytes<=rawsize and raw+rva-base+nbytes<=len(data):
                return data[raw+rva-base:raw+rva-base+nbytes]
        return b''
    symbol_source='COFF'
    export_originals={}
    if not rows:
        symbol_source='PE named export/native redirection'
        def read_rva(fmt,rva):
            raw=code(rva,struct.calcsize(fmt))
            assert len(raw)==struct.calcsize(fmt),'PE metadata outside file-backed sections'
            return struct.unpack(fmt,raw)
        redirects={};native_ranges=[]
        load,load_size=unpack('<II',pe+24+112+10*8)
        if machine in (0xa641,0x8664) and load and load_size>=208:
            pointer,=read_rva('<Q',load+200)
            if pointer:
                image_base,=unpack('<Q',pe+24+24)
                assert pointer>=image_base,'ARM64EC metadata below image base'
                metadata=pointer-image_base
                version,ranges,range_count=read_rva('<III',metadata)
                redirection,=read_rva('<I',metadata+16)
                redirect_count,=read_rva('<I',metadata+52)
                assert version in (1,2) and 0<range_count<=65536 and redirect_count<=65536,'invalid ARM64EC code map'
                assert bool(redirection)==bool(redirect_count),'invalid ARM64EC redirections'
                for index in range(range_count):
                    start,span=read_rva('<II',ranges+index*8)
                    if start&3==1:native_ranges.append((start&~3,(start&~3)+span))
                for index in range(redirect_count):
                    source,destination=read_rva('<II',redirection+index*8)
                    assert source not in redirects,'ambiguous ARM64EC export redirection'
                    redirects[source]=destination
        directory,directory_size=unpack('<II',pe+24+112)
        if directory and directory_size>=40:
            functions,names,ftable,ntable,otable=read_rva('<IIIII',directory+20)
            assert functions<=1000000 and names<=1000000,'invalid PE export count'
            for index in range(names):
                name_rva,=read_rva('<I',ntable+index*4)
                ordinal,=read_rva('<H',otable+index*2)
                assert ordinal<functions,'invalid PE export ordinal'
                original,=read_rva('<I',ftable+ordinal*4)
                if not original or directory<=original<directory+directory_size:continue
                name_bytes=bytearray()
                for position in range(4096):
                    char=code(name_rva+position,1)
                    assert char,'PE export name outside file-backed sections'
                    if char==b'\0':break
                    name_bytes.extend(char)
                else:raise AssertionError('unterminated PE export name')
                name=name_bytes.decode('utf8','replace')
                target=redirects.get(original,original)
                section=next((i for i,s in enumerate(sections,1) if s[1]<=target<s[1]+s[2]),None)
                if section is None:continue
                row=(target,name,section)
                all_rows.append(row)
                if sections[section-1][5]&0x20000000 and (machine==0xaa64 or
                    any(begin<=target<end for begin,end in native_ranges)):
                    rows.append(row)
                    export_originals[(target,name)]=original
        rows.sort()
        print(f'symbol-source={symbol_source} native-function-symbols={len(rows)} ARM64EC-redirections={len(redirects)}')
    if verify:
        assert code(0x108d5c,4)==bytes.fromhex('200040d4'),'artifact does not match captured HLT at RVA108d5c'
        assert code(0x1088f8,4)==bytes.fromhex('19010094'),'artifact does not match captured caller BL at RVA1088f8'
        print('PASS exact captured native HLT and caller BL bytes match this image')
    targets=TARGETS if code_targets is None else code_targets
    selected=[]
    intervals=[]
    for target in targets:
        section=next((i for i,s in enumerate(sections,1) if s[1]<=target<s[1]+s[2] and s[5]&0x20000000),None)
        candidates=[r for r in rows if r[2]==section and r[0]<=target]
        row=candidates[-1] if candidates else None
        selected.append(row)
        following=next((r[0] for r in rows if row and r[2]==section and r[0]>row[0]),None)
        intervals.append((following,'next distinct function') if following is not None else
                         (sections[section-1][1]+sections[section-1][2],'executable section end') if row else None)
    data_selected=[]
    for target in data_targets:
        candidates=[r for r in all_rows if r[0]<=target and
                    sections[r[2]-1][1]<=target<sections[r[2]-1][1]+sections[r[2]-1][2] and
                    not sections[r[2]-1][5]&0x20000000 and not r[1].startswith('.')]
        candidates.sort()
        data_selected.append(candidates[-5:])
    log_rows=[]
    if log_symbols:
        for match in re.finditer(rb'[\x20-\x7e]{4,}',data):
            raw=match.group()
            hit=raw.find(b'log_symbols')
            if hit<0:continue
            section=next((i for i,s in enumerate(sections,1) if s[3]<=match.start()<s[3]+s[4]),None)
            rva=sections[section-1][1]+match.start()-sections[section-1][3] if section else None
            candidates=[r for r in all_rows if rva is not None and r[2]==section and r[0]<=rva and
                        not sections[r[2]-1][5]&0x20000000 and not r[1].startswith('.')]
            candidates.sort()
            # Keep the matching token visible even in a long diagnostic string.
            begin=max(0,min(hit,len(raw)-80))
            log_rows.append((match.start(),rva,section,raw[begin:begin+80].decode('ascii'),candidates[-1] if candidates else None))
            if len(log_rows)==20:break
    names=[r[1] for r in selected if r]+[r[1] for group in data_selected for r in group]+[r[4][1] for r in log_rows if r[4]]
    filt=shutil.which('c++filt') or shutil.which('llvm-cxxfilt')
    demangled={}
    if filt:
        result=subprocess.run([filt],input='\n'.join(names)+'\n',text=True,capture_output=True,check=True)
        demangled=dict(zip(names,result.stdout.splitlines()))
    for target,row,interval in zip(targets,selected,intervals):
        if row:
            start,name,section=row
            print(f'RVA {target:#x}: function={name} start={start:#x} offset={target-start:#x} section={sections[section-1][0]}')
            label='raw-coff' if symbol_source=='COFF' else 'raw-export'
            print(f'  {label}={name!r} demangled={demangled.get(name,name)!r}')
            if (start,name) in export_originals:print(f'  export-entry-rva={export_originals[(start,name)]:#x} native-target-rva={start:#x}')
            print(f'  {symbol_source} symbol interval=[{start:#x},{interval[0]:#x}) upper-bound={interval[1]}; symbol interval is not a proven function extent')
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
            print(f'  raw-coff={name!r} candidate={demangled.get(name,name)!r} start={start:#x} offset={target-start:#x} section={sections[index-1][0]}')
        raw=code(target,32)
        print('  bytes='+raw.hex(' ') if raw else '  no raw bytes (virtual zero-filled data or outside file)')
    if log_symbols:
        print(f'LOG_SYMBOLS strings containing log_symbols: {len(log_rows)} (limit=20 strings, 80 characters each)' if log_rows else
              'LOG_SYMBOLS strings containing log_symbols: absent')
        for offset,rva,section,value,row in log_rows:
            where=f'RVA={rva:#x} section={sections[section-1][0]}' if rva is not None else 'outside mapped sections'
            print(f'  file-offset={offset:#x} {where} string={value!r}')
            if row:
                start,name,index=row
                print(f'    nearest-data-raw-coff={name!r} demangled={demangled.get(name,name)!r} start={start:#x} offset={rva-start:#x}; preceding symbol only')
            else:print('    nearest data COFF symbol unavailable')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image',type=Path)
    parser.add_argument('--assert-known-fault',action='store_true')
    parser.add_argument('--code-rva',action='append',type=lambda value:int(value,0),default=None)
    parser.add_argument('--data-rva',action='append',type=lambda value:int(value,0),default=[])
    parser.add_argument('--context',type=int,default=16,choices=range(4,257,4))
    parser.add_argument('--log-symbols',action='store_true',help='report bounded native-image strings containing log_symbols and their nearest preceding data symbols')
    args=parser.parse_args()
    inspect(args.image,args.assert_known_fault,args.code_rva,args.data_rva,args.context,args.log_symbols)
