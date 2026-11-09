#!/usr/bin/env python3
"""Check actual ARM64EC IosJitAlias COFF code before publishing the PE CPU.

The owned source uses the same cortex-a78/LSE tuning as existing FEXCore.
This gate checks compiled instructions, not option strings: the controlled
floor/state routines must contain 32/64-bit CASAL and release publication,
and may not introduce an exclusive-store retry sequence into RX aliases.
"""
import argparse
from pathlib import Path
import struct

STEMS=('BTCpu64IosAddAliasMapping','IosSubfloorConfigureFloor',
       'IosExtendedSubfloorAdd','IosSubfloorRetireMapping')
REQUIRED=('BTCpu64IosAddAliasMapping','IosSubfloorRetireMapping')
# LLVM BinaryFormat/COFF.h BigObjMagic: the GUID's first fields are little-endian.
BIGOBJ_ID=bytes.fromhex('c7a1bad1eebaa94baf20faf66aa4dcb8')


def controlled_code(data):
    def unpack(fmt,offset):
        size=struct.calcsize(fmt)
        if offset<0 or offset>len(data)-size:raise ValueError('truncated ARM64EC COFF object')
        return struct.unpack_from(fmt,data,offset)
    if data[:4]==b'\0\0\xff\xff':
        version,machine=unpack('<HH',4)
        if version<2 or data[12:28]!=BIGOBJ_ID:raise ValueError('unsupported COFF import/bigobj header')
        sections,symbol_table,symbol_count=unpack('<III',44)
        header,symbol_size=56,20
    else:
        machine,sections,_,symbol_table,symbol_count,optional,_=unpack('<HHIIIHH',0)
        if optional:raise ValueError('expected a COFF object, not a PE executable')
        header,symbol_size=20,18
    if machine not in (0xaa64,0xa641):raise ValueError('IosJitAlias object must contain native ARM64/ARM64EC code')
    if not 0<sections<=4096 or header+sections*40>len(data):raise ValueError('invalid COFF section table')
    section_info=[]
    for index in range(sections):
        entry=header+index*40
        size,raw=unpack('<II',entry+16);flags,=unpack('<I',entry+36)
        if raw>len(data) or size>len(data)-raw:raise ValueError('COFF section outside file')
        section_info.append((size,raw,flags))
    if not symbol_count or symbol_count>1000000 or symbol_table>len(data) or symbol_count*symbol_size>len(data)-symbol_table:
        raise ValueError('invalid COFF symbol table')
    strings=symbol_table+symbol_count*symbol_size
    string_size,=unpack('<I',strings)
    if string_size<4 or string_size>len(data)-strings:raise ValueError('invalid COFF string table')
    def name_at(entry):
        first,offset=unpack('<II',entry)
        if first:
            raw=data[entry:entry+8];return raw.split(b'\0',1)[0].decode('ascii')
        if not 4<=offset<string_size:raise ValueError('COFF name outside string table')
        start=strings+offset;end=data.find(b'\0',start,min(strings+string_size,start+4096))
        if end<0:raise ValueError('unterminated COFF symbol name')
        return data[start:end].decode('ascii')
    functions=[];index=0
    while index<symbol_count:
        entry=symbol_table+index*symbol_size;name=name_at(entry);value,=unpack('<I',entry+8)
        if symbol_size==18:section,kind,storage,aux=unpack('<hHBB',entry+12)
        else:section,kind,storage,aux=unpack('<iHBB',entry+12)
        if aux>symbol_count-index-1:raise ValueError('COFF auxiliary symbol extends past table')
        if kind&0x30==0x20 and 0<section<=sections:
            size,raw,flags=section_info[section-1]
            if flags&0x20000020==0x20000020 and flags&0x40000000 and not flags&0x80000000:
                if value>size or value&3:raise ValueError('unaligned/out-of-range native function symbol')
                length=unpack('<I',entry+symbol_size+4)[0] if aux and storage in (2,3) else 0
                if length>size-value or length&3:raise ValueError('invalid native function auxiliary extent')
                functions.append((name,section,value,length))
        index+=1+aux
    selected=[];found=set();seen=set()
    for name,section,start,length in functions:
        stems={stem for stem in STEMS if stem in name}
        if not stems:continue
        size,raw,_=section_info[section-1]
        if not length:
            length=min((value for _,sec,value,_ in functions if sec==section and value>start),default=size)-start
        if not length or length&3:raise ValueError('missing native function code extent')
        found.update(stems)
        if (section,start,length) not in seen:
            seen.add((section,start,length));selected.append((name,data[raw+start:raw+start+length]))
    if not set(REQUIRED)<=found:raise ValueError('new subfloor control routines missing from native object symbols')
    return selected


def verify_object(path):
    functions=controlled_code(Path(path).read_bytes())
    casal=set();release32=0;instructions=0
    for name,code in functions:
        for (word,) in struct.iter_unpack('<I',code):
            instructions+=1
            single_exclusive=(word&0x3fe07c00)==0x08007c00
            pair_exclusive=(word&0xbfe00000)==0x88200000
            if single_exclusive or pair_exclusive:
                raise ValueError('exclusive-store instruction in controlled subfloor code: '+name)
            if (word&0x3fa07c00)==0x08a07c00 and (word&0x00408000)==0x00408000:
                width=word>>30
                if width in (2,3):casal.add(32 if width==2 else 64)
            if (word&0x3ffffc00)==0x089ffc00 and word>>30==2:release32+=1
    if casal!={32,64}:raise ValueError('compiled subfloor object lacks 32/64-bit LSE CASAL; tuning or code is stale')
    if not release32:raise ValueError('compiled subfloor object lacks STLR32 state publication')
    print(f'PASS ARM64EC subfloor object: controlled-functions={len(functions)} instructions={instructions} CASAL=32,64 STLR32={release32} exclusive-stores=0')
    return {'functions':len(functions),'instructions':instructions,'casal_widths':sorted(casal),'release32':release32}


def build_object(directory):
    candidates=sorted(path for path in Path(directory).rglob('IosJitAlias.cpp.obj') if 'arm64ecfex.dir' in path.parts)
    if len(candidates)!=1:raise ValueError('expected exactly one ARM64EC IosJitAlias.cpp.obj')
    return candidates[0]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    source=parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--object',type=Path)
    source.add_argument('--build-dir',type=Path)
    args=parser.parse_args()
    try:verify_object(args.object or build_object(args.build_dir))
    except (ValueError,UnicodeError,struct.error,OSError) as error:parser.error(str(error))


if __name__=='__main__':main()
