#!/usr/bin/env python3
"""Verify genuine source-built registration utilities in each architecture farm.

This checks executable ABI, hybrid metadata, imports and byte provenance. It
does not assert that an official DirectX installer or its registration succeeds.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

FARMS={'aarch64-windows':0xaa64,'arm64ec-windows':0x8664,'i386-windows':0x14c}
PROGRAMS=('regsvr32','rundll32')
MANIFEST='arm64ec-windows/madeira-system-programs.json'
MARKER=b'[process-image-lookup-v1]'


def digest(data):return hashlib.sha256(data).hexdigest()


def read(path,limit=64<<20):
    path=Path(path)
    assert path.is_file() and not path.is_symlink(),'missing or symlinked system program input: '+str(path)
    assert path.stat().st_size<=limit,'oversized system program input'
    data=path.read_bytes();assert len(data)<=limit,'system program input grew while reading'
    return data


def unique_object(pairs):
    result={}
    for key,value in pairs:
        assert key not in result,'duplicate system program manifest key'
        result[key]=value
    return result


def inspect(data,farm,program=None,required_export=None):
    def unpack(fmt,offset):
        size=struct.calcsize(fmt)
        assert 0<=offset<=len(data) and size<=len(data)-offset,'truncated PE metadata'
        return struct.unpack_from(fmt,data,offset)
    assert data[:2]==b'MZ','invalid DOS signature'
    pe,=unpack('<I',0x3c);assert data[pe:pe+4]==b'PE\0\0','invalid PE signature'
    machine,count,_,_,_,optional_size,flags=unpack('<HHIIIHH',pe+4)
    expected=FARMS[farm]
    assert machine==expected or (farm=='arm64ec-windows' and machine==0xa641),'system program machine mismatch'
    opt=pe+24;magic,=unpack('<H',opt)
    assert magic==(0x10b if expected==0x14c else 0x20b),'system program optional-header ABI mismatch'
    assert optional_size>=(224 if magic==0x10b else 240),'short PE optional header'
    image_size,=unpack('<I',opt+56);entry,=unpack('<I',opt+16)
    assert image_size and 0<count<=96,'invalid PE image/section count'
    if program:
        assert flags&2 and not flags&0x2000,'system program must be a genuine executable, not a DLL'
        assert unpack('<H',opt+68)[0]==2,'system program must retain the Wine GUI subsystem'
    if required_export is not None:
        assert not program and flags&0x2000,'required API export must belong to a DLL'
    sections=[];table=opt+optional_size
    for i in range(count):
        off=table+40*i;size,rva,raw_size,raw=unpack('<IIII',off+8);section_flags,=unpack('<I',off+36)
        extent=max(size,raw_size)
        assert extent and rva<=image_size and extent<=image_size-rva,'section outside PE image'
        assert raw<=len(data) and raw_size<=len(data)-raw,'section outside PE file'
        assert not any(rva<base+span and base<rva+extent for base,span,_,_,_ in sections),'overlapping PE sections'
        sections.append((rva,extent,raw,raw_size,section_flags))
    def at(rva,size):
        for base,_,raw,raw_size,_ in sections:
            if base<=rva and rva-base+size<=raw_size:return raw+rva-base
        raise AssertionError('PE metadata is not file-backed')
    def string(rva,lower=True):
        result=bytearray()
        for i in range(256):
            value=data[at(rva+i,1)]
            if not value:
                text=result.decode('ascii')
                return text.lower() if lower else text
            result.append(value)
        raise AssertionError('unterminated import name')
    if program:
        assert any(base<=entry and entry+4<=base+raw_size and flags&0x20000000 and flags&0x40000000 and not flags&0x80000000
                   for base,_,_,raw_size,flags in sections),'system program entry is not file-backed RX code'
    dirs=opt+(96 if magic==0x10b else 112)
    directory_count,=unpack('<I',dirs-4);assert directory_count>=11,'missing PE data directories'
    imports=[];rva,size=unpack('<II',dirs+8)
    if rva:
        assert size>=20,'short system program import directory'
        terminated=False
        for i in range(min(size//20,1024)):
            fields=unpack('<IIIII',at(rva+i*20,20))
            if not any(fields):terminated=True;break
            assert fields[3] and fields[4],'malformed system program import descriptor'
            imports.append(string(fields[3]))
        assert terminated and len(imports)==len(set(imports)),'unterminated or duplicate system program imports'
    else:assert not program,'system program import directory missing'
    if program:
        required={'kernelbase.dll','user32.dll'}
        if program=='regsvr32':required.add('ole32.dll')
        assert required<=set(imports),'stock system program imports missing'
    export_target=None
    if required_export is not None:
        directory,directory_size=unpack('<II',dirs)
        assert directory and directory_size>=40 and directory<=image_size and directory_size<=image_size-directory,'required export directory outside image'
        fields=unpack('<IIHHIIIIIII',at(directory,40))
        functions,names,addresses,strings,ordinals=fields[6:]
        assert 0<names<=functions<=65536,'invalid required API export counts'
        at(addresses,functions*4);at(strings,names*4);at(ordinals,names*2)
        seen=set()
        for i in range(names):
            name=string(unpack('<I',at(strings+i*4,4))[0],lower=False)
            assert name and name not in seen,'ambiguous or empty API export name'
            seen.add(name)
            ordinal,=unpack('<H',at(ordinals+i*2,2))
            assert ordinal<functions,'invalid required API export ordinal'
            if name!=required_export:continue
            export_target,=unpack('<I',at(addresses+ordinal*4,4))
            assert export_target and not directory<=export_target<directory+directory_size,'required API export is null or forwarded'
            assert any(base<=export_target and export_target+4<=base+raw_size and flags&0x20000000 and
                       flags&0x40000000 and not flags&0x80000000
                       for base,_,_,raw_size,flags in sections),'required API export is not file-backed RX code'
            at(export_target,4)
        assert export_target is not None,'required API export missing'
    if farm=='arm64ec-windows':
        config_rva,config_size=unpack('<II',dirs+10*8)
        assert config_rva and config_size>=208,'ARM64EC program lacks hybrid load configuration'
        config=at(config_rva,208);assert unpack('<I',config)[0]>=208,'short hybrid load configuration'
        base,=unpack('<Q',opt+24);metadata,=unpack('<Q',config+200)
        assert metadata>=base,'hybrid metadata VA below image'
        version,code_map,code_count=unpack('<III',at(metadata-base,12))
        assert version in(1,2) and 0<code_count<=65536,'invalid hybrid code map'
        native=False
        for i in range(code_count):
            encoded,span=unpack('<II',at(code_map+i*8,8));start=encoded&~3
            if encoded&3==1 and span:
                assert any(b<=start and start+span<=b+rs and f&0x20000000 and f&0x40000000 and not f&0x80000000
                           for b,_,_,rs,f in sections),'hybrid native range must be file-backed RX'
                native=True
        assert native,'AMD64-only executable is not an ARM64EC system program'
    result={'machine':machine,'imports':sorted(imports),'sha256':digest(data),'bytes':len(data)}
    if required_export is not None:result.update(export_name=required_export,export_rva=export_target)
    return result


def source_inputs(source):
    result={}
    for program in PROGRAMS:
        directory=source/'programs'/program
        for path in sorted(directory.rglob('*')):
            if path.is_file() and (path.name=='Makefile.in' or path.suffix in('.c','.h','.rc','.in')):
                result[path.relative_to(source).as_posix()]=digest(read(path,2<<20))
        assert 'programs/'+program+'/'+program+'.c' in result,'stock program source missing'
    return result


def check(root,source=None,write=False,app=None,ipa=None):
    records={}
    for farm in FARMS:
        available={file.name.lower():file for file in(root/farm).iterdir() if file.is_file()}
        checked=set()
        for program in PROGRAMS:
            relative=farm+'/'+program+'.exe';file=root/relative
            assert file.is_file(),f'missing system program: {relative}'
            records[relative]=inspect(read(file),farm,program)
            for dependency in records[relative]['imports']:
                # Stock utility recipes name concrete Wine DLLs. A merely
                # API-set-shaped unknown import is not proof of resolution.
                assert dependency in available,f'missing {farm} system-program import: {dependency}'
                if dependency in available and dependency not in checked:
                    inspect(read(available[dependency]),farm)
                    checked.add(dependency)
        kernelbase=read(root/farm/'kernelbase.dll')
        inspect(kernelbase,farm)
        assert MARKER in kernelbase,f'stale {farm} failed-image attribution'
    if write:
        assert source is not None,'source tree required for build provenance'
        path=root/MANIFEST;pending=path.with_suffix('.json.pending')
        assert not path.is_symlink() and not pending.exists() and not pending.is_symlink(),'refusing unowned system program manifest output'
        pending.write_text(json.dumps({'recipe':1,'programs':records,'sources':source_inputs(source)},sort_keys=True,indent=2)+'\n')
        pending.replace(path)
    manifest=read(root/MANIFEST,1<<20);metadata=json.loads(manifest,object_pairs_hook=unique_object)
    assert metadata.get('recipe')==1 and metadata.get('programs')==records,'stale system program build manifest'
    if source is not None:assert metadata.get('sources')==source_inputs(source),'system program source provenance changed'
    paths=[*records,MANIFEST,*[farm+'/kernelbase.dll' for farm in FARMS]]
    if app:
        for relative in paths:assert read(app/relative)==read(root/relative),f'stale app system program: {relative}'
    if ipa:
        with zipfile.ZipFile(ipa) as archive:
            for relative in paths:
                name='Payload/Madeira.app/'+relative;entries=[entry for entry in archive.infolist() if entry.filename==name]
                assert len(entries)==1,'missing or duplicate IPA system program: '+relative
                expected=read(root/relative);assert entries[0].file_size==len(expected),'stale IPA system program length: '+relative
                with archive.open(entries[0]) as stream:assert stream.read(len(expected)+1)==expected,f'stale IPA system program: {relative}'
    print('PASS stock registration utilities: correct A64/ARM64EC/I386 executable ABIs, hybrid code, imports, source/build provenance and requested package copies; no installer completion claim')
    return metadata


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--source-root',type=Path)
    parser.add_argument('--write-manifest',action='store_true')
    parser.add_argument('--app',type=Path)
    parser.add_argument('--ipa',type=Path)
    args=parser.parse_args();check(args.root,args.source_root,args.write_manifest,args.app,args.ipa)
