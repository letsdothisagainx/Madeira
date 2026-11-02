#!/usr/bin/env python3
"""Read an archived IPA's UUID and exact cryptnet COFF/data references."""
import argparse,hashlib,struct,uuid,zipfile
from pathlib import Path

def inspect(ipa,expected,rva):
    with zipfile.ZipFile(ipa) as z:
        native=z.read('Payload/Madeira.app/Madeira.debug.dylib')
        image=z.read('Payload/Madeira.app/i386-windows/cryptnet.dll')
    pos=32;identity=None
    for _ in range(struct.unpack_from('<I',native,16)[0]):
        command,size=struct.unpack_from('<II',native,pos)
        assert size>=8 and pos+size<=len(native)
        if command==0x1b:identity=str(uuid.UUID(bytes=native[pos+8:pos+24])).upper()
        pos+=size
    assert identity==expected.upper(),(identity,expected)
    print('PASS archived native UUID='+identity)
    assert image[:2]==b'MZ';pe=struct.unpack_from('<I',image,0x3c)[0]
    assert image[pe:pe+4]==b'PE\0\0'
    machine,count,stamp,sym,n,opt,flags=struct.unpack_from('<HHIIIHH',image,pe+4)
    assert machine==0x14c and struct.unpack_from('<H',image,pe+24)[0]==0x10b
    base=struct.unpack_from('<I',image,pe+24+28)[0]
    image_size=struct.unpack_from('<I',image,pe+24+56)[0]
    sections=[]
    for i in range(count):
        p=pe+24+opt+40*i;name=image[p:p+8].rstrip(b'\0').decode('ascii','replace')
        vs,at,raw_size,raw=struct.unpack_from('<IIII',image,p+8)
        attrs=struct.unpack_from('<I',image,p+36)[0]
        sections.append((name,at,max(vs,raw_size),raw,raw_size,attrs))
        if at<=rva<at+max(vs,raw_size):print(f'target RVA={rva:#x} section={name} section-rva={at:#x} size={vs:#x} flags={attrs:#x}')
    def data(at,size):
        for _,start,_,raw,raw_size,_ in sections:
            if start<=at and at-start+size<=raw_size:return image[raw+at-start:raw+at-start+size]
        return b''
    print(f'cryptnet sha256={hashlib.sha256(image).hexdigest()} preferred-base={base:#x} image-size={image_size:#x} timestamp={stamp:08x} symbols={n}')
    print('target initial file bytes='+data(rva,16).hex())
    rows=[]
    if sym and n and sym+n*18+4<=len(image):
        strings=sym+n*18;length=struct.unpack_from('<I',image,strings)[0];i=0
        assert 4<=length<=len(image)-strings
        while i<n:
            p=sym+i*18;raw=image[p:p+8]
            if raw[:4]==bytes(4):
                off=struct.unpack_from('<I',raw,4)[0];assert 4<=off<length
                end=image.find(b'\0',strings+off,strings+length);assert end>=0
                name=image[strings+off:end].decode('utf8','replace')
            else:name=raw.rstrip(b'\0').decode('utf8','replace')
            value,section,kind,storage,aux=struct.unpack_from('<IhHBB',image,p+8)
            if 0<section<=count:rows.append((sections[section-1][1]+value,name,kind))
            i+=1+aux
    rows.sort()
    for at,name,kind in rows:
        if abs(at-rva)<=0x80:print(f'COFF {at:#x} {name} kind={kind:#x}')
    # Show real x86 instructions which reference the captured slot, with
    # neighboring instructions and the nearest COFF function when available.
    import capstone
    dis=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);dis.detail=True;dis.skipdata=True
    reports=0
    for name,at,_,raw,raw_size,attrs in sections:
        if not attrs&0x20000000:continue
        instructions=list(dis.disasm(image[raw:raw+raw_size],base+at))
        for i,insn in enumerate(instructions):
            if not insn.id:continue
            refs=[o.mem.disp for o in insn.operands if o.type==capstone.x86.X86_OP_MEM]
            if base+rva not in refs or reports>=12:continue
            reports+=1
            funcs=[row for row in rows if row[2]&0x20 and row[0]<=insn.address-base]
            nearest=funcs[-1] if funcs else None
            print(f'XREF {insn.address:#x} COFF={nearest}')
            for x in instructions[max(0,i-4):i+7]:print(f'  {x.address:#x}: {x.bytes.hex()} {x.mnemonic} {x.op_str}')
    print('direct slot reference windows='+str(reports))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('ipa',type=Path)
    p.add_argument('--expected-uuid',required=True);p.add_argument('--rva',type=lambda x:int(x,0),default=0xc100)
    a=p.parse_args();inspect(a.ipa,a.expected_uuid,a.rva)
