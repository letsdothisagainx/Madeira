#!/usr/bin/env python3
"""Execute real MSVC-target installer against the relocated pinned PE image."""
from pathlib import Path
import hashlib,json,os,struct,subprocess
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_PROT_READ,UC_PROT_WRITE,UC_PROT_EXEC,UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9
here=Path(__file__).resolve().parent
env=dict(os.environ,PYTHONPATH='/workspace/madeira-tools')
zig=os.environ.get('MADEIRA_ZIG','/workspace/madeira-tools/bin/python-zig')
for source in ('installer.cpp','loader.cpp','fixture.cpp'):
    subprocess.run([zig,'c++','-target','x86_64-windows-msvc','-std=c++20','-O2','-fno-exceptions','-fno-rtti','-fno-builtin',
        '-Wall','-Wextra','-Werror','-Wno-unused-command-line-argument','-g0','-c',source,'-o',source+'.obj'],check=True,cwd=here,env=env)
subprocess.run([os.environ.get('MADEIRA_PE_LD','ld'),'-mi386pep','--entry=run_tests','--subsystem=console','--image-base=0x180000000','--no-insert-timestamp',
    '--export-all-symbols','-o','installer-fixture.exe','installer.cpp.obj','fixture.cpp.obj'],check=True,cwd=here)
fixture=(here/'installer-fixture.exe').read_bytes();pe=pefile.PE(data=fixture)
assert not getattr(pe,'DIRECTORY_ENTRY_IMPORT',[])
symbols={e.name.decode():pe.OPTIONAL_HEADER.ImageBase+e.address for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
original=(here.parent/'current-chromehtml.dll').read_bytes()
assert hashlib.sha256(original).hexdigest()=='37f5ddbe874362d729b7cd33504943a9d649d845525afae4bcc2af36ab971f4b'
genuine=pefile.PE(data=original);mapped=bytearray(genuine.get_memory_mapped_image());module=0x280000000
for block in genuine.DIRECTORY_ENTRY_BASERELOC:
    for entry in block.entries:
        if entry.type==10:
            v=struct.unpack_from('<Q',mapped,entry.rva)[0]
            struct.pack_into('<Q',mapped,entry.rva,v+module-genuine.OPTIONAL_HEADER.ImageBase)
def permissions(flags):
    return (UC_PROT_READ if flags&0x40000000 else 0)|(UC_PROT_WRITE if flags&0x80000000 else 0)|(UC_PROT_EXEC if flags&0x20000000 else 0)
def load_pe(uc,base,p,data):
    uc.mem_map(base,(p.OPTIONAL_HEADER.SizeOfImage+4095)&~4095,0);uc.mem_write(base,data)
    uc.mem_protect(base,4096,UC_PROT_READ)
    for s in p.sections:
        n=(max(s.Misc_VirtualSize,s.SizeOfRawData)+4095)&~4095
        if n:uc.mem_protect(base+s.VirtualAddress,n,permissions(s.Characteristics))
out=[]
image_base_rva=genuine.OPTIONAL_HEADER.get_field_absolute_offset('ImageBase')
for mode in range(16):
    uc=Uc(UC_ARCH_X86,UC_MODE_64);base=pe.OPTIONAL_HEADER.ImageBase
    load_pe(uc,base,pe,pe.get_memory_mapped_image());load_pe(uc,module,genuine,bytes(mapped))
    pin=bytearray(original)
    if mode==4:pin[100]^=1
    uc.mem_map(0x900000000,(len(pin)+4095)&~4095,UC_PROT_READ);uc.mem_write(0x900000000,bytes(pin))
    if mode==5:uc.mem_write(module+0x17f428,b'X')
    if mode==7:uc.mem_write(module+0x132340,struct.pack('<Q',module+0x58bf1))
    if mode==10:uc.mem_write(module+0x1000,b'X')
    if mode==11:uc.mem_write(module+image_base_rva,struct.pack('<Q',module))
    if mode==12:uc.mem_protect(module,4096,UC_PROT_READ|UC_PROT_WRITE)
    if mode==13:uc.mem_protect(module+0x1000,4096,UC_PROT_READ)
    if mode==15:uc.mem_write(module+0x121ce0,b'X')
    uc.mem_write(symbols['test_mode'],struct.pack('<I',mode))
    transitions=[]
    def on_code(_uc,address,size,_):
        if address!=symbols['fake_protect']:return
        count=struct.unpack('<I',uc.mem_read(symbols['protect_calls'],4))[0]+1
        addr,n,value=uc.reg_read(UC_X86_REG_RDX),uc.reg_read(UC_X86_REG_R8),uc.reg_read(UC_X86_REG_R9)
        assert value in (2,4) and n==4096 and addr in (module+0x132000,module+0x121000)
        failed=(mode==1 and count==1) or (mode==2 and count==3) or (mode==3 and value==2)
        transitions.append({'page':hex(addr-module),'protection':value,'failed':failed})
        if not failed:uc.mem_protect(addr,n,UC_PROT_READ|(UC_PROT_WRITE if value==4 else 0))
    uc.hook_add(UC_HOOK_CODE,on_code,begin=symbols['fake_protect'],end=symbols['fake_protect'])
    stack,size,stop=0x700000000,0x20000,0x500000000
    uc.mem_map(stack,size,UC_PROT_READ|UC_PROT_WRITE);uc.mem_map(stop,4096,UC_PROT_READ|UC_PROT_EXEC)
    rsp=stack+size-0x28;uc.mem_write(rsp,struct.pack('<Q',stop));uc.reg_write(UC_X86_REG_RSP,rsp)
    uc.emu_start(symbols['run_tests'],stop,count=1500000000)
    result=uc.reg_read(UC_X86_REG_RAX);assert result==0,(mode,result)
    assert uc.mem_read(module+0x1000,0x11ed24)==(b'X'+bytes(mapped[0x1001:0x11fd24]) if mode==10 else bytes(mapped[0x1000:0x11fd24]))
    if mode not in (0,9):
        if mode!=7:assert uc.mem_read(module+0x132340,56)==bytes(mapped[0x132340:0x132378])
        expected_path=(b'X'+bytes(mapped[0x121ce1:0x121d05]) if mode==15 else bytes(mapped[0x121ce0:0x121d05]))
        assert uc.mem_read(module+0x121ce0,37)==expected_path
    else:
        assert uc.mem_read(module+0x121ce0,37)==(b'bin/cef/cef.win64/steamwebhelper.exe\0' if mode==9 else b'bin/cef/cef.win32/steamwebhelper.exe\0')
    stage,rva,expected,actual,ep,ap,actual_size,count,query_flags=struct.unpack('<IIQQIIQII',uc.mem_read(symbols['last_diagnostic'],48))
    diagnostic={'stage':stage,'rva':hex(rva),'expected_bytes':hex(expected),'actual_bytes':hex(actual),
        'expected_protection':ep,'actual_protection':ap,'actual_image_size':actual_size,'byte_count':count,'query_flags':query_flags}
    if mode in (5,7,10,11,12,13,14,15):
        assert not transitions,mode
        assert actual_size==(0x19c001 if mode==14 else 0x19c000)
        if mode==14:assert (expected,actual,count)==(0x19c000,0x19c001,0)
        else:
            assert count==8 and expected!=0
            reference=original[rva:rva+8] if stage in (2,3) else mapped[rva:rva+8]
            assert expected==int.from_bytes(reference,'little'),(mode,diagnostic,reference.hex())
            assert actual==int.from_bytes(uc.mem_read(module+rva,8),'little')
        if mode==11:assert rva==image_base_rva+4 and stage==3
        if mode==12:assert (stage,rva,ep,ap,query_flags)==(2,0,2,4,32)
        if mode==13:assert (stage,rva,ep,ap,query_flags)==(5,0x1000,0x20,2,32)
    out.append({'mode':mode,'result':result,'diagnostic':diagnostic,'data_page_transitions':transitions});print('PASS',mode,flush=True)
report={'scope':'data-only installer fixture; no hook codec or Steam startup activated','compiler':'x86_64-windows-msvc',
    'fixture_sha256':hashlib.sha256(fixture).hexdigest(),'pinned_image_sha256':hashlib.sha256(original).hexdigest(),
    'cases':out,'executable_bytes_modified':False,'rwx_transitions':0,'imports_in_fixture':0}
(here/'results.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='cases'},indent=2))
