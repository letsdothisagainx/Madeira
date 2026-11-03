#!/usr/bin/env python3
"""Execute MSVC-target provider fixture; OS/stream stand-ins, no Steam launch."""
from pathlib import Path
import hashlib,json,os,struct,subprocess
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_WRITE,UC_PROT_EXEC
from unicorn.x86_const import *
here=Path(__file__).resolve().parent
env=dict(os.environ)
if Path('/workspace/madeira-tools').is_dir():env['PYTHONPATH']='/workspace/madeira-tools'
zig=os.environ.get('MADEIRA_ZIG','/workspace/madeira-tools/bin/python-zig')
build=here/'test-build';build.mkdir(exist_ok=True)
sources=[here/'runtime_provider.cpp',here/'provider_fixture.cpp',here/'proven_map.cpp',
         here.parent/'stream-codec/stream_codec.cpp',here.parent/'wire-codec/wire_codec.cpp',
         here.parent/'stream-install/installer.cpp']
objects=[]
for source in sources:
    obj=build/(source.name+'.obj');objects.append(obj)
    subprocess.run([zig,'c++','-target','x86_64-windows-msvc','-std=c++20','-O2','-ffreestanding',
        '-fno-exceptions','-fno-rtti','-fno-builtin','-fno-strict-aliasing','-Wall','-Wextra','-Werror',
        '-Wno-unused-command-line-argument','-g0','-DMADEIRA_RUNTIME_HAS_PROVEN_MAP=1',
        '-c',str(source),'-o',str(obj)],env=env,check=True)
    subprocess.run([os.environ.get('MADEIRA_PE_OBJCOPY','objcopy'),'--remove-section','.drectve',str(obj)],check=True)
kernel=here/'build/version/KERNEL32.lib';ntdll=here/'build/version/NTDLL.lib'
assert kernel.is_file() and ntdll.is_file(),'run build_runtime.py first'
binary=here/'provider-fixture.exe'
subprocess.run([os.environ.get('MADEIRA_PE_LD','ld'),'-mi386pep','--entry=run_tests','--subsystem=console','--image-base=0x180000000',
    '--no-insert-timestamp','--export-all-symbols','-o',str(binary),*map(str,objects),str(kernel),str(ntdll)],check=True)
raw=binary.read_bytes();pe=pefile.PE(data=raw);base=pe.OPTIONAL_HEADER.ImageBase
symbols={e.name.decode():base+e.address for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
original=(here.parent/'current-chromehtml.dll').read_bytes()
assert hashlib.sha256(original).hexdigest()=='37f5ddbe874362d729b7cd33504943a9d649d845525afae4bcc2af36ab971f4b'
genuine=pefile.PE(data=original);module=0x280000000
mapped=bytearray(genuine.get_memory_mapped_image())
for b in genuine.DIRECTORY_ENTRY_BASERELOC:
    for r in b.entries:
        if r.type==10:
            value=struct.unpack_from('<Q',mapped,r.rva)[0]
            struct.pack_into('<Q',mapped,r.rva,value+module-genuine.OPTIONAL_HEADER.ImageBase)
marker=(here/'cache-contract.txt').read_bytes().replace(b'\r\n',b'\n')
assert marker.startswith(b'MadeiraHtmlIPC-I386-Cache-v1\n')

def prot(flags):
    return (UC_PROT_READ if flags&0x40000000 else 0)|(UC_PROT_WRITE if flags&0x80000000 else 0)|(UC_PROT_EXEC if flags&0x20000000 else 0)

def execute(mode):
    u=Uc(UC_ARCH_X86,UC_MODE_64);regions=[];permissions={}
    def load(address,image,data):
        size=(image.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
        u.mem_map(address,size,UC_PROT_READ|UC_PROT_WRITE);u.mem_write(address,bytes(data))
        u.mem_protect(address,4096,UC_PROT_READ)
        regions.append((address,address+4096,address,2))
        for s in image.sections:
            n=(max(s.Misc_VirtualSize,s.SizeOfRawData)+4095)&~4095
            if not n:continue
            flags=prot(s.Characteristics);assert flags!=7
            u.mem_protect(address+s.VirtualAddress,n,flags)
            win=0x20 if flags&UC_PROT_EXEC else 4 if flags&UC_PROT_WRITE else 2
            regions.append((address+s.VirtualAddress,address+s.VirtualAddress+n,address,win))
    load(base,pe,pe.get_memory_mapped_image());load(module,genuine,mapped)
    callback=0x500000000;stop=callback+0xff0
    u.mem_map(callback,4096,UC_PROT_READ|UC_PROT_EXEC);u.mem_write(callback,b'\xc3'*4096)
    apis={};next_api=callback
    for d in pe.DIRECTORY_ENTRY_IMPORT:
        for e in d.imports:
            name=e.name.decode();apis[next_api]=name;u.mem_write(base+e.address-pe.OPTIONAL_HEADER.ImageBase,struct.pack('<Q',next_api));next_api+=16
    heap_next=0x900000000;allocations={};allocation_calls=0;free_calls=0;sleeps=0;locks=[];logs=[];file_pos={};source_pins=0
    def reg(r):return u.reg_read(r)
    def word(address):return struct.unpack('<I',u.mem_read(address,4))[0]
    def qword(address):return struct.unpack('<Q',u.mem_read(address,8))[0]
    def ret(value):
        sp=reg(UC_X86_REG_RSP);dest=qword(sp);u.reg_write(UC_X86_REG_RAX,value&((1<<64)-1));u.reg_write(UC_X86_REG_RSP,sp+8);u.reg_write(UC_X86_REG_RIP,dest)
    def wide(address):
        b=bytearray()
        for k in range(32768):
            pair=bytes(u.mem_read(address+2*k,2))
            if pair==b'\0\0':return b.decode('utf-16-le')
            b+=pair
        raise AssertionError('unbounded fixture path')
    original_entries={module+r:symbols['fixture_original_'+name] for r,name in (
        (0x58bf0,'destroy'),(0x59100,'available'),(0x590e0,'writable'),(0x593f0,'put'),
        (0x58fa0,'get'),(0x58e60,'clear'),(0x58dc0,'wait'))}
    def on_code(_u,address,size,_):
        nonlocal heap_next,allocation_calls,free_calls,sleeps,source_pins
        if address in original_entries:
            u.reg_write(UC_X86_REG_RIP,original_entries[address]);return
        if address not in apis:return
        name=apis[address];a,b,c,d=[reg(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
        if name=='OutputDebugStringA':ret(0)
        elif name=='GetCurrentProcessId':ret(1234)
        elif name=='GetCurrentThreadId':ret(word(symbols['fixture_thread']))
        elif name=='GetModuleFileNameW':
            value='C:\\Steam\\other.exe' if mode==9 else 'C:\\Steam\\steam.exe'
            u.mem_write(b,(value+'\0').encode('utf-16-le'));ret(len(value))
        elif name=='GetModuleHandleExW':
            assert not any(qword(lock) for lock in locks),'loader API called under provider SRW lock'
            assert a==5 and b in original_entries
            u.mem_write(c,struct.pack('<Q',module));source_pins+=1;ret(1)
        elif name=='GetProcessHeap':ret(0x123)
        elif name=='HeapAlloc':
            allocation_calls+=1
            if mode==2 and allocation_calls==2:ret(0);return
            n=(c+4095)&~4095;pointer=heap_next;heap_next+=n+4096
            u.mem_map(pointer,n,UC_PROT_READ|UC_PROT_WRITE);allocations[pointer]=n
            regions.append((pointer,pointer+n,pointer,4));ret(pointer)
        elif name=='HeapFree':
            assert c in allocations;u.mem_unmap(c,allocations.pop(c));free_calls+=1;ret(1)
        elif name=='TryAcquireSRWLockExclusive':
            if a not in locks:locks.append(a)
            poison=word(symbols['fixture_poison'])
            if (poison==1 and a==locks[0]) or (poison==2 and len(locks)>1 and a==locks[1]):ret(0)
            elif qword(a):ret(0)
            else:u.mem_write(a,struct.pack('<Q',1));ret(1)
        elif name=='ReleaseSRWLockExclusive':
            assert qword(a)==1,('unowned SRW release',hex(a));u.mem_write(a,b'\0'*8);ret(0)
        elif name=='Sleep':
            sleeps+=1;assert a==1;u.reg_write(UC_X86_REG_RIP,symbols['fixture_sleep'])
        elif name=='CreateFileW':
            path=wide(a)
            if path.endswith('.madeira-cache-verified-v1'):
                if mode==10:ret((1<<64)-1);return
                file_pos[101]=0;ret(101)
            elif path=='C:\\Steam\\bin\\chromehtml.dll':file_pos[102]=0;ret(102)
            else:raise AssertionError(('unexpected file',path))
        elif name=='GetFileSizeEx':
            data=marker if a==101 else original;u.mem_write(b,struct.pack('<q',len(data)));ret(1)
        elif name=='ReadFile':
            data=(b'X'+marker[1:] if mode==8 else marker) if a==101 else original
            part=data[file_pos[a]:file_pos[a]+c];file_pos[a]+=len(part);u.mem_write(b,part);u.mem_write(d,struct.pack('<I',len(part)));ret(1)
        elif name=='CloseHandle':ret(1)
        elif name=='GetStdHandle':assert a&0xffffffff==(-12)&0xffffffff;ret(44)
        elif name=='WriteFile':
            line=bytes(u.mem_read(b,c)).decode('ascii');assert len(line)<192 and line.startswith('MADEIRA_HTMLIPC ')
            logs.append(line.strip());u.mem_write(d,struct.pack('<I',c));ret(1)
        elif name=='VirtualQuery':
            region=next((r for r in reversed(regions) if r[0]<=a<r[1]),None)
            if not region:ret(0);return
            start,end,allocation,value=region;page=a&~4095;value=permissions.get(page,value)
            data=struct.pack('<QQIHHQIIII',page,allocation,value,0,0,end-page,0x1000,value,0x1000000,0)
            assert len(data)==48;u.mem_write(b,data);ret(48)
        elif name=='VirtualProtect':
            first=a&~4095;last=(a+b+4095)&~4095
            region=next(r for r in regions if r[0]<=a<r[1]);old=permissions.get(first,region[3]);u.mem_write(d,struct.pack('<I',old))
            assert c in (2,4)
            u.mem_protect(first,last-first,UC_PROT_READ|(UC_PROT_WRITE if c==4 else 0))
            for page in range(first,last,4096):permissions[page]=c
            ret(1)
        elif name=='__C_specific_handler':raise AssertionError('unexpected exception; fixture does not swallow exceptions')
        else:raise AssertionError(('unexpected import',name))
    u.hook_add(UC_HOOK_CODE,on_code)
    for name,value in [('fixture_module',module),('fixture_own_module',base)]:u.mem_write(symbols[name],struct.pack('<Q',value))
    u.mem_write(symbols['fixture_mode'],struct.pack('<I',mode))
    stack=0x700000000;u.mem_map(stack,0x20000,UC_PROT_READ|UC_PROT_WRITE);rsp=stack+0x1ffd8
    u.mem_write(rsp,struct.pack('<Q',stop));u.reg_write(UC_X86_REG_RSP,rsp)
    u.emu_start(symbols['run_tests'],stop,count=100000000)
    assert reg(UC_X86_REG_RIP)==stop,('did not return',mode,hex(reg(UC_X86_REG_RIP)))
    assert reg(UC_X86_REG_RAX)==0,('fixture failure',mode,reg(UC_X86_REG_RAX))
    if mode in (3,4,5):assert sleeps==128,(mode,sleeps)
    if mode==3:assert word(symbols['fixture_closing_reentries'])==128
    if mode in (3,5,7):assert free_calls==0,'quarantined buffers freed'
    if mode==0:
        assert free_calls==6 and allocation_calls==7,(allocation_calls,free_calls)
        assert sum(' installed ' in s for s in logs)==1
        assert sum(' connected ' in s for s in logs)==2
        assert not any(' error=' in s for s in logs)
    if mode==1:assert any(' direction=1 command=53 ' in s for s in logs)
    if mode==12:assert sum(' install-error ' in s for s in logs)==1
    return {'mode':mode,'result':0,'allocation_calls':allocation_calls,'free_calls':free_calls,
            'sleep_calls':sleeps,'source_pins':source_pins,'status_lines':logs}

results=[execute(mode) for mode in range(13)]
report={'scope':'provider source ABI/lifetime fixture with explicit OS/stream stand-ins; no Steam/CEF startup assertion',
        'compiler_target':'x86_64-windows-msvc','fixture_sha256':hashlib.sha256(raw).hexdigest(),
        'actual_genuine_controller_metadata':True,'actual_proven_152_command_map':True,
        'bounded_lock_and_drain_attempts':128,'cases':results,'passed':True}
(here/'provider-results.json').write_text(json.dumps(report,indent=2)+'\n')
for row in results:print('PASS provider mode',row['mode'],flush=True)
