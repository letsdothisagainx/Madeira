#!/usr/bin/env python3
"""Execute real Wine ARM64EC SCM/NDR stub bytes, without simulating SCM replies.
Requires capstone, pefile and unicorn. --producer is the newly built sechost.
The source checkout's DLL is the build-10 negative fixture (never rewritten).
"""
import argparse, struct
from pathlib import Path
import capstone as cs
import pefile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X30, UC_ARM64_REG_SP
root=Path(__file__).resolve().parents[2]
dec=cs.Cs(cs.CS_ARCH_ARM64,cs.CS_MODE_LITTLE_ENDIAN); dec.detail=True
B=0x180000000; R=0x190000000; S=0x200000000; SIZE=0x20000
regs=[UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5]
def instructions(pe,rva,size): return list(dec.disasm(pe.get_data(rva,size),rva))
def native_export(pe,name):
    rva=next(e.address for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name==name.encode())
    code=pe.get_data(rva,14)
    assert code[:10]==bytes.fromhex('488bc448895820555de9'), (name,'not the pinned hybrid FFS')
    return rva+14+struct.unpack_from('<i',code,10)[0]
def slot_of_import(pe,rva):
    ins=instructions(pe,rva,12)
    if len(ins)==3 and [i.mnemonic for i in ins]==['adrp','ldr','br'] and ins[0].op_str.startswith('x16,') and ins[1].op_str.startswith('x16, [x16'):
        return ins[0].operands[1].imm+ins[1].operands[1].mem.disp
    return None

def rpc_producer(pe):
    start=native_export(pe,'OpenSCManagerW')
    for ins in instructions(pe,start,0xe0):
        if ins.mnemonic!='bl': continue
        target=ins.operands[0].imm
        body=instructions(pe,target,0x70)
        # The generated four-argument svcctl stub describes two stack arguments.
        if not any(i.mnemonic=='mov' and i.op_str=='x4, sp' for i in body): continue
        if not any(i.mnemonic=='mov' and i.op_str=='w5, #0x10' for i in body): continue
        for call in body:
            if call.mnemonic=='bl':
                slot=slot_of_import(pe,call.operands[0].imm)
                if slot is not None: return target,slot
    raise AssertionError('cannot locate the real svcctl_OpenSCManagerW producer')
def emulator(sechost,rpc):
    uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    for base,pe in [(B,sechost),(R,rpc)]:
        size=(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
        uc.mem_map(base,size); uc.mem_write(base,pe.get_memory_mapped_image())
    uc.mem_map(S,SIZE);uc.mem_write(S,b'\xcc'*SIZE)
    uc.reg_write(UC_ARM64_REG_SP,S+SIZE-0x100)
    return uc

def execute_native_binding(sechost,rpc,mask,require_eager):
    stub,slot=rpc_producer(sechost)
    if require_eager:
        assert not any(d.dll.lower()==b'rpcrt4.dll' for d in getattr(sechost,'DIRECTORY_ENTRY_DELAY_IMPORT',[])), 'lazy RPC producer shipped'
        imp=next(i for d in sechost.DIRECTORY_ENTRY_IMPORT if d.dll.lower()==b'rpcrt4.dll' for i in d.imports if i.name==b'NdrClientCall2')
        md=sechost.DIRECTORY_ENTRY_LOAD_CONFIG.struct.CHPEMetadataPointer-sechost.OPTIONAL_HEADER.ImageBase
        aux=struct.unpack_from('<I',sechost.get_data(md,80),44)[0]
        expected=aux+(imp.address-sechost.OPTIONAL_HEADER.ImageBase-sechost.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress)
        assert slot==expected, (hex(slot),hex(expected),'call must use the normal native auxiliary IAT')
    entry=native_export(rpc,'NdrClientCall2')
    c_entry=native_export(rpc,'NdrpClientCall2')
    uc=emulator(sechost,rpc)
    # Model the patched normal-import + native auxiliary-IAT binding.
    # The separate loader regression validates the actual shared RVA arithmetic;
    # this machine-code test checks the binding preserves the producer ABI.
    uc.mem_write(B+slot,struct.pack('<Q',R+entry))
    out=S+0x1000; uc.mem_write(out,struct.pack('<Q',0xa5a5a5a5a5a5a5a5))
    for reg,value in zip(regs,[0,0,mask,out,0,0]): uc.reg_write(reg,value)
    uc.reg_write(UC_ARM64_REG_X30,0xdead0000)
    recorded={}
    def hook(u,address,size,_):
        if address==R+entry:
            window=u.reg_read(UC_ARM64_REG_X4)
            assert u.reg_read(UC_ARM64_REG_X5)==16
            # Access is a DWORD: the ABI does not promise zeroed slot padding.
            assert struct.unpack('<I',u.mem_read(window,4))[0]==mask
            assert struct.unpack('<Q',u.mem_read(window+8,8))[0]==out
            fmt=u.reg_read(UC_ARM64_REG_X1)
            data=bytes(u.mem_read(fmt,62))
            assert struct.unpack_from('<H',data,6)[0]==15 # ROpenSCManagerW
            assert data[21]==5 # four arguments plus the NDR return descriptor
            p=22+data[22]
            offsets=[struct.unpack_from('<H',data,p+6*i+2)[0] for i in range(5)]
            assert offsets==[0,8,16,24,32], offsets
            recorded['window']=window
        if address==R+c_entry:
            stack=u.reg_read(UC_ARM64_REG_X2)
            a=struct.unpack('<4Q',u.mem_read(stack,32))
            assert a[0:2]==(0,0) and a[2]&0xffffffff==mask and a[3]==out, a
            assert stack==recorded['window']-16
            assert struct.unpack('<Q',u.mem_read(out,8))[0]==0xa5a5a5a5a5a5a5a5
            recorded['checked']=True
            u.emu_stop() # Do not run NDR or manufacture a server response.
    uc.hook_add(UC_HOOK_CODE,hook)
    uc.emu_start(B+stub,0,count=200)
    assert recorded.get('checked'), 'NdrpClientCall2 was not reached'

def reproduce_descriptor_leak(old,rpc):
    _,slot=rpc_producer(old)
    lazy_va=struct.unpack('<Q',old.get_data(slot,8))[0]
    body=instructions(old,lazy_va-old.OPTIONAL_HEADER.ImageBase,24)
    page=next(i.operands[1].imm for i in body if i.mnemonic=='adrp' and i.op_str.startswith('x10,'))
    off=next(i.operands[2].imm for i in body if i.mnemonic=='add' and i.op_str.startswith('x10, x10,'))
    exit_rva=page+off
    uc=emulator(old,rpc);window=S+0x2000;out=S+0x1000
    uc.mem_write(window,struct.pack('<QQ',1,out))
    uc.reg_write(UC_ARM64_REG_X4,window);uc.reg_write(UC_ARM64_REG_X5,16)
    seen=[]
    def hook(u,address,size,_):
        ins=list(dec.disasm(bytes(u.mem_read(address,size)),address))[0]
        if ins.mnemonic=='blr':
            # ExitToX64 pushes an 8-byte return address, as in FEX Module.S.
            guest_rsp=u.reg_read(UC_ARM64_REG_SP)-8
            pair=struct.unpack('<QQ',u.mem_read(guest_rsp+0x28,16))
            assert pair==(window,16), pair
            assert pair!=(1,out)
            seen.append(pair);u.emu_stop()
    uc.hook_add(UC_HOOK_CODE,hook)
    uc.emu_start(B+exit_rva,0,count=40)
    assert seen
    print('PASS build-10 compiled lazy exit thunk reproduces descriptor-as-arguments (pointer, 0x10), not a slot shift')

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--producer',type=Path);ap.add_argument('--runtime',type=Path);args=ap.parse_args()
    old=pefile.PE(str(root/'app/Madeira/arm64ec-windows/sechost.dll'))
    rpc=pefile.PE(str(args.runtime or root/'app/Madeira/arm64ec-windows/rpcrt4.dll'))
    reproduce_descriptor_leak(old,rpc)
    producer=pefile.PE(str(args.producer)) if args.producer else old
    for mask in [1,0x10,0xf003f,0x12345678]: execute_native_binding(producer,rpc,mask,bool(args.producer))
    print('PASS real SCM producer -> native NdrClientCall2 -> NdrpClientCall2: scalar/output pointer and all four argument positions preserved')
