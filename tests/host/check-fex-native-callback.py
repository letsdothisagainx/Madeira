#!/usr/bin/env python3
"""Exercise the production Unix-to-PE retirement bridge and nested ARM64 syscalls."""
import argparse
import ast
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / 'build/ntdll-unix/signal_arm64_ios.c').read_text()


def balanced(text, start, opening='{', closing='}'):
    begin = text.index(opening, start)
    depth = 0
    pattern = r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|[{}()]'
    for match in re.finditer(pattern, text[begin:], re.S):
        token = match[0]
        if token == opening:
            depth += 1
        elif token == closing:
            depth -= 1
            if not depth:
                return text[start:begin + match.end()]
    raise AssertionError('unclosed production body')


bridge = balanced(source, source.index('unsigned int ios_call_fex_callback('))
args_struct = balanced(source, source.index('struct ios_fex_callback_args\n')) + ';'
layout = balanced(source, source.index('struct callback_stack_layout\n')) + ';'
code = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
typedef uint64_t ULONG64; typedef uintptr_t ULONG_PTR;
typedef uint32_t ULONG; typedef unsigned char BYTE; typedef size_t SIZE_T;
typedef struct {struct {void *StackBase,*StackLimit;} Tib; void *Peb;} TEB;
struct syscall_frame {ULONG64 sp,lr,pc;};
struct thread_data {void *kernel_stack;};
enum {MADEIRA_FEX_THREAD_RETIRE_REFUSED=0x400};
static const size_t min_kernel_stack=0x1000,kernel_stack_size=0x100000;
static TEB owner,foreign; static TEB *current=&owner;
static struct syscall_frame frame_storage,*current_frame=&frame_storage;
static struct thread_data thread;
static int invalid_kernel;
static TEB *NtCurrentTeb(void){return current;}
static struct syscall_frame *get_syscall_frame(void){return current_frame;}
static struct thread_data *ntdll_get_thread_data(void){
 uintptr_t local=(uintptr_t)__builtin_frame_address(0);
 thread.kernel_stack=(void *)(invalid_kernel?local+kernel_stack_size:local-kernel_stack_size/2);
 return &thread;
}
static unsigned callbacks,transitions,logs;
static unsigned callback(void*t,unsigned long long*s,unsigned*d,unsigned*f){
 assert(t==&owner);callbacks++;*s=0xb71001140ull;*d=0;*f=3;return 0x100;
}
static void ios_fex_callback_dispatcher(void){}
static int diagnostic(int fd,const char*fmt,...){assert(fd==2&&strstr(fmt,"[fex-callback-v2]"));logs++;return 0;}
#define dprintf diagnostic
''' + layout + '\n' + args_struct + r'''
static unsigned call_user_mode_callback(ULONG64 sp,void**out,ULONG*len,void*func,TEB*teb){
 assert(teb==&owner&&func==ios_fex_callback_dispatcher&&!(sp&15));transitions++;
 struct callback_stack_layout *stack=(void *)(uintptr_t)sp;
 assert(stack->args==stack->args_data&&stack->len==sizeof(struct ios_fex_callback_args));
 assert(stack->lr==frame_storage.lr&&stack->pc==frame_storage.pc&&stack->sp==frame_storage.sp);
 struct ios_fex_callback_args args;memcpy(&args,stack->args,sizeof(args));
 assert(args.callback==callback&&args.teb==teb);
 *out=NULL;*len=0;return args.callback(args.teb,args.state,args.depth,args.flags);
}
''' + bridge + r'''
int main(void){
 _Alignas(16) unsigned char user[0x4000];memset(user,0xa5,sizeof(user));
 owner.Tib.StackBase=user+sizeof(user);owner.Tib.StackLimit=user;
 frame_storage=(struct syscall_frame){(uintptr_t)(user+sizeof(user)),0x12345678,0x300123004};
 const struct syscall_frame saved=frame_storage;
 unsigned long long state=0;unsigned depth=9,flags=9;
 for(unsigned i=0;i<64;i++){
  assert(ios_call_fex_callback(callback,&owner,&state,&depth,&flags)==0x100);
  assert(state==0xb71001140ull&&!depth&&flags==3&&!memcmp(&saved,&frame_storage,sizeof(saved)));
 }
 assert(callbacks==64&&transitions==64);
 for(unsigned i=0;i<20;i++)assert(ios_call_fex_callback(callback,&foreign,&state,&depth,&flags)==0x400);
 current=NULL;assert(ios_call_fex_callback(callback,&owner,&state,&depth,&flags)==0x400);current=&owner;
 current_frame=NULL;assert(ios_call_fex_callback(callback,&owner,&state,&depth,&flags)==0x400);current_frame=&frame_storage;
 assert(ios_call_fex_callback(NULL,&owner,&state,&depth,&flags)==0x400);
 frame_storage.sp=(uintptr_t)user+16;assert(ios_call_fex_callback(callback,&owner,&state,&depth,&flags)==0x400);
 frame_storage.sp=(uintptr_t)user+sizeof(user)+16;assert(ios_call_fex_callback(callback,&owner,&state,&depth,&flags)==0x400);
 frame_storage.sp=16;assert(ios_call_fex_callback(callback,&owner,&state,&depth,&flags)==0x400);
 frame_storage=saved;invalid_kernel=1;
 assert(ios_call_fex_callback(callback,&owner,&state,&depth,&flags)==0x400);
 assert(callbacks==64&&transitions==64&&logs==16);
 puts("PASS production FEX callback wrapper: real user-stack layout, owner/stack guards, results and 64 repeats; invalid/foreign/kernel-stack requests never invoke PE callback");
}
'''


def assembly(name):
    begin = source.index('__ASM_GLOBAL_FUNC( ' + name + ',')
    text = balanced(source, begin, '(', ')')
    # Execute the common native dispatcher; TLS recovery and diagnostic ring
    # instrumentation are covered by the existing x18/compiled-image checks.
    text = re.sub(r'#ifdef WINE_IOS\n.*?#endif', '', text, flags=re.S)
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    text = re.sub(r'__ASM_CFI\w*\([^)]*\)', '', text)
    text = re.sub(r'__ASM_NAME\("([^"]+)"\)', lambda m: '"' + m[1] + '"', text)
    text = re.sub(r'__ASM_LOCAL_LABEL\("([^"]+)"\)', lambda m: '"local_' + m[1] + '"', text)
    return name + ':\n' + ''.join(ast.literal_eval(t) for t in re.findall(r'"(?:\\.|[^"\\])*"', text)) + '\n'


def elf_text(data):
    shoff = struct.unpack_from('<Q', data, 40)[0]
    entsize, count, strings = struct.unpack_from('<3H', data, 58)
    headers = [struct.unpack_from('<2I4Q2I2Q', data, shoff + i * entsize) for i in range(count)]
    string_section = headers[strings]
    names = data[string_section[4]:string_section[4] + string_section[5]]
    sections = {names[h[0]:names.index(b'\0', h[0])].decode(): h for h in headers}
    text = sections['.text']; symbols = sections['.symtab']; strings = headers[symbols[6]]
    names = data[strings[4]:strings[4]+strings[5]]
    result = {}
    for pos in range(symbols[4], symbols[4]+symbols[5], symbols[9]):
        name, _, _, section, value, _ = struct.unpack_from('<IBBHQQ', data, pos)
        if name and section:
            result[names[name:names.index(b'\0',name)].decode()] = value
    assert not any(n.startswith('.rela.text') and h[5] for n,h in sections.items()), 'unresolved assembly relocation'
    return data[text[4]:text[4]+text[5]], result


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--emulate', action='store_true')
args = parser.parse_args()
with tempfile.TemporaryDirectory(prefix='madeira-fex-callback-') as directory:
    path = Path(directory)
    (path/'check.c').write_text(code)
    subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all',
                    str(path/'check.c'),'-o',str(path/'check')],check=True)
    # Heap-backed ASan fake stacks do not model Wine's real kernel-stack
    # membership check; ordinary address/undefined-behavior checks remain on.
    subprocess.run([str(path/'check')],check=True,
                   env=dict(os.environ,ASAN_OPTIONS='detect_stack_use_after_return=0'))
    if not args.emulate:
        raise SystemExit(0)
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UcError
    from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X18, UC_ARM64_REG_X29,
        UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC, UC_ARM64_REG_NZCV,
        UC_ARM64_REG_FPCR, UC_ARM64_REG_FPSR, UC_ARM64_REG_Q0)

    asm = '.text\n' + '\n'.join(assembly(n) for n in (
        'call_user_mode_callback', 'ios_fex_callback_dispatcher', 'user_mode_callback_return',
        '__wine_syscall_dispatcher'))
    asm += r'''
pe_callback:
 stp x29,x30,[sp,#-0x60]!
 mov x29,sp
 stp x19,x20,[sp,#0x10]
 stp x21,x22,[sp,#0x20]
 stp x23,x24,[sp,#0x30]
 mov x19,x0
 mov x20,x1
 mov x21,x2
 mov x22,x3
 bl nt_free_stub
 bl nt_free_stub
 mov x9,#0x1140
 movk x9,#0xb710,lsl#16
 str x9,[x20]
 str wzr,[x21]
 mov w9,#3
 str w9,[x22]
 mov w0,#0x100
 ldp x23,x24,[sp,#0x30]
 ldp x21,x22,[sp,#0x20]
 ldp x19,x20,[sp,#0x10]
 ldp x29,x30,[sp],#0x60
 ret
nt_free_stub:
 mov x8,#0
 mov x9,x30
 adr x16,__wine_syscall_dispatcher
 blr x16
 ret
service_free:
 sub sp,sp,#0x300
'''
    # An ordinary handler's local scratch storage overlaps a directly called
    # PE callback on the existing kernel stack, reproducing its destroyed LR.
    asm += ''.join(f' str xzr,[sp,#{i}]\n' for i in range(0,0x300,8))
    asm += r'''
 add sp,sp,#0x300
 mov x0,#1
 ret
trace_syscall:
trace_sysret:
trace_usercall:
trace_userret:
 ret
syscall_dispatcher_return_slowpath:
 brk #1
stop:
 nop
'''
    (path/'check.s').write_text(asm)
    compiler = shlex.split(os.environ.get('ASM_CC', shutil.which('clang') or 'clang'))
    subprocess.run(compiler+['-target','aarch64-linux-gnu','-c',str(path/'check.s'),'-o',str(path/'check.o')],check=True)
    machine, symbols = elf_text((path/'check.o').read_bytes())
    fixed_pack, old_pack = struct.pack('<I',0xb3607c41), struct.pack('<I',0xb3407c41)
    clear_flags, nop = struct.pack('<I',0xb9010c3f), struct.pack('<I',0xd503201f)
    assert machine.count(fixed_pack)==1 and machine.count(clear_flags)==1
    base, teb, kernel, user, output, table = 0x100000,0x200000,0x300000,0x400000,0x500000,0x600000
    addr = lambda name: base+symbols[name]

    def run(safe, owner, trace, repeats=1, packing_negative=False, clear_negative=False,
            clear_x18=False, teb_negative=False):
        mu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        for start,size in ((base,0x10000),(teb,0x10000),(kernel,0x20000),(user,0x20000),(output,0x10000),(table,0x10000)):
            mu.mem_map(start,size)
        mu.mem_write(base,machine)
        if packing_negative:
            # Production helper's previous BFI #0 destroyed nonzero FP state.
            mu.mem_write(base,machine.replace(fixed_pack,old_pack))
        if clear_negative:
            mu.mem_write(base,machine.replace(clear_flags,nop))
        if teb_negative:
            # Restore the exact old silent TEB copy. Unlike a TEB memory
            # access, MOV from a cleared x18 never reaches Mach recovery.
            location=symbols['ios_fex_callback_dispatcher']+4
            assert struct.unpack_from('<I',machine,location)[0]==0xf9400613  # ldr x19,[x16,#8]
            mu.mem_write(base+location,struct.pack('<I',0xaa1203f3))  # mov x19,x18
        mu.mem_write(kernel,b'\x5a'*0x20000)  # reused, nonzero kernel stack
        frame=kernel+0x18000
        outer=bytearray(b'\xa5'*0x330)
        struct.pack_into('<I',outer,0x10c,0)
        mu.mem_write(frame,bytes(outer))
        mu.mem_write(teb+0x60,struct.pack('<Q',owner))
        mu.mem_write(teb+0x370,struct.pack('<QQI',table,frame,trace))
        mu.mem_write(table,struct.pack('<QQQQ',table+0x100,0,1,table+0x200))
        mu.mem_write(table+0x100,struct.pack('<Q',addr('service_free')))
        mu.mem_write(table+0x200,b'\0')
        user_sp=user+0x18000
        mu.mem_write(user_sp,struct.pack('<Q',user_sp+0x30))
        mu.mem_write(user_sp+0x30,struct.pack('<5Q',addr('pe_callback'),teb,output+0x100,output+0x108,output+0x10c))
        stop=addr('stop')
        for iteration in range(repeats):
            saved_regs={r:0x91000000+r for r in range(19,30)}
            for r,value in saved_regs.items():
                mu.reg_write(UC_ARM64_REG_X29 if r==29 else UC_ARM64_REG_X0+r,value)
            mu.reg_write(UC_ARM64_REG_X18,teb)
            mu.reg_write(UC_ARM64_REG_X30,stop)
            mu.reg_write(UC_ARM64_REG_NZCV,0xa0000000)
            mu.reg_write(UC_ARM64_REG_FPCR,0x400000)
            mu.reg_write(UC_ARM64_REG_FPSR,0x8000000)
            for r in range(8,16): mu.reg_write(UC_ARM64_REG_Q0+r,0x123400000000+r)
            initial_sp=frame-0x100 if not safe else frame-0x800
            mu.reg_write(UC_ARM64_REG_SP,initial_sp)
            values=[user_sp,output,output+8,addr('ios_fex_callback_dispatcher'),teb] if safe else [teb,output+0x100,output+0x108,output+0x10c]
            for r,value in enumerate(values):mu.reg_write(UC_ARM64_REG_X0+r,value)
            visits=[]; syscall_flags=[]; invalid_accesses=[]; recovered_teb_accesses=[]
            def observe(m,a,n,u):
                if clear_x18:
                    # iOS can discard its reserved x18 at every context
                    # switch, including between adjacent transition insns.
                    m.reg_write(UC_ARM64_REG_X18,0)
                    word=struct.unpack('<I',m.mem_read(a,4))[0]
                    kind=word&0xffc00000
                    if ((word>>5)&31)==18 and kind in (0xf9400000,0xb9400000,0xf9000000,0xb9000000):
                        # Model the existing Mach handler's unsigned TEB
                        # LDR/STR recovery. Execute every other instruction,
                        # especially nonfaulting MOV, as actual ARM64 code.
                        width=8 if word&(1<<30) else 4
                        offset=((word>>10)&0xfff)*width
                        register=word&31
                        if kind in (0xf9400000,0xb9400000):
                            value=int.from_bytes(m.mem_read(teb+offset,width),'little')
                            if register!=31:m.reg_write(UC_ARM64_REG_X0+register,value)
                        else:
                            value=0 if register==31 else m.reg_read(UC_ARM64_REG_X0+register)
                            m.mem_write(teb+offset,(value&((1<<(width*8))-1)).to_bytes(width,'little'))
                        recovered_teb_accesses.append(a)
                        m.reg_write(UC_ARM64_REG_PC,a+4)
                        return
                if a==addr('pe_callback') and safe:
                    current_frame=struct.unpack('<Q',m.mem_read(teb+0x378,8))[0]
                    assert struct.unpack('<I',m.mem_read(current_frame+0x10c,4))[0]==0, 'fresh-frame restore flags uninitialized'
                if a==addr('service_free'):visits.append(a)
                if a==addr('nt_free_stub'):syscall_flags.append(m.reg_read(UC_ARM64_REG_NZCV))
                if a==addr('nt_free_stub')+16:
                    assert m.reg_read(UC_ARM64_REG_NZCV)==syscall_flags[-1], 'syscall changed incoming flags'
            def invalid(m,access,address,size,value,user_data):
                invalid_accesses.append(address)
                return False  # Never map the null page or suppress a fault.
            hook=mu.hook_add(UC_HOOK_CODE,observe)
            invalid_hook=mu.hook_add(UC_HOOK_MEM_INVALID,invalid)
            try:mu.emu_start(addr('call_user_mode_callback' if safe else 'pe_callback'),stop,count=5000)
            except UcError:
                if teb_negative:
                    assert clear_x18 and invalid_accesses==[0x378]
                    assert mu.reg_read(UC_ARM64_REG_PC)==addr('user_mode_callback_return')
                    assert mu.reg_read(UC_ARM64_REG_X0+3)==0 and mu.reg_read(UC_ARM64_REG_X0+2)==0x100
                    assert len(visits)==2 and recovered_teb_accesses
                    return
                if safe:raise
            mu.hook_del(hook)
            mu.hook_del(invalid_hook)
            assert not teb_negative,'old x18 copy unexpectedly returned safely'
            if not safe:
                assert mu.reg_read(UC_ARM64_REG_PC)==0,'negative control must reproduce null execution'
                return
            assert mu.reg_read(UC_ARM64_REG_PC)==stop and mu.reg_read(UC_ARM64_REG_SP)==initial_sp
            assert mu.reg_read(UC_ARM64_REG_X30)==stop
            assert mu.reg_read(UC_ARM64_REG_X0)==0x100 and len(visits)==2
            assert mu.mem_read(teb+0x378,8)==struct.pack('<Q',frame)
            assert mu.mem_read(frame,0x330)==bytes(outer),'outer syscall frame mutated'
            assert mu.reg_read(UC_ARM64_REG_FPCR)==0x400000 and mu.reg_read(UC_ARM64_REG_FPSR)==0x8000000
            for r,value in saved_regs.items():assert mu.reg_read(UC_ARM64_REG_X29 if r==29 else UC_ARM64_REG_X0+r)==value
            for r in range(8,16):assert mu.reg_read(UC_ARM64_REG_Q0+r)&((1<<64)-1)==0x123400000000+r
            assert mu.mem_read(output+0x100,16)==struct.pack('<QII',0xb7101140,0,3)
            assert mu.mem_read(teb+0x60,8)==struct.pack('<Q',owner)
            if clear_x18:assert recovered_teb_accesses,'x18 stress did not exercise Mach TEB recovery'

    run(False,0x400310000,0)
    for owner in (0x400310000,0x500310000):
        for trace in (0,1):
            run(True,owner,trace,32)
            run(True,owner,trace,32,clear_x18=True)
            run(True,owner,trace,clear_x18=True,teb_negative=True)
    try:run(True,0x400310000,0,packing_negative=True)
    except AssertionError:pass
    else:raise AssertionError('old floating-point packing unexpectedly preserved FPCR/FPSR')
    try:run(True,0x400310000,0,clear_negative=True)
    except (AssertionError,UcError):pass
    else:raise AssertionError('uninitialized fresh-frame flags unexpectedly survived dirty-stack reuse')
    print('PASS executed production ARM64 callback transition/dispatcher/return and nested syscall dispatcher: old direct-call PC=0, FP packing and dirty-frame failures reproduced; old x18 TEB copy reproduces read0x378 after successful callback; two frees per callback, 256 repeats/two owners/trace paths including x18 cleared before EVERY instruction preserve outer frame, SP/LR, nonvolatile registers, syscall flags, FP state, outputs and owner')
