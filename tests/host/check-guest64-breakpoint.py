#!/usr/bin/env python3
"""Classify the actual ARM64EC INT3 path without consuming its exception."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / 'build/ntdll-unix/signal_arm64_ios.c').read_text()
start = source.index('static int ios_verified_guest64_breakpoint(')
function = source[start:source.index('\n}\n', start) + 3]
wine = (root / 'wine/include/winternl.h').read_text()
area = re.search(r'typedef struct _CHPE_V2_CPU_AREA_INFO\s*\{.*?\} CHPE_V2_CPU_AREA_INFO, \*PCHPE_V2_CPU_AREA_INFO;', wine, re.S).group()
producer = (root / 'FEX/Source/Windows/ARM64EC/Module.cpp').read_text()
assert 'TEBCPUAreaOffset = 0x1788' in producer
assert 'reinterpret_cast<FEXCore::Core::CpuStateFrame*&>(Area->EmulatorData[0])' in producer
assert 'reinterpret_cast<FEXCore::Core::InternalThreadState*&>(Area->EmulatorData[1])' in producer
assert re.search(r'ChpeV2CpuAreaInfo;\s*/\*\s*/1788', wine)
gate = source[source.index('if (req->exception == EXC_BREAKPOINT &&\n                (ios_verified_guest_breakpoint'):]
assert gate.index('ios_verified_guest64_breakpoint(') < gate.index('goto send_exception_reply;')
assert 'reply.ret_code = handled ? KERN_SUCCESS : KERN_FAILURE;' in source
# Nothing in this observer may repair state, consume a trap, or advance RIP.
assert not any(s in function for s in ('thread_set_state', 'NtContinue', 'setup_exception', 'memcpy(', 'memset('))

code = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t BOOLEAN;
typedef uint64_t ULONG64;
typedef uint32_t ULONG;
typedef struct { int unused; } ARM64EC_NT_CONTEXT;
''' + area + r'''
typedef struct {
    struct { unsigned char unused[0x30]; uint64_t Self; } Tib;
    unsigned char unused1[0x60-0x38]; uint64_t Peb;
    unsigned char unused2[0x1788-0x68]; CHPE_V2_CPU_AREA_INFO *ChpeV2CpuAreaInfo;
} TEB;
_Static_assert(offsetof(TEB,ChpeV2CpuAreaInfo)==0x1788,"producer TEB offset");
_Static_assert(offsetof(CHPE_V2_CPU_AREA_INFO,EmulatorData)==0x30,"producer CPU area offset");
static TEB teb;
static CHPE_V2_CPU_AREA_INFO cpu;
static uint64_t frame[20], thread;
static uint32_t instruction=0xd4200000;
static unsigned char guest[4]={0xcc,0xcc,0x0f,0x0b};
static int owned=1, wow, denied;
static uint64_t deny_address;
static unsigned logs;
static int capture(int fd,const char *fmt,...) {
    assert(fd==2 && strstr(fmt,"[guest-breakpoint64-v1]") && strstr(fmt,"action=forward-to-guest-dispatch"));
    logs++; return 0;
}
#define dprintf capture
static uintptr_t ios_wow_base_for_peb(void *p) { assert(p==(void *)(uintptr_t)teb.Peb); return wow?0x400000000ull:0; }
int ios_fex_code_owner_matches(uintptr_t pc,void *p) {
    return owned && pc==(uintptr_t)&instruction && p==(void *)(uintptr_t)teb.Peb;
}
static int ios_fault_read(uint64_t a,void *out,size_t n) {
    const uintptr_t low[]={(uintptr_t)&teb,(uintptr_t)&cpu,(uintptr_t)frame,(uintptr_t)&thread,(uintptr_t)&instruction,(uintptr_t)guest};
    const size_t size[]={sizeof(teb),sizeof(cpu),sizeof(frame),sizeof(thread),sizeof(instruction),sizeof(guest)};
    if(denied || a==deny_address)return 0;
    for(unsigned i=0;i<sizeof(low)/sizeof(low[0]);i++)
        if(a>=low[i] && a-low[i]<=size[i] && n<=size[i]-(a-low[i])) {memcpy(out,(void *)(uintptr_t)a,n);return 1;}
    return 0;
}
''' + function + r'''
static int classify(void) {
    return ios_verified_guest64_breakpoint((uintptr_t)&instruction,(uintptr_t)frame,(uintptr_t)&teb);
}
int main(void) {
    teb.Tib.Self=(uintptr_t)&teb;teb.Peb=0x1043b4000;teb.ChpeV2CpuAreaInfo=&cpu;
    cpu.InSimulation=1;cpu.EmulatorData[0]=frame;cpu.EmulatorData[1]=&thread;thread=(uintptr_t)frame;
    frame[3]=(uintptr_t)guest+1;frame[8]=0x138e8ee30;
    TEB old_teb=teb;CHPE_V2_CPU_AREA_INFO old_cpu=cpu;uint64_t old_frame[20];memcpy(old_frame,frame,sizeof(frame));
    for(unsigned i=0;i<160;i++)assert(classify());
    assert(logs==16 && !memcmp(&teb,&old_teb,sizeof(teb)) && !memcmp(&cpu,&old_cpu,sizeof(cpu)) && !memcmp(frame,old_frame,sizeof(frame)));
    owned=0;assert(!classify());owned=1;
    wow=1;assert(!classify());wow=0;
    denied=1;assert(!classify());denied=0;
    teb.Tib.Self=0;assert(!classify());teb.Tib.Self=(uintptr_t)&teb;
    teb.Peb=0;assert(!classify());teb.Peb=old_teb.Peb;
    teb.ChpeV2CpuAreaInfo=NULL;assert(!classify());teb.ChpeV2CpuAreaInfo=&cpu;
    cpu.InSimulation=0;assert(!classify());cpu.InSimulation=1;
    cpu.EmulatorData[0]=frame+1;assert(!classify());cpu.EmulatorData[0]=frame;
    cpu.EmulatorData[1]=NULL;assert(!classify());cpu.EmulatorData[1]=&thread;
    thread=(uintptr_t)(frame+1);assert(!classify());thread=(uintptr_t)frame;
    frame[8]=0;assert(!classify());frame[8]=old_frame[8];
    frame[3]=0;assert(!classify());frame[3]=old_frame[3];
    frame[3]=UINT64_MAX;assert(!classify());frame[3]=old_frame[3];
    guest[0]=0x0b;assert(!classify());guest[0]=0xcc; /* UD2 is not INT3. */
    instruction=0xd4400020;assert(!classify()); /* FEX fatal HLT/BRK is not guest INT3. */
    instruction=0xd43e01a0;assert(!classify()); /* Native debugger protocol is separate. */
    instruction=0xd4200000;
    deny_address=(uintptr_t)guest;assert(!classify());deny_address=0;
    assert(!ios_verified_guest64_breakpoint((uintptr_t)&instruction+1,(uintptr_t)frame,(uintptr_t)&teb));
    assert(!ios_verified_guest64_breakpoint((uintptr_t)&instruction,(uintptr_t)frame+8,(uintptr_t)&teb));
    assert(classify() && logs==16);
    puts("PASS actual AMD64 INT3 observer: producer CHPE/TEB ABI, owned active frame/thread, guest opcode, 160 repeats/16-log cap, invalid/stale/foreign/native/UD2 cases decline, no execution or exception-state changes");
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-guest64-breakpoint-') as temp:
    src = Path(temp) / 'test.c'
    exe = Path(temp) / 'test'
    src.write_text(code)
    subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all',str(src),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True,timeout=20)

# Execute the pinned FEX converter as well: the intermediate native SIGILL must
# become the original guest breakpoint, including its Windows instruction address.
exception = (root / 'FEX/Source/Windows/Common/Exception.h').read_text()
converter = exception[exception.index('template<typename TReg>'):exception.index('\n} // namespace FEX::Windows')]
core = (root / 'FEX/FEXCore/include/FEXCore/Core/CoreState.h').read_text()
fault = re.search(r'struct alignas\(8\) SynchronousFaultDataStruct \{.*?\} SynchronousFaultData;', core, re.S).group()
signals = (root / 'FEX/FEXCore/include/FEXCore/Core/SignalDelegator.h').read_text()
win_signals = re.search(r'#else\n(\s*FAULT_SIGSEGV = 11,.*?FAULT_SIGILL = 4,)\n#endif', signals, re.S).group(1)
ec = producer[producer.index('  if (Args->Rec.ExceptionCode == EXCEPTION_SINGLE_STEP) {'):]
adjust = ec[:ec.index('\n\n  Context.Sp')]
cpp = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include "FEXCore/Core/X86Enums.h"
using NTSTATUS=int32_t;
#include "ntstatus.h"
#define EXCEPTION_ILLEGAL_INSTRUCTION uint32_t(STATUS_ILLEGAL_INSTRUCTION)
#define EXCEPTION_BREAKPOINT uint32_t(STATUS_BREAKPOINT)
#define EXCEPTION_SINGLE_STEP uint32_t(STATUS_SINGLE_STEP)
#define EXCEPTION_PRIV_INSTRUCTION uint32_t(STATUS_PRIVILEGED_INSTRUCTION)
#define EXCEPTION_INT_OVERFLOW uint32_t(STATUS_INTEGER_OVERFLOW)
#define EXCEPTION_INT_DIVIDE_BY_ZERO uint32_t(STATUS_INTEGER_DIVIDE_BY_ZERO)
#define EXCEPTION_EXECUTE_FAULT 8
#define EXCEPTION_NONCONTINUABLE 1
struct EXCEPTION_RECORD {
    uint32_t ExceptionCode{},ExceptionFlags{};
    void *ExceptionAddress{};
    uint32_t NumberParameters{};
    uint64_t ExceptionInformation[15]{};
};
namespace LogMan::Msg {template<class... T> static void EFmt(const char*,T...) {}}
namespace FEXCore::Core {
enum SignalNumber {
''' + win_signals + r'''
};
struct CpuStateFrame {
''' + fault + r'''
};
}
''' + converter + r'''
int main() {
    FEXCore::Core::CpuStateFrame::SynchronousFaultDataStruct fault{};
    fault.FaultToTopAndGeneratedException=true;
    fault.Signal=FEXCore::Core::FAULT_SIGTRAP;
    fault.TrapNo=FEXCore::X86State::X86_TRAPNO_BP;
    EXCEPTION_RECORD native{};native.ExceptionCode=0xc000001du;
    native.ExceptionAddress=(void*)0x33eff852cull;
    struct {EXCEPTION_RECORD Rec;struct{uint64_t Pc;uint32_t Cpsr;} Context;} args{};
    auto *Args=&args;Args->Context.Pc=0x3e5f1c105ull;
    Args->Rec=HandleGuestException(fault,native,Args->Context.Pc,uint64_t{},uint64_t{});
''' + adjust + r'''
    assert(Args->Rec.ExceptionCode==0x80000003u && Args->Rec.NumberParameters==1);
    assert((uintptr_t)Args->Rec.ExceptionAddress==0x3e5f1c104ull && Args->Context.Pc==0x3e5f1c104ull);
    assert(!fault.FaultToTopAndGeneratedException && native.ExceptionCode==0xc000001du);
    uint64_t rip=0x3e5f1c106ull;
    fault.FaultToTopAndGeneratedException=true;fault.Signal=FEXCore::Core::FAULT_SIGILL;
    auto illegal=HandleGuestException(fault,native,rip,uint64_t{},uint64_t{});
    assert(illegal.ExceptionCode==0xc000001du && (uintptr_t)illegal.ExceptionAddress==rip);
    assert(rip==0x3e5f1c106ull);
    puts("PASS pinned FEX guest exception converter and ARM64EC adjustment: native C000001D becomes guest INT3 80000003 at original RIP-1; real SIGILL stays illegal; source record preserved");
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-guest64-exception-') as temp:
    src = Path(temp) / 'test.cpp'
    exe = Path(temp) / 'test'
    src.write_text(cpp)
    subprocess.run([os.environ.get('CXX','c++'),'-std=c++20','-Wall','-Wextra','-Werror',
                    '-I'+str(root/'FEX/FEXCore/include'),'-I'+str(root/'wine/include'),
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all',str(src),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True,timeout=20)
