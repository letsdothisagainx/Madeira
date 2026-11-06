#!/usr/bin/env python3
"""Execute the captured high-volume FEX counter through old/new production plans.

The real counter function's memory instructions and retry/control flow remain
unchanged. Fixture relocation selects owned data and a clock-backend shim whose
captured prologue kills X8 before observing it. No FEX source is edited.
"""
from pathlib import Path
import argparse
import os
import platform
import subprocess
import tempfile

root=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--require-arm64-darwin',action='store_true');args=p.parse_args()
if platform.system()!='Darwin' or platform.machine().lower() not in ('arm64','aarch64'):
    if args.require_arm64_darwin:raise SystemExit('FAIL: native counter call benchmark requires actual Apple ARM64/Mach')
    print('SKIP native counter call benchmark: Apple ARM64/Mach required');raise SystemExit(0)
source=(root/'build/ntdll-unix/signal_arm64_ios.c').read_text()
first=source.index('#define IOS_MACH_RMW(type)');last=source.index('#undef IOS_MACH_RMW',first)+len('#undef IOS_MACH_RMW')
helper=source[first:last]+'\n'
first=source.index('                    else if ((insn & 0x3fe07c00) == 0x08007c00)')
last=source.index('                    /* iOS-Madeira ml626: SWP',first)
exclusive=source[first:last].replace('else if','if',1)
with tempfile.TemporaryDirectory(prefix='madeira-counter-call-') as directory:
    work=Path(directory);old=work/'previous';old.mkdir()
    header=(root/'build/ntdll-unix/native_data_alias.h').read_text()
    predicate='base==8&&!madeira_nd_direct_callee_kills_x8(code,count,at)'
    assert header.count(predicate)==1
    (old/'native_data_alias.h').write_text(header.replace(predicate,'base==8',1))
    (work/'production-atomic-emulation.h').write_text(helper+r'''
static int baseline_emulate(uint32_t insn,uintptr_t fault_pc,uintptr_t fault_addr,
                            uintptr_t rw_addr,arm_thread_state64_t *input)
{
    arm_thread_state64_t state=*input;uint64_t gpr[32];int emulated=0;
    memcpy(gpr,state.__x,sizeof(state.__x));
    gpr[29]=state.__fp;gpr[30]=state.__lr;gpr[31]=state.__sp;
    if(ios_mach_emulate_rmw(insn,rw_addr,gpr)){
        memcpy(state.__x,gpr,sizeof(state.__x));state.__fp=gpr[29];state.__lr=gpr[30];*input=state;return 1;
    }
#define IOS_STORE_SRC(r) ((r)==31?0ULL:state.__x[r])
'''+exclusive+r'''
#undef IOS_STORE_SRC
    *input=state;return emulated;
}
''')
    for fixed in (0,1):
        binary=work/('counter-fixed' if fixed else 'counter-previous')
        include=[] if fixed else ['-I',str(old)]
        subprocess.run([os.environ.get('CC','clang'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-pthread',
                        '-DPERF_EXPECT_FIXED='+str(fixed),*include,'-I',str(work),
                        '-I',str(root/'build/ntdll-unix'),
                        str(root/'tests/host/native-counter-call-performance.c'),'-o',str(binary)],check=True)
        subprocess.run([str(binary)],check=True,timeout=60)
