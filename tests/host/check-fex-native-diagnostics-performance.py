#!/usr/bin/env python3
"""Apple ARM64/Mach execution of FEX's explicit native diagnostic writers.

The production stager supplies GetTelemetryValue, IRTopoNoteChecked, and the
unaltered call-return-history statements from the real CompileBlock body. The
telemetry test executes exact captured STSETL 0xf860303f against addresses the
actual getters selected, as the real emitter does. This is a focused fixture,
not execution of the FEX compiler or a prediction of iPhone game frame rate.
"""
from pathlib import Path
import argparse
import importlib.util
import os
import platform
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def function(source, signature):
    start = source.index(signature)
    return source[start:source.index('\n}', start) + 2]


def prepare(work):
    spec = importlib.util.spec_from_file_location('fex_native_stage', ROOT / 'tools/build/stage-fex-compat.py')
    stage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stage)
    staged = work / 'staged'
    stage.stage(staged, ROOT / 'FEX', 'both')
    telemetry_path = 'FEXCore/include/FEXCore/Utils/Telemetry.h'
    ir_path = 'FEXCore/Source/Interface/IR/IRTopologyCheck.h'
    old_telemetry, new_telemetry = [(base / telemetry_path).read_text() for base in (ROOT / 'FEX', staged)]
    old_ir, new_ir = [(base / ir_path).read_text() for base in (ROOT / 'FEX', staged)]
    core_path = 'FEXCore/Source/Interface/Core/Core.cpp'
    old_core, new_core = [(base / core_path).read_text() for base in (ROOT / 'FEX', staged)]
    def history_block(source):
        start = source.index('  /* iOS-Madeira 2026-05-14: per-thread callret tracking (runs for EVERY')
        end = source.index('  /* iOS-Madeira 2026-05-13 lightweight HOTRIP', start)
        return source[start:end]
    old_history, new_history = history_block(old_core), history_block(new_core)
    history_getter = function(new_core, 'static MadeiraFEXDiagnostics::CallRetHistoryState& MadeiraFEXHistoryStats(')
    assert 'auto& history = MadeiraFEXHistoryStats();' in new_history
    substitutions = {'key': 'key', 'crsp_min': 'crsp_min', 'crsp_max': 'crsp_max',
                     'crsp_last': 'crsp_last', 'count': 'count', 'last_rip': 'last_rip'}
    restored = new_history.replace('    auto& history = MadeiraFEXHistoryStats();\n', '')
    for name, field in substitutions.items():
        restored = restored.replace('history.' + field, 'g_madeira_thr_' + name)
    assert restored == old_history, 'actual history statements/order must remain unchanged'
    emitter = (ROOT / 'FEX/FEXCore/Source/Interface/Core/JIT/AtomicOps.cpp').read_text()
    emit = emitter[emitter.index('DEF_OP(TelemetrySetValue)'):]
    assert 'Pointers.TelemetryValueAddresses, Op->TelemetryValueIndex' in emit
    assert 'cset(ARMEmitter::Size::i32Bit, TMP1, ARMEmitter::Condition::CC_NE)' in emit
    assert 'stsetl(ARMEmitter::SubRegSize::i64Bit, TMP1, TMP2)' in emit
    enum_start = old_telemetry.index('enum TelemetryType {')
    enum = old_telemetry[enum_start:old_telemetry.index('\n};', enum_start) + 3]
    old_getter = function(old_telemetry, 'inline Value& GetTelemetryValue(').replace('GetTelemetryValue(', 'OldGetTelemetryValue(', 1)
    getter = function(new_telemetry, 'inline Value& GetTelemetryValue(')
    ir_getter = function(new_ir, 'inline MadeiraFEXDiagnostics::IRTopoState& MadeiraFEXIRTopoStats(')
    old_note = function(old_ir, 'inline void IRTopoNoteChecked(').replace('IRTopoNoteChecked(', 'OldIRTopoNoteChecked(', 1)
    note = function(new_ir, 'inline void IRTopoNoteChecked(')
    header = r'''
#include <array>
#include <atomic>
#include <cassert>
#include <cstdint>
#include "native_diagnostics.h"
#define FEX_DIAG_IMAGE_SIZE 0x20000u
#define FEX_DIAG_CONTRACT 0x5000u
#define FEX_DIAG_TELEMETRY 0x6000u
#define FEX_DIAG_IRTOPO 0x6200u
#define FEX_DIAG_COMPILE 0x6400u
#define FEX_DIAG_HISTORY 0x6600u
static unsigned char *diagnostic_source_rx;
#define MadeiraFEXTelemetryWriteContract (*reinterpret_cast<MadeiraFEXNativeWriteContract*>(diagnostic_source_rx+FEX_DIAG_CONTRACT))
#define MadeiraFEXIRTopoWriteContract (*reinterpret_cast<MadeiraFEXNativeWriteContract*>(diagnostic_source_rx+FEX_DIAG_CONTRACT+64))
#define MadeiraFEXCompileWriteContract (*reinterpret_cast<MadeiraFEXNativeWriteContract*>(diagnostic_source_rx+FEX_DIAG_CONTRACT+128))
#define MadeiraFEXHistoryWriteContract (*reinterpret_cast<MadeiraFEXNativeWriteContract*>(diagnostic_source_rx+FEX_DIAG_CONTRACT+192))
namespace LogMan { namespace Msg {template<typename... T> void EFmt(const char*,T&&...) {}} }
namespace FEXCore { namespace Telemetry {
''' + enum + r'''
using Value=std::atomic<uint64_t>;
using Values=std::array<Value,TelemetryType::TYPE_LAST>;
static_assert(sizeof(Values)==136&&alignof(Values)==8);
inline Values& DiagnosticCanonicalTelemetry() {
  return *reinterpret_cast<Values*>(diagnostic_source_rx+FEX_DIAG_TELEMETRY);
}
#define TelemetryValues DiagnosticCanonicalTelemetry()
''' + old_getter + '\n' + getter + r'''
#undef TelemetryValues
}}
namespace FEXCore { namespace IR {
#define IRTopoChecked (reinterpret_cast<MadeiraFEXDiagnostics::IRTopoState*>(diagnostic_source_rx+FEX_DIAG_IRTOPO)->checked)
#define IRTopoTripped (reinterpret_cast<MadeiraFEXDiagnostics::IRTopoState*>(diagnostic_source_rx+FEX_DIAG_IRTOPO)->tripped)
#define IRTopoRepaired (reinterpret_cast<MadeiraFEXDiagnostics::IRTopoState*>(diagnostic_source_rx+FEX_DIAG_IRTOPO)->repaired)
#define IRTopoDeclined (reinterpret_cast<MadeiraFEXDiagnostics::IRTopoState*>(diagnostic_source_rx+FEX_DIAG_IRTOPO)->declined)
''' + old_note + r'''
#undef IRTopoChecked
#undef IRTopoTripped
#undef IRTopoRepaired
#undef IRTopoDeclined
#define MadeiraFEXIRTopoStorage (*reinterpret_cast<MadeiraFEXDiagnostics::IRTopoState*>(diagnostic_source_rx+FEX_DIAG_IRTOPO))
''' + ir_getter + '\n' + '\n'.join(line for line in new_ir.splitlines() if line.startswith('#define IRTopo')) + '\n' + note + r'''
#undef IRTopoChecked
#undef IRTopoTripped
#undef IRTopoRepaired
#undef IRTopoDeclined
#undef MadeiraFEXIRTopoStorage
}}
'''
    header += r'''
struct alignas(64) DiagnosticHistoryFrame {
  struct {uint64_t callret_sp;} State;
  unsigned char fixture_padding[56];
};
static_assert(sizeof(DiagnosticHistoryFrame)==64);
inline MadeiraFEXDiagnostics::CallRetHistoryState& DiagnosticCanonicalHistory() {
  return *reinterpret_cast<MadeiraFEXDiagnostics::CallRetHistoryState*>(diagnostic_source_rx+FEX_DIAG_HISTORY);
}
#define MadeiraFEXHistoryStorage DiagnosticCanonicalHistory()
''' + history_getter + r'''
#undef MadeiraFEXHistoryStorage
'''
    for name, field in substitutions.items():
        header += '#define g_madeira_thr_' + name + ' (DiagnosticCanonicalHistory().' + field + ')\n'
    header += 'inline void OldRecordHistory(DiagnosticHistoryFrame* Frame,uint64_t GuestRIP) {\n' + old_history + '}\n'
    for name in substitutions:
        header += '#undef g_madeira_thr_' + name + '\n'
    header += 'inline void RecordHistory(DiagnosticHistoryFrame* Frame,uint64_t GuestRIP) {\n' + new_history + '}\n'
    (work / 'production-fex-diagnostics-source.h').write_text(header)
    (work / 'production-fex-diagnostics-fixture.h').write_text(r'''
#include "native_fex_diagnostics_alias.h"
enum { FEX_DIAG_IMAGE_SIZE=0x20000,FEX_DIAG_CONTRACT=0x5000,FEX_DIAG_TELEMETRY=0x6000,FEX_DIAG_IRTOPO=0x6200,FEX_DIAG_COMPILE=0x6400,FEX_DIAG_HISTORY=0x6600,FEX_DIAG_TRANSITION=0x8000 };
static void diag_w16(unsigned char *p,size_t at,uint16_t value){memcpy(p+at,&value,2);}
static void diag_w32(unsigned char *p,size_t at,uint32_t value){memcpy(p+at,&value,4);}
static void diag_w64(unsigned char *p,size_t at,uint64_t value){memcpy(p+at,&value,8);}
static void diagnostic_pe_fixture(unsigned char *p) {
  memset(p,0,FEX_DIAG_IMAGE_SIZE);p[0]='M';p[1]='Z';diag_w32(p,60,0x80);memcpy(p+0x80,"PE\0\0",4);
  diag_w16(p,0x84,0xaa64);diag_w16(p,0x86,3);diag_w16(p,0x94,0xf0);diag_w16(p,0x98,0x20b);
  diag_w64(p,0xb0,0x180000000ULL);diag_w32(p,0xd0,FEX_DIAG_IMAGE_SIZE);diag_w32(p,0x104,16);
  diag_w32(p,0x108,0x1000);diag_w32(p,0x10c,0x1000);
  const uint32_t starts[]={0x1000,0x2000,0x4000},lengths[]={0x1000,0x1000,0x1c000},flags[]={0x40000040,0x60000020,0xc0000040};
  for(unsigned i=0;i<3;i++){size_t a=0x188+i*40;diag_w32(p,a+8,lengths[i]);diag_w32(p,a+12,starts[i]);diag_w32(p,a+16,lengths[i]);diag_w32(p,a+36,flags[i]);}
  diag_w32(p,0x1000+12,0x1180);strcpy((char*)p+0x1180,"libarm64ecfex.dll");
  diag_w32(p,0x1000+20,6);diag_w32(p,0x1000+24,6);diag_w32(p,0x1000+28,0x1100);diag_w32(p,0x1000+32,0x1120);diag_w32(p,0x1000+36,0x1140);
  const char *names[]={"MadeiraFEXTelemetryWriteContract","MadeiraFEXIRTopoWriteContract","MadeiraFEXCompileWriteContract","MadeiraFEXHistoryWriteContract","MadeiraFEXTransitionWriteContract"};
  const uint64_t tags[]={MADEIRA_FEX_TELEMETRY_TAG,MADEIRA_FEX_IRTOPO_TAG,MADEIRA_FEX_COMPILE_TAG,MADEIRA_FEX_HISTORY_TAG,MADEIRA_FEX_TRANSITION_TAG};
  const uint32_t payloads[]={FEX_DIAG_TELEMETRY,FEX_DIAG_IRTOPO,FEX_DIAG_COMPILE,FEX_DIAG_HISTORY,FEX_DIAG_TRANSITION},length[]={136,32,48,192,35968};
  for(unsigned i=0;i<5;i++){
    diag_w32(p,0x1100+4*i,FEX_DIAG_CONTRACT+64*i);diag_w32(p,0x1120+4*i,0x1200+64*i);diag_w16(p,0x1140+2*i,(uint16_t)i);
    strcpy((char*)p+0x1200+64*i,names[i]);diag_w64(p,FEX_DIAG_CONTRACT+64*i,tags[i]);
    diag_w32(p,FEX_DIAG_CONTRACT+64*i+8,length[i]);diag_w32(p,FEX_DIAG_CONTRACT+64*i+12,i==4?64:8);
    diag_w64(p,FEX_DIAG_CONTRACT+64*i+16,0x180000000ULL+payloads[i]);
  }
  diag_w32(p,0x1100+4*5,FEX_DIAG_TRANSITION);diag_w32(p,0x1120+4*5,0x1200+64*5);diag_w16(p,0x1140+2*5,5);
  strcpy((char*)p+0x1200+64*5,"IosXpFex");
}
''')


def emulation_header(work):
    source = (ROOT / 'build/ntdll-unix/signal_arm64_ios.c').read_text()
    first = source.index('#define IOS_MACH_RMW(type)')
    last = source.index('#undef IOS_MACH_RMW', first) + len('#undef IOS_MACH_RMW')
    helpers = source[first:last]
    for signature in ('static int ios_alias_write(',):
        helpers += '\n' + function(source, signature)
    start = source.index('                    else if ((insn & 0x3fe07c00) == 0x08007c00)')
    end = source.index('                    /* iOS-Madeira ml626: SWP', start)
    exclusive = source[start:end].replace('else if', 'if', 1)
    start = source.index('                    else if ((insn & 0xffc00000) == 0xf9000000)')
    end = source.index('                    /* STR (immediate, unsigned offset, 32-bit)', start)
    scalar = source[start:end]
    start = source.index('                    else if ((insn & 0xffe00c00) == 0xf8200800)')
    end = source.index('                    /* STLR (Store-Release Register, 64-bit):', start)
    indexed = source[start:end]
    (work / 'production-atomic-emulation.h').write_text(helpers + r'''
static int baseline_emulate(uint32_t insn,uintptr_t fault_pc,uintptr_t fault_addr,
                            uintptr_t rw_addr,arm_thread_state64_t *input){
  arm_thread_state64_t state=*input;uint64_t gpr[32];int emulated=0,honor_guest_prot=1;uintptr_t alias_fault=0;
  memcpy(gpr,state.__x,sizeof(state.__x));gpr[29]=state.__fp;gpr[30]=state.__lr;gpr[31]=state.__sp;
  if(ios_mach_emulate_rmw(insn,rw_addr,gpr)){
    memcpy(state.__x,gpr,sizeof(state.__x));state.__fp=gpr[29];state.__lr=gpr[30];*input=state;return 1;
  }
#define IOS_STORE_SRC(r) ((r)==31?0ULL:state.__x[r])
''' + exclusive + scalar + indexed + r'''
#undef IOS_STORE_SRC
  *input=state;return emulated;
}
''')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-arm64-darwin', action='store_true')
    args = parser.parse_args()
    if platform.system() != 'Darwin' or platform.machine().lower() not in ('arm64', 'aarch64'):
        if args.require_arm64_darwin:
            raise SystemExit('FAIL FEX diagnostic benchmark requires real Apple ARM64/Mach')
        print('SKIP FEX diagnostic benchmark: actual Apple ARM64/Mach execution required')
        return
    with tempfile.TemporaryDirectory(prefix='madeira-fex-native-mach-') as folder:
        work = Path(folder)
        prepare(work)
        emulation_header(work)
        flags = ['-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-pthread', '-mcpu=generic', '-march=armv8-a', '-mno-outline-atomics',
                 '-I', str(work), '-I', str(ROOT / 'build/ntdll-unix'), '-I', str(ROOT / 'build/fex-compat'), '-I', str(ROOT / 'tests/host')]
        cpp = ROOT / 'tests/host/native-fex-native-diagnostics-performance.cpp'
        cc = os.environ.get('CC', 'clang')
        cxx = os.environ.get('CXX', 'clang++')
        assembly = work / 'producer.s'
        subprocess.run([cxx, '-std=c++17', *flags, '-S', str(cpp), '-o', str(assembly)], check=True)
        text = assembly.read_text()
        for name in ('madeira_diag_ir_old', 'madeira_diag_ir_bound'):
            label = re.search(r'(?m)^_' + name + r':[^\n]*\n', text)
            assert label, 'actual IR topology source wrapper required'
            end = re.search(r'(?m)^\s*\.cfi_endproc\b|^Lfunc_end[0-9]+:', text[label.end():])
            assert end
            body = text[label.end():label.end()+end.start()]
            assert re.search(r'\bldxr\s+x[0-9]+,', body) and re.search(r'\bstxr\s+w[0-9]+,\s*x[0-9]+,', body) and re.search(r'\bcbnz\s+w[0-9]+,', body), 'real IR counter must retain64-bit LDXR/STXR/status retry'
        assert 'f860303f' in (ROOT / 'tests/host/native-fex-native-diagnostics-performance.cpp').read_text()
        print('PASS actual staged GetTelemetryValue/IRTopoNoteChecked and captured STSETL emitter proof; IR producer retains64-bit exclusive loop')
        cobj, cppobj = work / 'benchmark.o', work / 'producer.o'
        subprocess.run([cc, '-std=c11', *flags, '-c', str(ROOT / 'tests/host/native-fex-native-diagnostics-performance.c'), '-o', str(cobj)], check=True)
        subprocess.run([cxx, '-std=c++17', *flags, '-c', str(cpp), '-o', str(cppobj)], check=True)
        binary = work / 'fex-native-throughput'
        subprocess.run([cxx, '-pthread', str(cobj), str(cppobj), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=90)


if __name__ == '__main__':
    main()
