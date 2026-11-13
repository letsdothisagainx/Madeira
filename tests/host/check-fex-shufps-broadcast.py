#!/usr/bin/env python3
"""Execute pinned/staged SHUFOpImpl and check the captured same-source broadcast.

The production frontend bodies run unchanged in a small IR recorder. All other
shuffle paths must emit exactly their previous IR. Raw integer bits test the
changed path; no host floating-point arithmetic can canonicalize NaN payloads.
On AArch64 the same test also executes the captured DUP/DUP/ZIP1 and replacement
DUP instructions, both in place and into a separate destination.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
VECTOR = 'FEXCore/Source/Interface/Core/OpcodeDispatcher/Vector.cpp'


def captured_broadcast():
    fixture = json.loads((ROOT / 'tests/fixtures/fex-shufps/run6-phonon-broadcast.json').read_text())
    def words(key):
        return [int(word, 16) for word in fixture[key]['words'].split()]
    header = int(fixture['header']['address'], 16)
    tail = int(fixture['tail']['address'], 16)
    assert header + words('header')[0] == tail
    assert words('header')[1:] == [0x10ffffea, 0xf900038a]
    size, rip, guest_size, entries, offset, _, single = struct.unpack(
        '<QQQIIIB3x', struct.pack('<10I', *words('tail')))
    assert size == 0x7c4 and guest_size == 0x48b and entries == 90 and offset == 40 and not single
    assert rip - int(fixture['module_base'], 16) == 0x39e0330
    assert header < int(fixture['broadcast']['address'], 16) < tail < header + size
    assert words('broadcast') == [0x4e1c05d2, 0x4e1c05d3, 0x4ed33a4e]
    assert fixture['sample']['host_bucket_samples'] == 5 and fixture['sample']['running_samples'] == 83
    return words('broadcast')


def body(source, signature):
    start = source.index(signature)
    return source[start:source.index('\n}', start) + 2]


def arm64_code(work, clang, objdump):
    # VDupElement's unchanged 128-bit backend emits DUP(SubRegSize, Dst.Q(),
    # Vector.Q(), Index). Assemble that consumer for distinct and aliased regs.
    backend = (ROOT / 'FEX/FEXCore/Source/Interface/Core/JIT/VectorOps.cpp').read_text()
    duplicate = body(backend, 'DEF_OP(VDupElement) {')
    assert 'if (Is128Bit) {\n      dup(SubRegSize, Dst.Q(), Vector.Q(), Index);' in duplicate
    assembly = ['.text', '.globl captured', 'captured:',
                'dup v18.4s, v14.s[3]', 'dup v19.4s, v14.s[3]',
                'zip1 v14.2d, v18.2d, v19.2d']
    expected = captured_broadcast()
    for index in range(4):
        for source in (0, 1):
            assembly += [f'.globl duplicate_{index}_{source}', f'duplicate_{index}_{source}:',
                         f'dup v0.4s, v{source}.s[{index}]', 'ret']
            expected += [0x4e040400 | index << 19 | source << 5, 0xd65f03c0]
    asm = work / 'broadcast.S'
    obj = work / 'broadcast.o'
    asm.write_text('\n'.join(assembly) + '\n')
    subprocess.run([clang, '--target=aarch64-linux-gnu', '-c', str(asm), '-o', str(obj)], check=True)
    result = subprocess.run([objdump, '-d', str(obj)], text=True, capture_output=True, check=True)
    words = [int(word, 16) for word in re.findall(r'^\s*[0-9a-f]+:\s+([0-9a-f]{8})\s', result.stdout, re.M)]
    assert words == expected, '128-bit backend DUP consumer has unexpected ARM64 code'
    print('ARM64 DUP consumer: exact words for all four lanes, separate and aliased registers passed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-arm64-darwin', action='store_true')
    parser.add_argument('--clang', default=os.environ.get('CLANG') or shutil.which('clang'))
    parser.add_argument('--objdump', default=os.environ.get('LLVM_OBJDUMP') or shutil.which('llvm-objdump'))
    args = parser.parse_args()
    native_arm = platform.machine().lower() in ('arm64', 'aarch64')
    if args.require_arm64_darwin and not (native_arm and platform.system() == 'Darwin'):
        parser.error('native Apple ARM64 is required; cross-compilation is not execution evidence')
    captured_broadcast()
    with tempfile.TemporaryDirectory(prefix='madeira-shufps-broadcast-') as directory:
        work = Path(directory)
        spec = importlib.util.spec_from_file_location('fex_stage', ROOT / 'tools/build/stage-fex-compat.py')
        stager = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(stager)
        staged = work / 'staged'
        stager.stage(staged, ROOT / 'FEX', 'both')
        before = body((ROOT / 'FEX' / VECTOR).read_text(), 'Ref OpDispatchBuilder::SHUFOpImpl(')
        after = body((staged / VECTOR).read_text(), 'Ref OpDispatchBuilder::SHUFOpImpl(')
        # The patch must stay confined to one new branch. In particular, retain
        # the established immediate-zero behavior and every 256-bit path.
        branch = after[after.index('    if (DstSize == OpSize::i128Bit && ElementSize == OpSize::i32Bit && LHS == RHS &&'):
                       after.index('    if (ElementSize == OpSize::i32Bit) {')]
        assert after.replace(branch, '', 1) == before
        assert 'LaneShuffle == 0x55 || LaneShuffle == 0xAA || LaneShuffle == 0xFF' in branch
        source = PRELUDE + '\n' + before.replace('OpDispatchBuilder::', 'Before::', 1)
        source += '\n' + after.replace('OpDispatchBuilder::', 'After::', 1) + '\n' + HARNESS
        cpp = work / 'shuffle.cpp'
        cpp.write_text(source)
        compiler = os.environ.get('CXX') or shutil.which('clang++') or shutil.which('c++')
        assert compiler, 'a C++20 compiler is required'
        executable = work / 'shuffle-test'
        subprocess.run([compiler, '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror',
                        str(cpp), '-o', str(executable)], check=True)
        subprocess.run([str(executable)], check=True)
        if args.clang and args.objdump:
            arm64_code(work, args.clang, args.objdump)
        else:
            print('ARM64 cross-assembly not run: pass --clang and --objdump to enable it')
    print('Production SHUFOpImpl: all masks/widths/SSA aliases and raw-bit broadcasts passed')
    if not native_arm:
        print('Native ARM64 execution not run on this host; Apple CI uses --require-arm64-darwin')


PRELUDE = r'''
#include <array>
#include <bit>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>
#if defined(__x86_64__)
#include <xmmintrin.h>
#endif
namespace IR {
enum class OpSize : unsigned { i8Bit=1, i16Bit=2, i32Bit=4, i64Bit=8, i128Bit=16, i256Bit=32 };
unsigned NumElements(OpSize size, OpSize element) { return unsigned(size)/unsigned(element); }
enum class IndexNamedVectorConstant { INDEXED_NAMED_VECTOR_SHUFPS };
}
namespace FEXCore { namespace IR = ::IR; }
using IR::OpSize;
using Ref = unsigned;
using Bits = std::array<uint32_t, 8>;
struct Node {
  std::string kind;
  OpSize size, element;
  Ref a=0, b=0, c=0;
  unsigned index=0, other=0;
  Bits bits {};
  bool operator==(const Node&) const = default;
};
struct Builder {
  std::vector<Node> nodes {Node{"null", OpSize::i128Bit, OpSize::i32Bit}};
  Ref input(const Bits& bits) {
    Node n {"input", OpSize::i256Bit, OpSize::i32Bit}; n.bits=bits;
    nodes.push_back(n); return nodes.size()-1;
  }
  Ref append(const char* kind, OpSize size, OpSize element, Ref a, Ref b=0,
             unsigned index=0, unsigned other=0, Ref c=0) {
    nodes.push_back(Node {kind, size, element, a, b, c, index, other}); return nodes.size()-1;
  }
  Ref _VDupElement(OpSize s, OpSize e, Ref a, unsigned i) { return append("dup",s,e,a,0,i); }
  Ref _VInsElement(OpSize s, OpSize e, unsigned d, unsigned i, Ref a, Ref b) {
    return append("ins",s,e,a,b,d,i);
  }
  Ref _VExtr(OpSize s, OpSize e, Ref a, Ref b, unsigned i) { return append("extr",s,e,a,b,i); }
  Ref _VRev64(OpSize s, OpSize e, Ref a) { return append("rev64",s,e,a); }
#define BINARY(NAME, TEXT) Ref NAME(OpSize s,OpSize e,Ref a,Ref b) {return append(TEXT,s,e,a,b);}
  BINARY(_VZip,"zip") BINARY(_VZip2,"zip2")
  BINARY(_VUnZip,"unzip") BINARY(_VUnZip2,"unzip2")
  BINARY(_VTrn,"trn") BINARY(_VTrn2,"trn2")
#undef BINARY
  Ref LoadAndCacheIndexedNamedVectorConstant(OpSize s, IR::IndexNamedVectorConstant, unsigned i) {
    return append("constant",s,OpSize::i8Bit,0,0,i);
  }
  Ref _VTBL2(OpSize s,Ref a,Ref b,Ref c) {return append("tbl2",s,OpSize::i8Bit,a,b,0,0,c);}
  Bits evaluate(Ref id) const {
    const auto& n=nodes.at(id);
    if(n.kind=="input") return n.bits;
    const auto a=evaluate(n.a);
    Bits result {};
    if(n.kind=="dup") {
      const unsigned count=unsigned(n.size)/unsigned(n.element);
      const unsigned words=unsigned(n.element)/4;
      for(unsigned i=0;i<count;i++)
        std::memcpy(result.data()+i*words,a.data()+n.index*words,words*4);
    } else if(n.kind=="zip") {
      const auto b=evaluate(n.b);
      const unsigned count=unsigned(n.size)/unsigned(n.element);
      const unsigned words=unsigned(n.element)/4;
      for(unsigned i=0;i<count/2;i++) {
        std::memcpy(result.data()+i*2*words,a.data()+i*words,words*4);
        std::memcpy(result.data()+(i*2+1)*words,b.data()+i*words,words*4);
      }
    } else throw std::runtime_error("unexpected operation on broadcast path: "+n.kind);
    return result;
  }
};
struct Before : Builder { Ref SHUFOpImpl(OpSize,OpSize,Ref,Ref,uint8_t); };
struct After : Builder { Ref SHUFOpImpl(OpSize,OpSize,Ref,Ref,uint8_t); };
'''


HARNESS = r'''
static unsigned native_cases;
static void native_broadcast(const uint32_t* input, uint32_t* output, unsigned lane, bool old, bool register_alias) {
#if defined(__aarch64__)
  struct Vector { uint32_t words[4]; };
  const auto& in=*reinterpret_cast<const Vector*>(input);
  auto& out=*reinterpret_cast<Vector*>(output);
#define ARM_CASE(I) case I: \
  if(old && register_alias) asm volatile("ldr q14, %1\n dup v18.4s, v14.s[" #I "]\n" \
                       "dup v19.4s, v14.s[" #I "]\n zip1 v14.2d, v18.2d, v19.2d\n str q14, %0" \
                       : "=m"(out) : "m"(in) : "v14","v18","v19","memory"); \
  else if(old) asm volatile("ldr q14, %1\n dup v18.4s, v14.s[" #I "]\n" \
                       "dup v19.4s, v14.s[" #I "]\n zip1 v13.2d, v18.2d, v19.2d\n str q13, %0" \
                       : "=m"(out) : "m"(in) : "v13","v14","v18","v19","memory"); \
  else if(register_alias) asm volatile("ldr q14, %1\n dup v14.4s, v14.s[" #I "]\n str q14, %0" \
                    : "=m"(out) : "m"(in) : "v14","memory"); \
  else asm volatile("ldr q14, %1\n dup v13.4s, v14.s[" #I "]\n str q13, %0" \
                    : "=m"(out) : "m"(in) : "v13","v14","memory"); break;
  switch(lane) { ARM_CASE(0) ARM_CASE(1) ARM_CASE(2) ARM_CASE(3) default: assert(false); }
#undef ARM_CASE
  ++native_cases;
#elif defined(__x86_64__)
  (void)old; (void)register_alias;
  __m128 v; std::memcpy(&v,input,16);
  switch(lane) {
    case 0: v=_mm_shuffle_ps(v,v,0x00); break;
    case 1: v=_mm_shuffle_ps(v,v,0x55); break;
    case 2: v=_mm_shuffle_ps(v,v,0xaa); break;
    case 3: v=_mm_shuffle_ps(v,v,0xff); break;
    default: assert(false);
  }
  std::memcpy(output,&v,16);
#else
  (void)input; (void)output; (void)lane; (void)old; (void)register_alias;
#endif
}
static void check_bits(const Bits& bits, unsigned lane) {
  Before before; After after;
  const auto x=before.input(bits), y=after.input(bits);
  const unsigned mask=lane*0x55;
  const auto a=before.SHUFOpImpl(OpSize::i128Bit,OpSize::i32Bit,x,x,mask);
  const auto b=after.SHUFOpImpl(OpSize::i128Bit,OpSize::i32Bit,y,y,mask);
  const Bits av=before.evaluate(a), bv=after.evaluate(b);
  for(unsigned i=0;i<4;i++) assert(av[i]==bits[lane] && bv[i]==bits[lane]);
  assert(av==bv);
  // Both aliased source/destination and a separate destination preserve the
  // upper 128 bits, which the unchanged SSE StoreResult path retains.
  for(bool in_place : {false,true}) {
    Bits source=bits, old_result=bits, new_result=bits;
    if(!in_place) { old_result.fill(0xa5a5a5a5); new_result=old_result; }
    const Bits guard=old_result;
    std::memcpy(old_result.data(),av.data(),16);
    std::memcpy(new_result.data(),bv.data(),16);
    assert(old_result==new_result);
    for(unsigned i=4;i<8;i++) assert(new_result[i]==guard[i]);
#if defined(__aarch64__) || defined(__x86_64__)
    for(bool register_alias : {false,true}) {
      old_result=guard; new_result=guard;
      native_broadcast(in_place ? old_result.data() : source.data(),old_result.data(),lane,true,register_alias);
      native_broadcast(in_place ? new_result.data() : source.data(),new_result.data(),lane,false,register_alias);
      for(unsigned i=0;i<4;i++) {
        const auto expected=in_place ? guard[lane] : bits[lane];
        assert(old_result[i]==expected && new_result[i]==expected);
      }
      assert(old_result==new_result);
      for(unsigned i=4;i<8;i++) assert(new_result[i]==guard[i]);
    }
#endif
  }
}
int main() {
  const Bits distinct {0x80000000,0x7fa12345,0x7fc54321,0xffffffff,1,2,3,4};
  Bits different=distinct; different[0]^=1; different[3]^=0x40000000;
  unsigned unchanged=0, changed=0;
  for(auto width : {OpSize::i128Bit,OpSize::i256Bit})
    for(auto element : {OpSize::i32Bit,OpSize::i64Bit})
      for(unsigned mode=0;mode<3;mode++)
        for(unsigned mask=0;mask<256;mask++) {
          Before before; After after;
          const auto bx=before.input(distinct), ax=after.input(distinct);
          const auto by=mode ? before.input(mode==1 ? distinct : different) : bx;
          const auto ay=mode ? after.input(mode==1 ? distinct : different) : ax;
          const auto b=before.SHUFOpImpl(width,element,bx,by,mask);
          const auto a=after.SHUFOpImpl(width,element,ax,ay,mask);
          const bool selected=width==OpSize::i128Bit && element==OpSize::i32Bit && !mode &&
                              (mask==0x55 || mask==0xaa || mask==0xff);
          if(selected) {
            assert(before.nodes.size()==5 && after.nodes.size()==3);
            assert(before.nodes[2].kind=="dup" && before.nodes[3].kind=="dup" &&
                   before.nodes[b].kind=="zip");
            assert(after.nodes[a].kind=="dup" && after.nodes[a].index==(mask&3));
            assert(before.evaluate(b)==after.evaluate(a));
            ++changed;
          } else {
            assert(b==a && before.nodes==after.nodes); ++unchanged;
          }
        }
  assert(changed==3 && unchanged==3069);
  unsigned bit_cases=0;
  // Basis vectors cover every bit in every input lane. Additional exact NaN,
  // zero, infinity, subnormal, alternating and randomized bits exercise data
  // that a floating-point-value comparison would incorrectly conflate.
  for(unsigned lane=0;lane<4;lane++) {
    for(unsigned input_lane=0;input_lane<4;input_lane++)
      for(unsigned bit=0;bit<32;bit++) {
        Bits bits=distinct; bits[input_lane]=uint32_t(1)<<bit;
        check_bits(bits,lane); ++bit_cases;
        bits[input_lane]=~bits[input_lane]; check_bits(bits,lane); ++bit_cases;
      }
    for(uint32_t value : {0u,0x80000000u,0x7f800000u,0xff800000u,0x7f800001u,
                         0x7fc12345u,0xffa54321u,0xffffffffu,1u,0x007fffffu,
                         0xaaaaaaaau,0x55555555u}) {
      Bits bits=distinct; bits[lane]=value; check_bits(bits,lane); ++bit_cases;
    }
    uint32_t state=0x913acf07;
    for(unsigned i=0;i<4096;i++) {
      Bits bits;
      for(auto& word : bits) {state^=state<<13; state^=state>>17; state^=state<<5; word=state;}
      check_bits(bits,lane); ++bit_cases;
    }
  }
  std::printf("IR cases: unchanged=%u optimized=%u; raw-bit cases=%u; native ARM64 cases=%u\n",
              unchanged,changed,bit_cases,native_cases);
}
'''


if __name__ == '__main__':
    main()
