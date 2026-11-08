#!/usr/bin/env python3
"""Exercise the ARM64EC staged OpDispatcher's actual failed-buffer path."""
from pathlib import Path
import os
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]


def function(source, marker):
    start = source.index(marker)
    brace = source.index('{', start)
    depth, end = 1, brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


with tempfile.TemporaryDirectory() as temporary:
    directory = Path(temporary)
    staged = directory / 'staged'
    subprocess.run([
        'python3', str(ROOT / 'tools/build/stage-fex-compat.py'),
        'stage', str(staged), '--backend', 'arm64ec',
    ], check=True)

    # Compile the real staged pool and dual allocator. Only the OS allocator,
    # containers' standard aliases and unrelated IR node fields are substituted.
    stub = directory / 'include'
    utils = stub / 'FEXCore/Utils'
    utils.mkdir(parents=True)
    (stub / 'FEXCore/fextl').mkdir()
    (stub / 'FEXCore/fextl/list.h').write_text(
        '#include <list>\nnamespace fextl {template<class T>using list=std::list<T>;}\n')
    (utils / 'TypeDefines.h').write_text('#define FEX_DEFAULT_VISIBILITY\n')
    (utils / 'MathUtils.h').write_text('''
#include <cstdint>
namespace FEXCore::Utils {
constexpr size_t FEX_PAGE_SIZE=4096;
template<class T>T AlignDown(T value,size_t alignment){return value&~(alignment-1);}
}
''')
    (utils / 'LogManager.h').write_text('''
#define LOGMAN_THROW_A_FMT(value,...) do{if(!(value))throw Fatal{};}while(0)
namespace LogMan::Msg {template<class...T>void EFmt(T...){}}
''')
    (utils / 'Allocator.h').write_text(r'''
#pragma once
#include <cstdlib>
#include <cstdint>
#include <new>
#include <unordered_map>
struct Fatal {};
static unsigned failure,maps,names,metadata,fatals;
static std::unordered_map<void*,size_t> backing;
namespace fextl {
[[noreturn]]inline void ReportAllocationFailure(size_t,size_t){fatals++;throw Fatal{};}
}
namespace FEXCore::Allocator {
inline void* malloc(size_t size){metadata++;return failure==3?nullptr:std::malloc(size);}
inline void free(void* pointer){std::free(pointer);}
inline void* VirtualAlloc(size_t size){
  assert(size==16*1024*1024);maps++;
  if(failure==1)return nullptr;
  if(failure==2)return reinterpret_cast<void*>(~uintptr_t{});
  void* pointer=std::malloc(size);assert(pointer);backing.emplace(pointer,size);
  std::memset(pointer,0xa5,size);return pointer;
}
inline void VirtualFree(void* pointer,size_t size){
  assert(backing.at(pointer)==size);backing.erase(pointer);std::free(pointer);
}
inline void VirtualName(const char*,void* pointer,size_t){assert(backing.contains(pointer));names++;}
enum class ProtectOptions{None};
inline bool VirtualProtect(void* pointer,size_t,ProtectOptions){assert(pointer);return true;}
struct FEXAllocOperators{static void operator delete(void* pointer){free(pointer);}};
}
''')

    allocator = (staged / 'FEXCore/Source/Interface/IR/IntrusiveIRList.h').read_text()
    allocator = allocator[allocator.index('namespace FEXCore::IR {'):
                          allocator.index('class IRListView final')]
    emitter = (staged / 'FEXCore/Source/Interface/IR/IREmitter.h').read_text()
    constructor_start = emitter.index('  IREmitter(')
    constructor = emitter[constructor_start:emitter.index('  virtual ~IREmitter()', constructor_start)]
    methods = '\n'.join(function(emitter, marker) for marker in (
        'bool TryReownOrClaimBuffer()', 'void ReownOrClaimBuffer()',
        'void DelayedDisownBuffer()',
    ))
    reset = function((ROOT / 'FEX/FEXCore/Source/Interface/IR/IREmitter.cpp').read_text(),
                     'void IREmitter::ResetWorkingList()')
    dispatch_reset = function(
        (ROOT / 'FEX/FEXCore/Source/Interface/Core/OpcodeDispatcher.cpp').read_text(),
        'void OpDispatchBuilder::ResetWorkingList()')
    pool = staged / 'FEXCore/include/FEXCore/Utils/ThreadPoolAllocator.h'
    code = r'''
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>
#include <FEXCore/Utils/Allocator.h>
''' + '#include "' + str(pool) + '"\n' + allocator + r'''
// OrderedNode is 20 bytes in Interface/IR/IR.h. Its unrelated methods are not
// needed to execute the production invalid-node allocation and memset below.
struct OrderedNode{unsigned char bytes[20];};
using Ref=OrderedNode*;
struct Nodes:std::vector<Ref>{unsigned clears{};void clear(){clears++;std::vector<Ref>::clear();}};
class IREmitter {
public:
''' + constructor + methods + r'''
  Ref CurrentWriteCursor{},InvalidNode{},CurrentCodeBlock{};
  DualIntrusiveAllocatorThreadPool DualListData;
  Nodes CodeBlocks;
  bool SupportsTSOImm9{};
  void ResetWorkingList();
};
''' + reset + r'''
class OpDispatchBuilder:public IREmitter {
public:
  using IREmitter::IREmitter;
  std::vector<unsigned> JumpTargets;
  bool BlockSetRIP{},DecodeFailure{},ShouldDump{};
  struct {unsigned Written{},Cached{};}RegCache;
  void ResetWorkingList();
};
''' + dispatch_reset + r'''
}
using FEXCore::Utils::PooledAllocatorVirtual;
using FEXCore::IR::OpDispatchBuilder;
static void empty(const OpDispatchBuilder& emitter){
  assert(!emitter.DualListData.DataBegin()&&!emitter.DualListData.ListBegin());
  assert(!emitter.DualListData.DataSize()&&!emitter.DualListData.ListSize());
  assert(!emitter.InvalidNode&&!emitter.CodeBlocks.clears&&backing.empty());
}
int main(){
  // Both OS failure forms and metadata rollback must stop before the exact
  // OpDispatchBuilder -> IREmitter reset path that wrote to 0x800010 on device.
  for(failure=1;failure<=3;failure++){
    PooledAllocatorVirtual pool("FEXMem_OpDispatcher");
    OpDispatchBuilder emitter(pool,false);unsigned old_names=names,old_fatals=fatals;
    assert(!emitter.TryReownOrClaimBuffer());empty(emitter);
    bool stopped=false;
    try{emitter.ResetWorkingList();}catch(const Fatal&){stopped=true;}
    assert(stopped&&fatals==old_fatals+1);empty(emitter);
    assert(names==old_names+(failure==3?2:0));
  }
  assert(metadata==2); // NULL and MAP_FAILED never acquired metadata/ownership.
  failure=0;
  {
    PooledAllocatorVirtual pool("FEXMem_OpDispatcher");
    OpDispatchBuilder emitter(pool,false);unsigned old_maps=maps;
    emitter.ResetWorkingList();
    auto data=emitter.DualListData.DataBegin(),list=emitter.DualListData.ListBegin();
    assert(data&&list==data+8*1024*1024&&emitter.CodeBlocks.clears==1);
    assert(reinterpret_cast<uintptr_t>(emitter.InvalidNode)==list);
    assert(emitter.DualListData.ListSize()==sizeof(FEXCore::IR::OrderedNode));
    for(unsigned i=0;i<sizeof(FEXCore::IR::OrderedNode);i++)assert(!emitter.InvalidNode->bytes[i]);
    assert(reinterpret_cast<unsigned char*>(list)[20]==0xa5); // exact memset bound
    // A still-owned buffer survives subsequent OS allocation failure unchanged.
    failure=1;emitter.ResetWorkingList();
    assert(maps==old_maps+1&&emitter.DualListData.DataBegin()==data);
    assert(emitter.DualListData.ListBegin()==list&&emitter.CodeBlocks.clears==2);
  }
  assert(backing.empty());
  // Recently disowned storage remains reusable under real allocation pressure.
  failure=0;
  {
    PooledAllocatorVirtual pool("FEXMem_OpDispatcher");
    using Allocator=FEXCore::Utils::IntrusivePooledAllocator;
    Allocator::BufferOwnedFlag flag{Allocator::ClientFlags::FLAG_FREE};
    auto previous=pool.TryClaimBuffer(16*1024*1024,&flag);assert(previous);
    auto old=reinterpret_cast<uintptr_t>((**previous)->Ptr);
    pool.DisownBuffer(*previous);failure=1;unsigned old_maps=maps;
    OpDispatchBuilder emitter(pool,false);emitter.ResetWorkingList();
    assert(maps==old_maps+1&&flag==Allocator::ClientFlags::FLAG_FREE);
    assert(emitter.DualListData.DataBegin()==old);
    assert(emitter.DualListData.ListBegin()==old+8*1024*1024);
  }
  assert(backing.empty());
  puts("PASS ARM64EC staged OpDispatcher: NULL/MAP_FAILED/metadata failure never derive List=0x800000 or reset invalid storage; direct legacy path stops explicitly; valid reset, owned-buffer reuse and pressure reuse preserved");
}
'''
    source = directory / 'arm64ec-startup.cpp'
    source.write_text(code)
    executable = directory / 'arm64ec-startup'
    subprocess.run([
        os.environ.get('CXX', 'c++'), '-std=c++20', '-Wall', '-Wextra', '-Werror',
        '-Wno-unused-function', '-Wno-unused-parameter', '-Wno-misleading-indentation',
        '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-pthread',
        '-I' + str(stub), str(source), '-o', str(executable),
    ], check=True)
    subprocess.run([str(executable)], check=True)
