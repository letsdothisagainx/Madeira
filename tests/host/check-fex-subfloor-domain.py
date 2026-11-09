#!/usr/bin/env python3
"""Compile actual staged FEX subfloor dispatch/query/fetch/SMC/IR arithmetic.

Two independently loaded host libraries model the per-image private backend
state. The raw 4-GiB captures are checked numerically; real byte reads/writes
use owned host mappings, not MAP_FIXED over ASan/iOS reserved regions. This
executes production decoder reads and IR address construction with scalar IR
operation adapters; it does not run the complete FEX compiler or Valve's EXE.
"""
from pathlib import Path
import os
import platform
import re
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]


def function(source,signature):
    start=source.index(signature)
    brace=source.index('{',start)
    depth=0
    for token in re.finditer(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]',source[brace:],re.S):
        if token[0]=='{':depth+=1
        elif token[0]=='}':
            depth-=1
            if not depth:return source[start:brace+token.end()]
    raise AssertionError(signature)


def compiled_source(alias,module,capable):
    alias_prefix=alias[alias.index('struct IosAliasEntry {'):alias.index('\nextern "C" {\n\n// ml357:')]
    floor_mark='static constexpr uint64_t kIosSubfloorDefaultFloor' if capable else 'static constexpr uint64_t kIosSubfloorFloor'
    table=alias[alias.index(floor_mark):alias.index('/* ======================= end ml951 SUB-FLOOR WINDOWS')]
    alias_functions='\n'.join(function(alias,mark) for mark in (
        'void BTCpu64IosAddAliasMapping(', 'uint64_t IosJitTranslate(', 'uint64_t IosJitReverseTranslate('))
    query=function(module,'  FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(').replace(' override','')
    protect=function(module,'  void MarkGuestExecutableRange(').replace(' override','')
    notify=function(module,'void NotifyUnmapViewOfSection(')
    frontend=(ROOT/'FEX/FEXCore/Source/Interface/Core/Frontend.cpp').read_text()
    adjust_start=frontend.index('const Decoder::DecodeStream Decoder::AdjustAddrForSpecialRegion(')
    adjust=frontend[adjust_start:frontend.index('\n}',adjust_start)+2]  # both #ifdef return arms must remain intact
    peek=function(frontend,'std::optional<uint8_t> Decoder::PeekByte(')
    read=function(frontend,'std::pair<uint64_t, bool> Decoder::ReadData(')
    ir_header=(ROOT/'FEX/FEXCore/Source/Interface/Core/OpcodeDispatcher.h').read_text()
    translate=function(ir_header,'  Ref IosXlate(')
    accessors=function(ir_header,'  Ref _StoreMemAutoTSO(RegClass Class, OpSize Size, Ref Addr,')+'\n'+function(ir_header,'  Ref _LoadMemAutoTSO(RegClass Class, OpSize Size, Ref ssa0,')
    begin_function=function((ROOT/'FEX/FEXCore/Source/Interface/Core/OpcodeDispatcher.cpp').read_text(),'void OpDispatchBuilder::BeginFunction(')
    begin_start=begin_function.index('  {\n    uint64_t Low = 0, Sz = 0, Real = 0;')
    begin=begin_function[begin_start:begin_function.index('\n#endif',begin_start)]
    invalidation=(ROOT/'FEX/Source/Windows/Common/InvalidationTracker.cpp').read_text()
    paired=invalidation[invalidation.index('  {\n    const uint64_t End = Size >',invalidation.index('/* iOS-Madeira ml1207:')):]
    paired=paired[:paired.index('\n#endif')]
    primary_start=invalidation.index('  CTX.InvalidateCodeBuffersCodeRange(Address, Size);',invalidation.index('void InvalidationTracker::InvalidateIntervalInternalLocked('))
    primary=invalidation[primary_start:invalidation.index('\n#if defined(FEX_IOS_HOST)',primary_start)]
    return r'''
#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <map>
#include <tuple>
#include <mutex>
#include <thread>
#include <optional>
#include <algorithm>
#include <limits>
#define FEX_IOS_HOST 1
#define ASSERTIONS_ENABLED 0
#define LOGMAN_THROW_A_FMT(condition,...) assert(condition)
namespace LogMan::Msg {template<typename...T>void EFmt(T...) {}}
namespace FEXCore::Core {struct InternalThreadState {};}
namespace FEXCore::HLE {
struct ExecutableRangeInfo {uint64_t Base{},Size{};bool Writable{};};
enum class SyscallOSABI {OS_LINUX64,OS_WINDOWS};
}
''' + alias_prefix + table + alias_functions + r'''
static void observe_before_unmap(uint64_t,uint64_t);
struct Tracker {
    std::vector<FEXCore::HLE::ExecutableRangeInfo> ranges;
    std::vector<std::pair<uint64_t,uint64_t>> protected_ranges;
    FEXCore::HLE::ExecutableRangeInfo QueryExecutableRange(uint64_t address) {
        for(auto range:ranges)if(address>=range.Base&&address-range.Base<range.Size)return range;
        return {};
    }
    void ReprotectRWXIntervals(uint64_t address,uint64_t size){protected_ranges.emplace_back(address,size);}
    std::pair<uint64_t,uint64_t> InvalidateContainingSection(uint64_t address,bool free) {
        auto range=QueryExecutableRange(address);
        if(!range.Size)return {address,0};
        observe_before_unmap(range.Base,range.Size);
        if(free)ranges.clear(); // Match the legacy pre-unmap tracker removal.
        return {range.Base,range.Size};
    }
};
struct NativeModule {
    Tracker *InvalidationTracker;
''' + query + protect + r'''
};
using NativeRange=FEXCore::HLE::ExecutableRangeInfo;
static Tracker tracker;
static NativeModule module{&tracker};
struct Decoder {
    struct DecodeStream {const uint8_t *InstStream{},*AdjustedInstStream{};};
    FEXCore::HLE::SyscallOSABI OSABI=FEXCore::HLE::SyscallOSABI::OS_WINDOWS;
    static inline const uint8_t VSyscallData[4096]={0};
    enum class GuestRelocationType {Rel32,Rel64};
    static constexpr unsigned MAX_INST_SIZE=15;
    DecodeStream InstStream;
    uint8_t Instruction[15]{};unsigned InstructionSize{};
    bool HitNonExecutableRange{},HitBadRelocation{};
    uint64_t EntryPoint{},SectionMinAddress{};
    std::map<uint32_t,GuestRelocationType> *Relocations{};
    bool CheckRangeExecutable(uint64_t address,uint64_t size) {
        auto range=module.QueryGuestExecutableRange(nullptr,address);
        return range.Size&&address>=range.Base&&size<=range.Size-(address-range.Base);
    }
    void SkipBytes(uint8_t size){InstructionSize+=size;}
    const DecodeStream AdjustAddrForSpecialRegion(const uint8_t *,uint64_t,uint64_t);
    std::optional<uint8_t> PeekByte(uint8_t);
    std::pair<uint64_t,bool> ReadData(uint8_t);
};
''' + adjust + peek + read + r'''
// Scalar adapters execute exactly the IR nodes requested by production IosXlate.
// The complete FEX machine-code compiler is deliberately outside this fixture.
enum class RegClass {GPR,FPR};enum class MemOffsetType {SXTX};
struct IR {
    enum class OpSize {i8Bit=1,i64Bit=8};using Ref=uint64_t;
    struct {bool On{};uint64_t Low{},Size{},Delta{};} IosXl;
    bool tso{},last_tso{};
    Ref Invalid(){return 0;}
    bool IsTSOEnabled(RegClass){return tso;}
    Ref _LoadMem(RegClass,OpSize size,Ref address,Ref,OpSize,MemOffsetType,unsigned){
        last_tso=false;uint64_t value=0;assert(size==OpSize::i64Bit);std::memcpy(&value,reinterpret_cast<void*>(address),8);return value;
    }
    Ref _StoreMem(RegClass,OpSize size,Ref value,Ref address,Ref,OpSize,MemOffsetType,unsigned){
        last_tso=false;assert(size==OpSize::i64Bit);std::memcpy(reinterpret_cast<void*>(address),&value,8);return value;
    }
    Ref _LoadMemTSO(RegClass cls,OpSize size,Ref address,Ref extra,OpSize align,MemOffsetType type,unsigned scale){
        auto value=_LoadMem(cls,size,address,extra,align,type,scale);last_tso=true;return value;
    }
    Ref _StoreMemTSO(RegClass cls,OpSize size,Ref value,Ref address,Ref extra,OpSize align,MemOffsetType type,unsigned scale){
        auto result=_StoreMem(cls,size,value,address,extra,align,type,scale);last_tso=true;return result;
    }
    Ref Constant(uint64_t value){return value;}
    Ref Sub(OpSize,Ref a,Ref b){return a-b;}
    Ref Add(OpSize,Ref a,Ref b){return a+b;}
    Ref _Andn(OpSize,Ref a,Ref b){return a&~b;}
    Ref _And(OpSize,Ref a,Ref b){return a&b;}
    Ref _Ashr(OpSize,Ref a,Ref b){assert(b==63);return uint64_t(int64_t(a)>>b);}
''' + translate + accessors + r'''
    void Begin(uint64_t RIP) {
''' + begin + r'''
    }
};
struct Invalidator {
    struct Context {
        std::vector<std::pair<uint64_t,uint64_t>> code;
        std::map<uint64_t,uint8_t> cached;
        std::vector<std::tuple<void*,uint64_t,uint64_t>> thread_code;
        void InvalidateCodeBuffersCodeRange(uint64_t address,uint64_t size){
            code.emplace_back(address,size);
            for(auto it=cached.begin();it!=cached.end();) {
                if(it->first>=address&&it->first-address<size)it=cached.erase(it);else ++it;
            }
        }
        void InvalidateThreadCachedCodeRange(void *thread,uint64_t address,uint64_t size){thread_code.emplace_back(thread,address,size);}
    } CTX;
    std::vector<std::pair<unsigned,void*>> Threads{{1,(void*)1},{2,(void*)2}};
    void invalidate(uint64_t Address,uint64_t Size) {
''' + primary + paired + r'''
    }
};
using BOOL=bool;using NTSTATUS=int32_t;
#define NT_SUCCESS(value) (int32_t(value)>=0)
static Tracker *InvalidationTracker=&tracker;
static std::atomic<bool> ProcessTerminating{false};
struct CPUArea {bool active=true;void *ThreadState(){return active?reinterpret_cast<void*>(1):nullptr;}};
static CPUArea cpu_area;
static CPUArea &GetCPUArea(){return cpu_area;}
struct UnmapMutex {
    std::recursive_mutex mutex;unsigned held{};
    void lock(){mutex.lock();++held;}
    void unlock(){assert(held);--held;mutex.unlock();}
} ThreadCreationMutex;
static Invalidator unmap_invalidation;
static unsigned image_unmaps;
static void observe_before_unmap(uint64_t address,uint64_t size) {
    assert(ThreadCreationMutex.held);
    assert(IosSubfloorToLow(address)!=address); // Both names still exist during invalidation.
    unmap_invalidation.invalidate(address,size);
}
static void HandleImageUnmap(uint64_t address,uint64_t size) {
    assert(ThreadCreationMutex.held&&size&&IosSubfloorToLow(address)!=address);++image_unmaps;
}
''' + notify + r'''
#pragma GCC visibility push(default)
extern "C" {
uint64_t test_capability() {
#if CAPABLE
    return IosSubfloorProtocolV1;
#else
    return 0;
#endif
}
void test_register(uint64_t low,uint64_t real,uint64_t size){BTCpu64IosAddAliasMapping(low,real,size);}
uint64_t test_real(uint64_t address){return IosSubfloorToReal(address);}
uint64_t test_low(uint64_t address){return IosSubfloorToLow(address);}
unsigned test_subfloor_count(){
#if CAPABLE
return g_SubfloorCount+(g_ExtendedSubfloor.State.load(std::memory_order_acquire)==2);
#else
return g_SubfloorCount;
#endif
}
unsigned test_ordinary_count(){return g_EntryCount;}
uint64_t test_branch_target(uint64_t address){return IosJitTranslate(address);}
uint64_t test_clip(uint64_t address,uint64_t size){return IosSubfloorClipSize(address,size);}
int test_configure_contracts(uint64_t floor) {
#if CAPABLE
    assert(!IosSubfloorConfigureFloor(0));
    assert(!IosSubfloorConfigureFloor(0xffffffffull));
    assert(!IosSubfloorConfigureFloor(0x200001000ull));
    assert(!IosSubfloorConfigureFloor(floor+1));
    assert(g_SubfloorFloor.load()==0x100000000ull);
    BTCpu64IosAddAliasMapping(0,0,floor);
    assert(g_SubfloorFloor.load()==floor&&g_SubfloorCount==0&&g_EntryCount==0);
    assert(IosSubfloorConfigureFloor(floor));
    assert(!IosSubfloorConfigureFloor(floor+0x1000));
    assert(!IosSubfloorConfigureFloor(0x100000000ull));
    assert(g_SubfloorFloor.load()==floor);
    return 1;
#else
    return 0;
#endif
}
int test_mapping_contracts(uint64_t floor) {
#if CAPABLE
    const uint64_t low=0x100000000ull,real=0x13d700000ull,size=0x10000;
    assert(g_SubfloorCount==0&&g_EntryCount==0);
    BTCpu64IosAddAliasMapping(low,real,size);
    assert(g_SubfloorCount==0&&g_ExtendedSubfloor.State.load()==2&&g_EntryCount==0);
    assert(IosSubfloorToReal(low+0x4321)==real+0x4321);
    assert(IosSubfloorToLow(real+0x4321)==low+0x4321);
    assert(IosJitTranslate(low+0x1234)==low+0x1234); // never rewrite guest RIP
    assert(IosSubfloorClipSize(low+size-8,32)==8);
    assert(IosSubfloorToReal(low-1)==low-1&&IosSubfloorToReal(low+size)==low+size);
    assert(IosSubfloorToReal(floor)==floor);
    uint64_t saved=IosSubfloorToReal(low+0x40);
    BTCpu64IosAddAliasMapping(low,real+0x100000,size); // live identity cannot change
    BTCpu64IosAddAliasMapping(low+0x1000,real+0x200000,size); // overlap cannot publish
    assert(g_SubfloorCount==0&&g_ExtendedSubfloor.State.load()==2&&IosSubfloorToReal(low+0x40)==saved);
    BTCpu64IosAddAliasMapping(0,real,size);
    BTCpu64IosAddAliasMapping(0x1000,real,size);
    BTCpu64IosAddAliasMapping(low,real,0);
    BTCpu64IosAddAliasMapping(floor-0x1000,real,0x2000);
    BTCpu64IosAddAliasMapping(low+0x20000,UINT64_MAX-0x1000,0x2000);
    BTCpu64IosAddAliasMapping(low+0x20000,floor-0x1000,0x1000);
    assert(g_SubfloorCount==0&&g_ExtendedSubfloor.State.load()==2&&g_EntryCount==0);
    // Existing <4-GiB guest windows remain supported and isolated from branch aliases.
    BTCpu64IosAddAliasMapping(0x400000,real+0x300000,0x10000);
    assert(IosSubfloorToReal(0x401234)==real+0x301234&&g_EntryCount==0);
    // True mapped PE aliases at/above the configured floor keep their original contract.
    BTCpu64IosAddAliasMapping(floor+0x100000,0x300000000ull,0x20000);
    assert(g_EntryCount==1&&IosJitTranslate(floor+0x101234)==0x300001234ull);
    assert(IosJitReverseTranslate(0x300001234ull)==floor+0x101234);
    return 1;
#else
    return 0;
#endif
}
int test_capacity_contracts(uint64_t floor) {
#if CAPABLE
    (void)floor;
    while(g_SubfloorCount<kMaxSubfloorEntries) {
        uint64_t slot=g_SubfloorCount;
        BTCpu64IosAddAliasMapping(0x1000000ull+slot*0x20000,0x140000000ull+slot*0x20000,0x10000);
    }
    auto count=g_SubfloorCount;
    BTCpu64IosAddAliasMapping(0x2000000ull,0x150000000ull,0x10000);
    assert(g_SubfloorCount==count&&IosSubfloorToReal(0x2000000ull)==0x2000000ull);
    BTCpu64IosAddAliasMapping(0x102000000ull,0x150000000ull,0x10000);
    assert(g_SubfloorCount==count&&IosSubfloorToReal(0x102000000ull)==0x102000000ull);
    return 1;
#else
    return 0;
#endif
}
int test_real_bytes(uint8_t *backing,size_t bytes,uint64_t floor) {
#if CAPABLE
    assert(bytes>=0x4000);
    const uint64_t low=0x100000000ull,real=reinterpret_cast<uint64_t>(backing),size=0x4000;
    assert(real>=floor);
    // A new private image instance starts with an empty table; native ownership
    // and generation admission are separately exercised by the Wine harness.
    assert(g_SubfloorCount==0);
    BTCpu64IosAddAliasMapping(0,0,floor);BTCpu64IosAddAliasMapping(low,real,size);
    assert(g_SubfloorCount==0&&g_ExtendedSubfloor.State.load()==2&&g_EntryCount==0);
    tracker.ranges={{real,size,true}};
    const uint8_t code[]={0x48,0xa1,0x00,0x01,0x00,0x00,0x01,0x00,0x00,0x00};
    std::memcpy(backing,code,sizeof code);
    uint64_t payload=0x1122334455667788ull;std::memcpy(backing+0x100,&payload,sizeof payload);
    auto range=module.QueryGuestExecutableRange(nullptr,low);
    assert(range.Base==low&&range.Size==size&&range.Writable);
    tracker.ranges={{real,size+0x1000,true}};
    range=module.QueryGuestExecutableRange(nullptr,low+0x10);
    assert(range.Base==low&&range.Size==size); // preserve true mapped window bound
    Decoder decoder;decoder.EntryPoint=low;
    decoder.InstStream=decoder.AdjustAddrForSpecialRegion(reinterpret_cast<const uint8_t*>(low),low,low);
    assert(reinterpret_cast<uint64_t>(decoder.InstStream.InstStream)==low);
    assert(decoder.InstStream.AdjustedInstStream==backing);
    assert(decoder.PeekByte(0)==0x48);decoder.SkipBytes(1);
    assert(decoder.PeekByte(0)==0xa1);decoder.SkipBytes(1);
    auto absolute=decoder.ReadData(8);
    assert(absolute.first==low+0x100&&!absolute.second&&!decoder.HitNonExecutableRange);
    IR ir;ir.Begin(low);assert(ir.IosXl.On);
    auto address=ir.IosXlate(absolute.first);assert(address==real+0x100);
    uint64_t loaded=ir._LoadMemAutoTSO(RegClass::GPR,IR::OpSize::i64Bit,absolute.first);
    assert(loaded==payload&&!ir.last_tso);
    uint64_t updated=loaded+1;
    ir._StoreMemAutoTSO(RegClass::GPR,IR::OpSize::i64Bit,low+0x100,updated);assert(!ir.last_tso);
    ir.tso=true;loaded=ir._LoadMemAutoTSO(RegClass::GPR,IR::OpSize::i64Bit,low+0x100);
    assert(loaded==payload+1&&ir.last_tso);
    ir._StoreMemAutoTSO(RegClass::GPR,IR::OpSize::i64Bit,low+0x100,payload+2);assert(ir.last_tso);
    std::memcpy(&loaded,backing+0x100,sizeof loaded);assert(loaded==payload+2);
    assert(ir.IosXlate(low-1)==low-1&&ir.IosXlate(low+size)==low+size&&ir.IosXlate(UINT64_MAX)==UINT64_MAX);
    IR ordinary;ordinary.Begin(floor+0x100000);assert(!ordinary.IosXl.On&&ordinary.IosXlate(low+0x100)==low+0x100);
    module.MarkGuestExecutableRange(nullptr,low+0x100,size);
    assert(tracker.protected_ranges.size()==2);
    assert(tracker.protected_ranges[0]==std::make_pair(real+0x100,size-0x100));
    assert(tracker.protected_ranges[1]==std::make_pair(low+size,0x100ull));
    Invalidator invalidator;invalidator.invalidate(real+0x100,8);
    assert(invalidator.CTX.code.size()==2&&invalidator.CTX.code[0]==std::make_pair(real+0x100,8ull));
    assert(invalidator.CTX.code[1]==std::make_pair(low+0x100,8ull)&&invalidator.CTX.thread_code.size()==4);
    Invalidator low_writer;low_writer.invalidate(low+0x100,8);
    assert(low_writer.CTX.code.size()==2&&low_writer.CTX.code[1]==std::make_pair(real+0x100,8ull));
    // A patch of the actual instruction byte invalidates both cached names;
    // the actual frontend then fetches the new backing byte at the same RIP.
    Invalidator patch;patch.CTX.cached={{low,0x48},{real,0x48}};
    backing[0]=0x90;patch.invalidate(low,1);
    assert(patch.CTX.cached.empty());decoder.InstructionSize=0;
    assert(decoder.PeekByte(0)==0x90);
    tracker.ranges.clear();assert(!module.QueryGuestExecutableRange(nullptr,low).Size);
    assert(!decoder.PeekByte(0)); // no invented executable permission
    return 1;
#else
    (void)backing;(void)bytes;(void)floor;return 0;
#endif
}
int test_unmap_lifetime(uint8_t *backing) {
#if CAPABLE
    const uint64_t low=0x100000000ull,real=reinterpret_cast<uint64_t>(backing),size=0x4000;
    assert(IosSubfloorToReal(low)==real);
    tracker.ranges={{real,size,true}};
    ProcessTerminating=true;NotifyUnmapViewOfSection(reinterpret_cast<void*>(low),false,0);
    assert(!ThreadCreationMutex.held&&tracker.ranges.size()==1);ProcessTerminating=false;
    cpu_area.active=false;NotifyUnmapViewOfSection(reinterpret_cast<void*>(low),false,0);
    assert(!ThreadCreationMutex.held&&tracker.ranges.size()==1);cpu_area.active=true;
    NotifyUnmapViewOfSection(reinterpret_cast<void*>(low),false,0);
    assert(ThreadCreationMutex.held==1&&image_unmaps==1&&unmap_invalidation.CTX.code.size()==2);
    assert(unmap_invalidation.CTX.code[0]==std::make_pair(real,size));
    assert(unmap_invalidation.CTX.code[1]==std::make_pair(low,size));
    assert(IosSubfloorToReal(low)==real); // Retirement may not precede paired invalidation.
    NotifyUnmapViewOfSection(reinterpret_cast<void*>(low),true,int32_t(0xc0000018u));
    assert(!ThreadCreationMutex.held&&IosSubfloorToReal(low)==real);
    // Failure retains only the query alias metadata. Legacy NotifyUnmap already
    // removed tracker intervals BEFORE the real status; this fixture does not
    // pretend those permissions have been restored by the new retirement hook.
    assert(tracker.ranges.empty());
    tracker.ranges={{real,size,true}};
    NotifyUnmapViewOfSection(reinterpret_cast<void*>(real),false,0);
    NotifyUnmapViewOfSection(reinterpret_cast<void*>(real),true,0);
    assert(!ThreadCreationMutex.held&&IosSubfloorToReal(low)==low);
    tracker.ranges={{real,size,true}}; // Another image at the same backing VA.
    assert(!module.QueryGuestExecutableRange(nullptr,low).Size);
    BTCpu64IosAddAliasMapping(low,real,size);
    assert(IosSubfloorToReal(low)==low&&g_ExtendedSubfloor.State.load()==3);
    BTCpu64IosAddAliasMapping(low+0x10000,real,size);
    assert(IosSubfloorToReal(low+0x10000)==low+0x10000&&!ThreadCreationMutex.held);
    BTCpu64IosAddAliasMapping(0x400000,real,size);
    IosSubfloorRetireMapping(0x400000);assert(IosSubfloorToReal(0x400000)==real);
    return 1;
#else
    (void)backing;return 0;
#endif
}
int test_concurrent_retire() {
#if CAPABLE
    const uint64_t low=0x100000000ull,real=0x13d700000ull,size=0x10000;
    assert(g_ExtendedSubfloor.State.load()==2);
    const uint64_t frozenLow=g_ExtendedSubfloor.LowBase,frozenReal=g_ExtendedSubfloor.RealBase,frozenSize=g_ExtendedSubfloor.Size;
    std::atomic<unsigned> ready{0};std::atomic<bool> start{false};std::vector<std::thread> readers;
    for(unsigned n=0;n<8;n++)readers.emplace_back([&]{
        uint64_t l,r,z;assert(IosExtendedSubfloorSnapshot(&l,&r,&z)&&l==low&&r==real&&z==size);
        ready.fetch_add(1,std::memory_order_release);while(!start.load(std::memory_order_acquire)){}
        for(unsigned i=0;i<50000;i++){
            auto translated=IosSubfloorToReal(low+0x40);assert(translated==real+0x40||translated==low+0x40);
            auto reverse=IosSubfloorToLow(real+0x40);assert(reverse==low+0x40||reverse==real+0x40);
            if(IosExtendedSubfloorSnapshot(&l,&r,&z))assert(l==low&&r==real&&z==size);
            if(IosSubfloorWindowForCode(low+0x40,&l,&z,&r))assert(l==low&&r==real&&z==size);
            auto clipped=IosSubfloorClipSize(low+size-8,32);assert(clipped==0||clipped==8);
            assert(IosSubfloorEnum(0,&l,&r,&z));if(z)assert(l==low&&r==real&&z==size);
        }
    });
    while(ready.load(std::memory_order_acquire)!=8){}
    tracker.ranges={{real,size,true}};start.store(true,std::memory_order_release);
    NotifyUnmapViewOfSection(reinterpret_cast<void*>(low),false,0);
    NotifyUnmapViewOfSection(reinterpret_cast<void*>(low),true,0);
    for(auto &reader:readers)reader.join();
    assert(g_ExtendedSubfloor.State.load()==3&&IosSubfloorToReal(low)==low&&IosSubfloorToLow(real)==real);
    assert(g_ExtendedSubfloor.LowBase==frozenLow&&g_ExtendedSubfloor.RealBase==frozenReal&&g_ExtendedSubfloor.Size==frozenSize);
    BTCpu64IosAddAliasMapping(low,real,size);assert(g_ExtendedSubfloor.State.load()==3&&IosSubfloorToReal(low)==low);
    // Reuse of the old host VA by another legacy window must not answer the old logical query.
    BTCpu64IosAddAliasMapping(0x600000,real,size);tracker.ranges={{real,size,true}};
    assert(!module.QueryGuestExecutableRange(nullptr,low).Size);
    return 1;
#else
    return 0;
#endif
}
int test_legacy_control(uint64_t floor) {
#if CAPABLE
    (void)floor;return 0;
#else
    uint64_t low=0x100000000ull,real=0x13d700000ull;
    assert(!test_capability());
    BTCpu64IosAddAliasMapping(low,real,0x10000);
    assert(g_SubfloorCount==0&&g_EntryCount==1);
    assert(IosSubfloorToReal(low)==low&&IosJitTranslate(low)==real);
    tracker.ranges={{real,0x10000,false}};
    assert(module.QueryGuestExecutableRange(nullptr,low).Size==0);
    Decoder decoder;
    auto stream=decoder.AdjustAddrForSpecialRegion(reinterpret_cast<const uint8_t*>(low),low,low);
    assert(reinterpret_cast<uint64_t>(stream.AdjustedInstStream)==low);
    assert(floor>low);return 1;
#endif
}
}
#pragma GCC visibility pop
'''.replace('CAPABLE',str(int(capable)))


main=r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
struct Backend {
    void *image;
    uint64_t (*capability)();void (*mapping)(uint64_t,uint64_t,uint64_t);
    uint64_t (*real)(uint64_t);unsigned (*count)();
    int (*configure)(uint64_t),(*contracts)(uint64_t),(*capacity)(uint64_t),(*legacy)(uint64_t);
    int (*bytes)(uint8_t*,size_t,uint64_t);
    int (*unmap)(uint8_t*);int (*concurrent)();
    template<typename T>T symbol(const char *name){auto fn=dlsym(image,name);assert(fn);return reinterpret_cast<T>(fn);}
    explicit Backend(const char *path):image(dlopen(path,RTLD_NOW|RTLD_LOCAL)) {
        if(!image){std::fprintf(stderr,"dlopen:%s\n",dlerror());std::abort();}
        capability=symbol<decltype(capability)>("test_capability");mapping=symbol<decltype(mapping)>("test_register");
        real=symbol<decltype(real)>("test_real");count=symbol<decltype(count)>("test_subfloor_count");
        configure=symbol<decltype(configure)>("test_configure_contracts");contracts=symbol<decltype(contracts)>("test_mapping_contracts");
        capacity=symbol<decltype(capacity)>("test_capacity_contracts");legacy=symbol<decltype(legacy)>("test_legacy_control");
        bytes=symbol<decltype(bytes)>("test_real_bytes");
        unmap=symbol<decltype(unmap)>("test_unmap_lifetime");
        concurrent=symbol<decltype(concurrent)>("test_concurrent_retire");
    }
    ~Backend(){assert(!dlclose(image));}
};
int main(int argc,char **argv) {
    assert(argc==4);constexpr uint64_t floor=0x1044f8000ull;
    Backend legacy(argv[1]);assert(legacy.legacy(floor));
    puts("PASS unchanged production control:4GiB preferred address entered ordinary branch-alias table, executable query missed and frontend byte source remained unmappedlogicalRIP");
    Backend ownerA(argv[2]),ownerB(argv[3]);
    assert(ownerA.capability()==0x4d53460100000001ull&&ownerB.capability()==ownerA.capability());
    assert(ownerA.configure(floor)&&ownerA.contracts(floor));
    assert(ownerB.count()==0&&ownerB.real(0x100000000ull)==0x100000000ull);
    void *mapping=mmap(nullptr,0x4000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(mapping!=MAP_FAILED);
    assert(ownerB.bytes(static_cast<uint8_t*>(mapping),0x4000,floor));
    assert(ownerB.unmap(static_cast<uint8_t*>(mapping)));
    assert(ownerA.real(0x100000000ull)==0x13d700000ull);
    assert(ownerA.capacity(floor));assert(ownerA.concurrent());
    assert(!munmap(mapping,0x4000));
    puts("PASS staged production two private backend images: protocolfloor configure/bounds/immutability, exact0x100000000 highbit capture, liveoverlap/fulltable refusal, normalaliases and per-image isolation");
    puts("PASS actual frontend PeekByte/ReadData and executable query retain logicalRIP while reading owned backing; production IosXlate IR nodes address absolute64bit loads/stores correctly; real bytes preserved");
    puts("PASS production MarkGuestExecutableRange protects realbacking and clipscrosswindowtail; actual pairedSMC invalidation reaches bothguest/backing cachedcode names without inventing permissions");
    puts("PASS actual NotifyUnmap callback: both address names invalidate before successful retirement; failure retains query alias metadata only (legacy pre-unmap tracker removal unchanged); backing VA reuse cannot revive a retired alias");
    puts("PASS sole extended descriptor:8 readers perform400000 snapshot/lookup/clip/enum operations across atomic retirement; coordinates remain immutable and State3 forbids revival/ABA; legacy table capacity stays8");
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-fex-subfloor-domain-') as folder:
    directory=Path(folder);staged=directory/'staged'
    subprocess.run(['python3',str(ROOT/'tools/build/stage-fex-compat.py'),'stage',str(staged),'--backend','arm64ec'],check=True)
    new_alias=(staged/'Source/Windows/ARM64EC/IosJitAlias.cpp').read_text()
    new_module=(staged/'Source/Windows/ARM64EC/Module.cpp').read_text()
    old_alias=(ROOT/'FEX/Source/Windows/ARM64EC/IosJitAlias.cpp').read_text()
    old_module=(ROOT/'FEX/Source/Windows/ARM64EC/Module.cpp').read_text()
    assert re.search(r'^\s+IosSubfloorProtocolV1 DATA$',(staged/'Source/Windows/ARM64EC/libarm64ecfex_ios.def').read_text(),re.M)
    sources=[compiled_source(old_alias,old_module,False),compiled_source(new_alias,new_module,True),compiled_source(new_alias,new_module,True)]
    cxx=os.environ.get('CXX','c++');common=['-std=c++20','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-unused-function','-fsanitize=address,undefined','-fno-sanitize-recover=all']
    libraries=[]
    for index,text in enumerate(sources):
        source=directory/f'backend{index}.cpp';source.write_text(text)
        library=directory/f'backend{index}.so';libraries.append(library)
        link=['-dynamiclib','-Wl,-install_name,'+str(library)] if platform.system()=='Darwin' else ['-shared']
        subprocess.run([cxx,*common,'-fPIC','-fvisibility=hidden',*link,str(source),'-o',str(library)],check=True)
    source=directory/'main.cpp';source.write_text(main);binary=directory/'check'
    dl=[] if platform.system()=='Darwin' else ['-ldl']
    subprocess.run([cxx,*common,str(source),*dl,'-o',str(binary)],check=True)
    subprocess.run([str(binary),*(str(p) for p in libraries)],check=True,timeout=30)
