#!/usr/bin/env python3
"""Replay Run10's large-upload charge with the real staged initializer/ring.

The matching cube-array layout is a controlled witness, not a recovered game
descriptor. Metal command execution/completion and native pressure are explicit
host adapters. Allocation, forecasting, bounded growth and reclamation execute
the production methods unchanged; no iPhone footprint/FPS result is implied.
"""
from pathlib import Path
import importlib.util
import hashlib
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def load(name, relative):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def declaration(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + (';' if source[end:end + 1] == ';' else '')


upload = load('bounded_upload', 'tools/build/stage-dxmt-upload-memory.py')
failure = load('bounded_failure', 'tools/build/stage-dxmt-initializer-failure.py')
admission = load('bounded_admission', 'tools/build/stage-dxmt-texture-admission.py')
accounting = load('bounded_accounting', 'tools/build/stage-dxmt-texture-accounting.py')
cpp = failure.stage_cpp(upload.stage_initializer((ROOT / 'dxmt/src/dxmt/dxmt_resource_initializer.cpp').read_text()))
header = failure.stage_header(upload.stage_initializer_header((ROOT / 'dxmt/src/dxmt/dxmt_resource_initializer.hpp').read_text()))
factory = admission.stage_factory((ROOT / 'dxmt/src/d3d11/d3d11_texture_device.cpp').read_text())
ring = upload.stage_ring((ROOT / 'dxmt/src/dxmt/dxmt_ring_bump_allocator.hpp').read_text())
ring_type = ring[ring.index('template <typename Allocator, size_t BlockSize ='):ring.index('\nclass GpuPrivateBufferBlockAllocator')]
ring_methods = ring[ring.index('template <typename Allocator, size_t BlockSize, class mutex>\nstd::pair'):ring.rindex('\n} // namespace dxmt')]
initializer = declaration(cpp, 'uint64_t\nResourceInitializer::initWithData(')
assert initializer.index('if (!prepareUploadLocked') < initializer.index('ALLOC_GPU(temp,') < initializer.index('RETAIN(allocation);') < initializer.index('ALLOC_BLIT(')
allocation = declaration(cpp, 'WMT::Buffer\nResourceInitializer::allocateGpuHeap(')
assert 'flushInternal(' not in allocation and 'prepareUploadLocked(' not in allocation
assert 'if (!initializer.initWithData(' in factory and 'return E_OUTOFMEMORY;' in factory

policy = (ROOT / 'build/dxmt-ios/memory_pressure.hpp').read_text()
policy = policy[policy.index('struct MemoryPressureSnapshot'):policy.index('namespace memory_pressure_detail')]
wmt = (ROOT / 'dxmt/src/winemetal/winemetal.h').read_text()
enums = '\n'.join(declaration(wmt, item) for item in (
    'enum WMTPixelFormat :', 'enum WMTResourceOptions :', 'enum WMTTextureType :',
    'enum WMTTextureUsage :', 'struct WMTTextureInfo {'))
census = accounting.stage_file('src/dxmt/dxmt_mem_census.hpp', (ROOT / 'dxmt/src/dxmt/dxmt_mem_census.hpp').read_text())
helpers = '\n'.join('inline ' + declaration(census, item) for item in (
    'uint32_t\nmem_census_texel_bytes(', 'uint32_t\nmem_census_bc_block_bytes(',
    'uint64_t\nmem_census_capacity_mul(', 'uint64_t\nmem_census_texture_bytes('))
scope = declaration(header, '  class TextureUploadScope {') + '\n' + declaration(header, '  TextureUploadScope textureUploadScope()')
lock = declaration(header, '  std::unique_lock<std::recursive_mutex> lockTextureCreation()')
methods = '\n'.join(declaration(cpp, signature) for signature in (
    'std::uint64_t\nResourceInitializer::flushInternal(', 'uint64_t\nResourceInitializer::flushToWait(',
    'uint64_t\nResourceInitializer::refreshCompletedLocked(', 'uint64_t\nResourceInitializer::trimMemoryPressure(',
    'MemoryPressureDecision\nResourceInitializer::transientMemoryPressureDecision(',
    'uint64_t\nResourceInitializer::initializationFence(', 'size_t\nResourceInitializer::forecastUploadGrowth(',
    'bool\nResourceInitializer::prepareUploadLocked(', 'WMT::Buffer\nResourceInitializer::allocateGpuHeap('))
baseline = (ROOT / 'tests/host/fixtures/dxmt-run10-upload-forecast.cpp').read_text()
assert hashlib.sha256(baseline.encode()).hexdigest() == '8bd57c316c26f36637fe9ccf708d8df0814c3eaf3533aef5f3425f3caa1c0db3'

C = r'''
#include <algorithm>
#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <utility>
#include <vector>
#define WARN(...) ((void)0)
using mach_port_t=uint32_t;
#define ORIGINAL_FORMAT(format) (format & ~WMTPixelFormatCustomSwizzle)
constexpr uint64_t MiB=uint64_t{1}<<20;
static size_t natural_size;
struct Stats {size_t allocations=0,frees=0,bytes=0,peak=0;} stats;
struct Payload {
 std::vector<uint8_t> bytes;
 explicit Payload(size_t count):bytes(count){++stats.allocations;stats.bytes+=count;stats.peak=std::max(stats.peak,stats.bytes);}
 ~Payload(){++stats.frees;assert(stats.bytes>=bytes.size());stats.bytes-=bytes.size();}
};
namespace WMT {
struct Buffer {
 std::shared_ptr<Payload> payload;
 explicit operator bool()const{return !!payload;}
 void updateContents(size_t offset,const void*data,size_t size){assert(payload&&offset+size<=payload->bytes.size());memcpy(payload->bytes.data()+offset,data,size);}
};
struct Command {Buffer source;size_t offset,size,destination;uint8_t value;std::shared_ptr<std::vector<uint8_t>> target;bool initialized=true;};
struct Event {
 uint64_t value=0,submitted=0;unsigned waits=0,commits=0;bool complete_wait=true;
 std::vector<Command> recording,pending;size_t copied=0;
 uint64_t signaledValue(){return value;}
 void complete(){
  for(auto &c:pending){assert(c.initialized&&c.source&&c.target&&c.offset+c.size<=c.source.payload->bytes.size());
   for(size_t i=0;i<c.size;++i)assert(c.source.payload->bytes[c.offset+i]==c.value);
   memcpy(c.target->data()+c.destination,c.source.payload->bytes.data()+c.offset,c.size);copied+=c.size;}
  pending.clear();value=submitted;
 }
 bool waitUntilSignaledValue(uint64_t wanted,uint64_t timeout){++waits;assert(timeout==50);if(complete_wait)complete();return value>=wanted;}
};
struct CommandBuffer {
 Event*event;uint64_t signal=0;
 void encodeSignalEvent(Event&,uint64_t target){signal=target;}
 void commit(){assert(signal);event->submitted=signal;++event->commits;
  for(auto &c:event->recording){assert(c.initialized);event->pending.push_back(std::move(c));}event->recording.clear();}
};
struct Queue {Event*event;CommandBuffer commandBuffer(){return {event};}};
struct Pool{};Pool MakeAutoreleasePool(){return {};}
}
namespace dxmt {
using mutex=std::mutex;
template<class T,class U>size_t align(T v,U a){return (size_t(v)+size_t(a)-1)&~(size_t(a)-1);}
constexpr size_t kStagingBlockSize=32*MiB,kStagingBlockLifetime=300;
size_t madeiraRingBlockSize(size_t){return natural_size;}
bool ringOversizeReuseEnabled(){return false;}
struct Logger{template<class...T>static void info(T&&...) {}};
'''+enums+'\n'+helpers+'\n'+policy+r'''
MemoryPressureSnapshot pressure;
MemoryPressureSnapshot memoryPressureSnapshot(bool=false){return pressure;}
'''+ring_type+'\n'+ring_methods+r'''
struct CountingAllocator {
 struct Block {WMT::Buffer buffer;Block()=default;Block(Block&&)=default;Block&operator=(Block&&)=default;Block(const Block&)=delete;};
 Block allocate(size_t size){Block b;b.buffer.payload=std::make_shared<Payload>(size);return b;}
};
constexpr size_t kResourceInitializerGpuUploadHeapSize=32*MiB,kResourceInitializerGpuUploadHeapAlignment=256;
constexpr int MEMOWN_INIT_UPLOAD=0;
void mem_census_sub(int,uint64_t){}
class ResourceInitializer {
public:
 std::recursive_mutex creation_mutex_;std::mutex mutex_;
 MemoryPressureController transient_pressure_controller_;
 size_t texture_upload_minimum_=0,texture_upload_budget_=0,texture_upload_spent_=0;
 bool texture_upload_active_=false;
 uint64_t current_seq_id_=1,cached_coherent_seq_id=0;
 size_t upload_bytes_since_flush_=0;
 std::shared_ptr<std::vector<uint8_t>> zero_buffer_;uint64_t zero_buffer_census_=0;size_t zero_buffer_size_=0;
 WMT::Event upload_queue_event_;WMT::Queue upload_queue_{&upload_queue_event_};
 RingBumpState<CountingAllocator,32*MiB> gpu_command_heap_allocator{CountingAllocator{}};
 bool pending=false;
 bool idle(){return !pending;}
 void reset(){pending=false;upload_bytes_since_flush_=0;}
 void encode(WMT::CommandBuffer){for(const auto &c:upload_queue_event_.recording)assert(c.initialized&&c.target);}
 uint64_t flushInternal();uint64_t flushToWait();uint64_t refreshCompletedLocked(bool,bool=false);
 uint64_t trimMemoryPressure(bool=false);MemoryPressureDecision transientMemoryPressureDecision();
 uint64_t initializationFence();size_t forecastUploadGrowth(size_t,size_t=0,bool=false);
 size_t forecastZeroGrowth(size_t){assert(false);return 0;}
 bool prepareUploadLocked(size_t);WMT::Buffer allocateGpuHeap(size_t,size_t&);
 size_t uploadBlockSize()const{return gpu_command_heap_allocator.ring_block_size();}
'''+lock+'\n'+scope+'\n};\n'+methods+r'''
class LegacyInitializer:public ResourceInitializer {public:size_t forecastUploadGrowth(size_t,size_t=0,bool=false);};
'''+r'''
static WMTTextureInfo matching_layout(){WMTTextureInfo info{};info.type=WMTTextureTypeCubeArray;
 info.pixel_format=WMTPixelFormatBC7_RGBAUnorm;info.width=info.height=256;info.depth=1;
 info.array_length=116;info.mipmap_level_count=7;info.sample_count=1;return info;}
'''+baseline

for name, body, initializer_type in (
        ('bounded_factory_charge', factory, 'ResourceInitializer'),):
    forecast = declaration(body, '  auto forecast_creation = [&]() -> uint64_t {')
    C += 'uint64_t '+name+'('+initializer_type+r''' &creation_initializer) {
 auto info=matching_layout();const bool admission_native_bc=true;
 const uint64_t creation_bytes=mem_census_texture_bytes(info,true);
 const void*pInitialData=reinterpret_cast<void*>(1);
'''+forecast+'\n return forecast_creation();\n}\n'

C += r'''
static void sample(uint64_t available){pressure={6139771056ull,available,6144*MiB,768*MiB,1,true};}
static bool send(ResourceInitializer &init,const std::shared_ptr<std::vector<uint8_t>>&target,unsigned slice,unsigned mip,size_t destination){
 const size_t size=size_t(65536)>>(2*mip);uint8_t value=uint8_t((slice*7+mip)%251+1);
 std::vector<uint8_t> source(size,value);
 std::lock_guard<std::recursive_mutex> creation(init.creation_mutex_);std::lock_guard<std::mutex> lock(init.mutex_);
 // The exact production loop has this preflight at the head of each retry,
 // before ALLOC_GPU then RETAIN then ALLOC_BLIT. Keep test commands complete.
 if(!init.prepareUploadLocked(size))return false;
 size_t offset=0;auto block=init.allocateGpuHeap(size,offset);if(!block)return false;
 block.updateContents(offset,source.data(),size);
 init.upload_queue_event_.recording.push_back({block,offset,size,destination,value,target,true});
 init.pending=true;return true;
}
static void verify(const std::vector<uint8_t>&target){size_t position=0;
 for(unsigned face=0;face<696;++face)for(unsigned mip=0;mip<7;++mip){
  size_t size=size_t(65536)>>(2*mip);uint8_t value=uint8_t((face*7+mip)%251+1);
  for(size_t i=0;i<size;++i)assert(target[position+i]==value);position+=size;}
 assert(position==60813696&&target.size()==position);
}
static void run(size_t cap){
 natural_size=cap;stats={};sample(302679888);
 {
 LegacyInitializer old;auto transaction=old.lockTextureCreation();auto scope=old.textureUploadScope();
 uint64_t charge=legacy_factory_charge(old);
 assert(charge==184925808&&charge-60813696==124112112&&stats.allocations==0);
 assert(charge>302679888ull-201326592ull);
 printf("BASELINE actual factory charge=%llu temporary=%llu; matching-layout request denied at unchanged floor\n",
        (unsigned long long)charge,(unsigned long long)(charge-60813696));
 }
 {
 ResourceInitializer init;auto target=std::make_shared<std::vector<uint8_t>>(60813696,0);
 {
 auto transaction=init.lockTextureCreation();auto scope=init.textureUploadScope();
 uint64_t charge=bounded_factory_charge(init);
 assert(charge==60813696+cap&&charge<=302679888ull-201326592ull);
 assert(!init.texture_upload_active_&&stats.allocations==0);
 // Forecast alone must not protect a cache against an explicit denial drain.
 init.gpu_command_heap_allocator.allocate(1,0,cap,256,cap);init.current_seq_id_=2;init.upload_queue_event_.value=1;
 assert(init.trimMemoryPressure(true)==cap&&!stats.bytes);
 size_t allocation_start=stats.allocations,position=0;
 for(unsigned face=0;face<696;++face)for(unsigned mip=0;mip<7;++mip){
  assert(send(init,target,face,mip,position));position+=size_t(65536)>>(2*mip);
  if(face%31==0){init.trimMemoryPressure(true);assert(stats.bytes<=cap);}
 }
 assert(position==60813696&&init.texture_upload_spent_==cap&&stats.allocations==allocation_start+1);
 auto submitted=init.flushToWait();if(submitted)init.upload_queue_event_.waitUntilSignaledValue(submitted,50);
 assert(init.upload_queue_event_.copied==position&&stats.bytes==cap);
 verify(*target);
 printf("PASS actual bounded allocator cap=%zu: all4872subresources/%zu bytes uploaded, one new block, peak<=cap, real event reuse, complete command/retain ownership\n",cap,position);
 }
 // Two maps may legitimately overlap while the application still owns the
 // departing map. Bound transient storage without destroying either owner.
 auto incoming=std::make_shared<std::vector<uint8_t>>(60813696,0);
 std::weak_ptr<std::vector<uint8_t>> departing=target;
 {
 auto transaction=init.lockTextureCreation();auto scope=init.textureUploadScope();
 auto before=stats.allocations;
 assert(bounded_factory_charge(init)==60813696+cap);
 size_t position=0;
 for(unsigned face=0;face<696;++face)for(unsigned mip=0;mip<7;++mip){
  assert(send(init,incoming,face,mip,position));position+=size_t(65536)>>(2*mip);
 }
 auto submitted=init.flushToWait();if(submitted)init.upload_queue_event_.waitUntilSignaledValue(submitted,50);
 assert(stats.allocations==before&&stats.bytes==cap&&init.texture_upload_spent_==0);
 verify(*target);verify(*incoming);assert(!departing.expired());
 }
 target.reset();assert(departing.expired());
 puts("PASS map-transition ownership: departing and incoming full contents remain valid while owned; same upload block reused, departing object releases only with its owner");
 init.trimMemoryPressure(true);assert(!stats.bytes);
 }
 assert(stats.allocations==stats.frees&&stats.peak<=cap);
 {
 ResourceInitializer init;init.upload_queue_event_.complete_wait=false;
 auto target=std::make_shared<std::vector<uint8_t>>(60813696);std::weak_ptr<std::vector<uint8_t>> weak=target;
 {
 auto transaction=init.lockTextureCreation();auto scope=init.textureUploadScope();
 assert(bounded_factory_charge(init)==60813696+cap);
 size_t position=0;bool refused=false;
 for(unsigned face=0;face<696&&!refused;++face)for(unsigned mip=0;mip<7;++mip){
  if(!send(init,target,face,mip,position)){refused=true;break;}position+=size_t(65536)>>(2*mip);
 }
 assert(refused&&init.texture_upload_spent_==cap&&stats.bytes==cap);
 assert(init.upload_queue_event_.waits==1&&init.upload_queue_event_.copied==0);
 }
 target.reset();assert(!weak.expired());init.trimMemoryPressure(true);assert(stats.bytes==cap);
 init.upload_queue_event_.complete();init.trimMemoryPressure(true);
 assert(!stats.bytes&&weak.expired());
 puts("PASS unsignalled GPU: bounded producer refuses second block/unfinished resource, pending bytes and destination remain owned until actual completion");
 }
 assert(stats.allocations==stats.frees);
 {
 ResourceInitializer init;auto transaction=init.lockTextureCreation();
 init.texture_upload_minimum_=19;init.texture_upload_budget_=37;init.texture_upload_spent_=11;init.texture_upload_active_=true;
 {auto outer=init.textureUploadScope();bounded_factory_charge(init);
  {auto inner=init.textureUploadScope();assert(!init.texture_upload_budget_&&!init.texture_upload_active_);}
  assert(init.texture_upload_budget_==cap&&!init.texture_upload_active_);
 }
 assert(init.texture_upload_minimum_==19&&init.texture_upload_budget_==37&&init.texture_upload_spent_==11&&init.texture_upload_active_);
 puts("PASS nested/unwind scope restores bounded budget, spend, warm ownership and original minimum");
 }
}
}
int main(){dxmt::run(32*MiB);dxmt::run(4*MiB);puts("NOTE Metal completion is a controlled adapter; no iPhone physical-footprint or remote-match performance claim");}
'''

with tempfile.TemporaryDirectory(prefix='madeira-texture-creation-growth-') as directory:
    source, executable = Path(directory) / 'growth.cpp', Path(directory) / 'growth'
    source.write_text(C)
    subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++20', '-O1', '-g', '-pthread',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    str(source), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True, timeout=60)
print('PASS actual complete producer preflights before all partial command state; pinned DXMT remains unchanged')
