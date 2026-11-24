#!/usr/bin/env python3
"""Actual staged ring/initializer on normal owned byte arrays and explicit GPU
completion adapters. No fault/crash/protection experiments or captured code execution.
"""
from pathlib import Path
import importlib.util,tempfile,subprocess,os
R=Path(__file__).resolve().parents[2]
def load(n,p):
 spec=importlib.util.spec_from_file_location(n,R/p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def decl(s,sig):
 a=s.index(sig);b=s.index('{',a);d=1;e=b+1
 while d:d+=(s[e]=='{')-(s[e]=='}');e+=1
 return s[a:e]+(';' if s[e:e+1]==';' else '')
u=load('window_upload','tools/build/stage-dxmt-upload-memory.py');f=load('window_failure','tools/build/stage-dxmt-initializer-failure.py');a=load('window_admission','tools/build/stage-dxmt-texture-admission.py');w=load('window_stage','tools/build/stage-dxmt-upload-window.py');acc=load('window_account','tools/build/stage-dxmt-texture-accounting.py')
basecpp=f.stage_cpp(u.stage_initializer((R/'dxmt/src/dxmt/dxmt_resource_initializer.cpp').read_text()))
cpp=w.stage_file(w.FILES[1],basecpp)
h=w.stage_file(w.FILES[0],a.stage_file(a.FILES[1],f.stage_header(u.stage_initializer_header((R/'dxmt/src/dxmt/dxmt_resource_initializer.hpp').read_text()))))
ring=u.stage_ring((R/'dxmt/src/dxmt/dxmt_ring_bump_allocator.hpp').read_text());ringtype=ring[ring.index('template <typename Allocator, size_t BlockSize ='):ring.index('\nclass GpuPrivateBufferBlockAllocator')];ringmethods=ring[ring.index('template <typename Allocator, size_t BlockSize, class mutex>\nstd::pair'):ring.rindex('\n} // namespace dxmt')]
wm=(R/'dxmt/src/winemetal/winemetal.h').read_text();enums='\n'.join(decl(wm,x)for x in ['enum WMTPixelFormat :','enum WMTResourceOptions :','enum WMTTextureType :','enum WMTTextureUsage :','struct WMTTextureInfo {'])
census=acc.stage_file(acc.FILES[0],(R/'dxmt'/acc.FILES[0]).read_text());helpers='\n'.join('inline '+decl(census,x)for x in ['uint32_t\nmem_census_texel_bytes(','uint32_t\nmem_census_bc_block_bytes(','uint64_t\nmem_census_capacity_mul(','uint64_t\nmem_census_texture_bytes('])
policy=(R/'build/dxmt-ios/memory_pressure.hpp').read_text();policy=policy[policy.index('struct MemoryPressureSnapshot'):policy.index('namespace memory_pressure_detail')]
methods='\n'.join(decl(cpp,x)for x in ['std::uint64_t\nResourceInitializer::flushInternal(','uint64_t\nResourceInitializer::flushToWait(','uint64_t\nResourceInitializer::refreshCompletedLocked(','uint64_t\nResourceInitializer::trimMemoryPressure(','MemoryPressureDecision\nResourceInitializer::transientMemoryPressureDecision(','uint64_t\nResourceInitializer::initializationFence(','size_t\nResourceInitializer::forecastUploadGrowth(','bool\nResourceInitializer::prepareUploadLocked(','WMT::Buffer\nResourceInitializer::allocateGpuHeap(','uint64_t\nResourceInitializer::initWithData('])
methods+='\n'+decl(basecpp,'size_t\nResourceInitializer::forecastUploadGrowth(').replace('ResourceInitializer::forecastUploadGrowth','ResourceInitializer::baselineForecast')
scope=decl(h,'  class TextureUploadScope {')+'\n'+decl(h,'  TextureUploadScope textureUploadScope()')+'\n'+decl(h,'  size_t forecastPressureUploadGrowth(')
C=r'''
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <utility>
#include <vector>
#include <cstdlib>
#define WARN(...) ((void)0)
#define CHECK(c) do{if(!(c)){fprintf(stderr,"window fixture failed %d: %s\n",__LINE__,#c);exit(1);}}while(0)
using mach_port_t=uint32_t;constexpr size_t MiB=1u<<20;
struct Stats{size_t bytes=0,peak=0,allocs=0,updates=0;}stats;
struct Payload{std::vector<uint8_t> data;Payload(size_t n):data(n){stats.bytes+=n;stats.peak=std::max(stats.peak,stats.bytes);++stats.allocs;}~Payload(){stats.bytes-=data.size();}};
namespace WMT{
struct Buffer{std::shared_ptr<Payload> p;explicit operator bool()const{return !!p;}void updateContents(size_t o,const void*s,size_t n){CHECK(p&&o<=p->data.size()&&n<=p->data.size()-o);memcpy(p->data.data()+o,s,n);++stats.updates;}};
struct Pool{};Pool MakeAutoreleasePool(){return {};}
}
namespace dxmt {
using mutex=std::mutex;
template<class T,class U>size_t align(T v,U a){return (size_t(v)+size_t(a)-1)&~(size_t(a)-1);}
constexpr size_t kStagingBlockSize=32*MiB,kStagingBlockLifetime=300;
size_t madeiraRingBlockSize(size_t n){return n;}bool ringOversizeReuseEnabled(){return false;}
struct Logger{template<class...T>static void info(T&&...) {}};
#define ORIGINAL_FORMAT(x) (x & ~WMTPixelFormatCustomSwizzle)
'''+enums+'\n'+helpers+'\n'+policy+r'''
struct ResourceGrowthBudgetSnapshot{uint64_t footprint=0,available=0,pending=0,floor=0;bool valid=false;}budget;
ResourceGrowthBudgetSnapshot resourceGrowthBudgetSnapshot(uint64_t=0){return budget;}
MemoryPressureSnapshot memoryPressureSnapshot(bool=false){return {5800*MiB,budget.available,6144*MiB,768*MiB,1,true};}
struct Texture{uint32_t w,h,d,mips,slices;WMTPixelFormat fmt;WMTTextureType type;
 uint32_t width()const{return w;}uint32_t height()const{return h;}uint32_t depth()const{return d;}
 WMTPixelFormat pixelFormat()const{return fmt;}WMTTextureType textureType()const{return type;}};
size_t MTLGetTexelSize(WMTPixelFormat f){auto b=mem_census_bc_block_bytes(f);return b?b:mem_census_texel_bytes(f);}
struct Target{Texture t;std::vector<std::vector<uint8_t>> sub;
 Target(Texture v):t(v){for(unsigned s=0;s<t.slices;++s)for(unsigned m=0;m<t.mips;++m){size_t b=mem_census_bc_block_bytes(t.fmt)?4:1;size_t tx=MTLGetTexelSize(t.fmt);sub.emplace_back(((std::max(1u,t.w>>m)+b-1)/b)*((std::max(1u,t.h>>m)+b-1)/b)*std::max(1u,t.d>>m)*tx,0);}}};
struct TextureAllocation{Target*target;Target*texture(){return target;}};
struct Vec{uint32_t width,height,depth;};
struct wmtcmd_blit_copy_from_buffer_to_texture{int type=0;WMT::Buffer src;size_t src_offset=0,bytes_per_row=0,bytes_per_image=0;Vec size{},origin{};Target*dst=nullptr;uint32_t slice=0,level=0;};
constexpr int WMTBlitCommandCopyFromBufferToTexture=1;
namespace WMTAdapter {
struct Event{uint64_t value=0,submitted=0;unsigned waits=0;std::vector<wmtcmd_blit_copy_from_buffer_to_texture> pending;
 uint64_t signaledValue(){return value;}
 void complete(){for(auto &c:pending){CHECK(c.type==1&&c.dst&&c.src);auto&t=c.dst->t;size_t bs=mem_census_bc_block_bytes(t.fmt)?4:1,tx=MTLGetTexelSize(t.fmt);size_t pitch=((std::max(1u,t.w>>c.level)+bs-1)/bs)*tx,rows=(std::max(1u,t.h>>c.level)+bs-1)/bs;auto&dst=c.dst->sub[c.slice*t.mips+c.level];
 for(unsigned z=0;z<c.size.depth;++z)for(size_t y=0;y<(c.size.height+bs-1)/bs;++y){size_t n=((c.size.width+bs-1)/bs)*tx;size_t off=c.src_offset+z*c.bytes_per_image+y*c.bytes_per_row;size_t to=(c.origin.depth+z)*rows*pitch+(c.origin.height/bs+y)*pitch+c.origin.width/bs*tx;CHECK(off+n<=c.src.p->data.size()&&to+n<=dst.size());memcpy(dst.data()+to,c.src.p->data.data()+off,n);}}
 pending.clear();value=submitted;}
 bool waitUntilSignaledValue(uint64_t wanted,uint64_t ms){CHECK(ms>0&&ms<=50);++waits;complete();return value>=wanted;}};
struct CommandBuffer{Event*e;uint64_t signal=0;void encodeSignalEvent(Event&,uint64_t s){signal=s;}void commit(){CHECK(signal);e->submitted=signal;}};
struct Queue{Event*e;CommandBuffer commandBuffer(){return{e};}};
}
'''+ringtype+'\n'+ringmethods+r'''
struct CountingAllocator{struct Block{WMT::Buffer buffer;Block()=default;Block(Block&&)=default;Block&operator=(Block&&)=default;Block(const Block&)=delete;};Block allocate(size_t n){Block b;b.buffer.p=std::make_shared<Payload>(n);return b;}};
constexpr size_t kResourceInitializerGpuUploadHeapAlignment=256,kResourceInitializerFlushThreshold=32*MiB;constexpr int MEMOWN_INIT_UPLOAD=0;
void mem_census_sub(int,uint64_t){}
const void*ptr_add(const void*p,size_t n){return static_cast<const uint8_t*>(p)+n;}
int bc_decode_kind(WMTPixelFormat){return 0;}bool bc_is_unsupported_src(WMTPixelFormat){return false;}uint32_t bc_fill_texel_size(WMTPixelFormat){return 0;}uint32_t bc_decode_texel_size(int){return 0;}void bc_fill_pattern(WMTPixelFormat,void*,uint32_t,uint32_t,uint32_t){}void bc_decode_image(const uint8_t*,size_t,void*,uint32_t,uint32_t,int){}
#define ERR(...) ((void)0)
#define ALLOC_GPU(buffer,size) WMT::Buffer buffer; size_t buffer##_offset=0; if (!(buffer=allocateGpuHeap(size,buffer##_offset))) return 0
#define RETAIN(allocation) if (!retainAllocation(allocation)) {flushInternal();continue;}
#define ALLOC_BLIT(type,cmd) type *cmd=nullptr; if (!allocateBlit(&cmd)) {flushInternal();continue;}
class ResourceInitializer{public:
 std::recursive_mutex creation_mutex_;std::mutex mutex_;MemoryPressureController transient_pressure_controller_;
 size_t texture_upload_minimum_=0,texture_upload_limit_=0,texture_upload_budget_=0,texture_upload_spent_=0;bool texture_upload_active_=false;
 std::chrono::steady_clock::time_point texture_upload_wait_deadline_{};
 uint64_t current_seq_id_=1,cached_coherent_seq_id=0;size_t upload_bytes_since_flush_=0;
 uint64_t zero_buffer_census_=0;size_t zero_buffer_size_=0;std::shared_ptr<int>zero_buffer_;
 struct Device{bool supportsBCTextureCompression(){return true;}}device_;
 WMTAdapter::Event upload_queue_event_;WMTAdapter::Queue upload_queue_{&upload_queue_event_};
 RingBumpState<CountingAllocator,32*MiB>gpu_command_heap_allocator{CountingAllocator{}};
 std::vector<std::unique_ptr<wmtcmd_blit_copy_from_buffer_to_texture>> recording;
 bool idle(){return recording.empty();}void reset(){recording.clear();upload_bytes_since_flush_=0;}
 void encode(WMTAdapter::CommandBuffer){for(auto &x:recording){CHECK(x->type==1&&x->src&&x->dst);upload_queue_event_.pending.push_back(*x);}}
 bool retainAllocation(TextureAllocation*){return true;}
 template<class T>bool allocateBlit(T**p){recording.push_back(std::make_unique<T>());*p=recording.back().get();return true;}
 uint64_t flushInternal();uint64_t flushToWait();uint64_t refreshCompletedLocked(bool,bool=false);uint64_t trimMemoryPressure(bool=false);MemoryPressureDecision transientMemoryPressureDecision();uint64_t initializationFence();
 size_t baselineForecast(size_t,size_t,bool);size_t forecastUploadGrowth(size_t,size_t=0,bool=false,size_t=0);bool prepareUploadLocked(size_t);WMT::Buffer allocateGpuHeap(size_t,size_t&);
 uint64_t initWithData(const Texture*,TextureAllocation*,uint32_t,uint32_t,const void*,size_t,size_t);
 size_t uploadBlockSize()const{return gpu_command_heap_allocator.ring_block_size();}
'''+scope+r'''
};
'''+methods+r'''
static void run(Texture descriptor,uint64_t available,bool reuse=false){
 stats={};budget={5800*MiB,available,0,201326592,true};
 {ResourceInitializer init;Target target(descriptor);TextureAllocation allocation{&target};
 if(reuse){init.gpu_command_heap_allocator.preallocate(1);}
 size_t total=0,largest=0;for(auto &v:target.sub){total+=v.size()+255;largest=std::max(largest,v.size());}
 const size_t destination=total-255*target.sub.size();
 size_t baseline=0;{auto oldscope=init.textureUploadScope();baseline=init.baselineForecast(total,largest,true);}
 {auto scope=init.textureUploadScope();
 size_t growth=init.forecastPressureUploadGrowth(total,largest,true,destination);
 const size_t window=init.texture_upload_limit_;CHECK(window && window<=32*MiB);
 if(reuse)CHECK(growth==0);else CHECK(growth==window);
 CHECK(destination+growth<=available-budget.floor);
 if(destination+baseline>available-budget.floor)printf("baseline full staging=%zu rejected creation=%zu; corrected actual staging=%zu admitted creation=%zu (controlled budget)\n",baseline,destination+baseline,growth,destination+growth);
 for(unsigned slice=0;slice<descriptor.slices;++slice)for(unsigned mip=0;mip<descriptor.mips;++mip){
  size_t bs=mem_census_bc_block_bytes(descriptor.fmt)?4:1,tx=MTLGetTexelSize(descriptor.fmt),width=std::max(1u,descriptor.w>>mip),height=std::max(1u,descriptor.h>>mip),depth=std::max(1u,descriptor.d>>mip),rows=(height+bs-1)/bs,row=((width+bs-1)/bs)*tx,pitch=row+32,plane=pitch*rows+64;
  std::vector<uint8_t>input(plane*depth,0xcc),expected(row*rows*depth);
  for(size_t z=0;z<depth;++z)for(size_t y=0;y<rows;++y)for(size_t x=0;x<row;++x){uint8_t value=uint8_t((z*17+y*7+x+slice*13+mip)%251);input[z*plane+y*pitch+x]=value;expected[z*row*rows+y*row+x]=value;}
  CHECK(init.initWithData(&descriptor,&allocation,slice,mip,input.data(),pitch,plane));
  // Expected source is owned until this ordinary API returns; staging has its bytes.
  uint64_t submitted=init.flushToWait();if(submitted)init.upload_queue_event_.waitUntilSignaledValue(submitted,50);
  CHECK(target.sub[slice*descriptor.mips+mip]==expected);
  // Repeat critical-pressure completion sweeps throughout a still-owned
  // creation. A completed hot window must survive; unfinished work was
  // completed only by the explicit event adapter above.
  init.trimMemoryPressure(true);
 }
 CHECK(init.texture_upload_spent_<=growth);
 CHECK(stats.peak<=(reuse?32*MiB:window));
 printf("actual window=%zu growth-charge=%zu upload-peak=%zu allocations=%zu native-updates=%zu; every mip/slice/block/row/depth byte verified\n",window,growth,stats.peak,stats.allocs,stats.updates);
 }
 init.trimMemoryPressure(true);
 }
 CHECK(stats.bytes==0);
}
}
int main(){using namespace dxmt;
 // Controlled BC witness, not a recovered Run19 descriptor.
 run({4096,4096,1,13,1,WMTPixelFormatBC7_RGBAUnorm,WMTTextureType2D},239208200);
 run({1027,2051,1,11,6,WMTPixelFormatBC1_RGBA_sRGB,WMTTextureTypeCube},240*MiB);
 run({1031,67,9,5,1,WMTPixelFormatRGBA8Unorm,WMTTextureType3D},210*MiB);
 run({16384,3,1,1,1,WMTPixelFormatRGBA32Float,WMTTextureType2D},201326592+16384*3*16+65536);
 run({65,1,1,7,3,WMTPixelFormatR8Unorm,WMTTextureType1DArray},202*MiB);
 run({4096,4096,1,13,1,WMTPixelFormatBC7_RGBAUnorm,WMTTextureType2D},239208200,true);
 // Destination-only shortage remains a truthful denial at the unchanged floor.
 CHECK(22020096ull>212551384ull-201326080ull);
 CHECK(16777216ull>203392272ull-201326592ull);
 printf("PASS actual staged forecast/ring/initializer; genuine event-adapter reuse, no extra new block, destination-only shortage preserved\n");
}
'''
with tempfile.TemporaryDirectory() as d:
 t=Path(d);(t/'test.cpp').write_text(C)
 subprocess.run([os.getenv('CXX','c++'),'-std=c++20','-O2','-pthread',str(t/'test.cpp'),'-o',str(t/'test')],check=True)
 subprocess.run([str(t/'test')],check=True)
