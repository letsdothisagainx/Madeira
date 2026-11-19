#!/usr/bin/env python3
"""Execute production initializer methods with owned host Metal adapters.

The real five initializer bodies, macros, zero-buffer allocation/forecast,
CPU command helpers and reset are compiled unchanged from staged output.
Host buffers and a synchronous command executor stand in for Metal only.
This catches silent CPU-heap retries and invalid partial commands; it does
not execute Metal, CS2 or prove on-device resource/memory correctness.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
FILES = ('src/dxmt/dxmt_resource_initializer.cpp', 'src/dxmt/dxmt_resource_initializer.hpp')

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

UPLOAD = module('initializer_upload_stage', ROOT / 'tools/build/stage-dxmt-upload-memory.py')
STAGE = module('initializer_failure_stage', ROOT / 'tools/build/stage-dxmt-initializer-failure.py')
ACCOUNT = module('initializer_account_stage', ROOT / 'tools/build/stage-dxmt-texture-accounting.py')
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--sanitize', action='store_true')
args = parser.parse_args()


def function(source, marker):
    start = source.index(marker)
    brace = source.index('{', start)
    at, depth = brace + 1, 1
    while depth:
        depth += (source[at] == '{') - (source[at] == '}')
        at += 1
    return source[start:at]


PRELUDE = r'''
#include <algorithm>
#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <thread>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <utility>
#include <vector>
#define unlikely(x) (x)
template<class... Args> void ignore_log(Args&&...) {}
#define ERR(...) ignore_log(__VA_ARGS__)
struct Logger { static void info(const char *) {} };
static bool use_pow2;
bool madeiraSwitch(const char *) { return use_pow2; }
struct NativeCounts { size_t live=0, allocated=0, freed=0, calls=0; } native;
struct Payload {
  size_t refs=1;
  std::vector<uint8_t> bytes;
  explicit Payload(size_t size):bytes(size,0xcd) { native.live+=size; ++native.allocated; }
  ~Payload() { native.live-=bytes.size(); ++native.freed; }
};
namespace WMT {
struct Buffer {
  Payload *handle;
  operator bool() const { return handle; }
  void retain() { if(handle) ++handle->refs; }
  void release() { if(handle && !--handle->refs) delete handle; }
  void updateContents(size_t offset,const void *data,size_t size) {
    assert(handle && offset<=handle->bytes.size() && size<=handle->bytes.size()-offset);
    std::memcpy(handle->bytes.data()+offset,data,size);
  }
};
template<class T> struct Reference:T {
  Reference() { this->handle=nullptr; }
  explicit Reference(Payload *p) { this->handle=p; }
  Reference(const Reference &r) { this->handle=r.handle; this->retain(); }
  Reference(Reference &&r) { this->handle=r.handle; r.handle=nullptr; }
  Reference &operator=(Reference &&r) { this->release();this->handle=r.handle;r.handle=nullptr;return *this; }
  Reference &operator=(const Reference &r) { if(this!=&r) { this->release();this->handle=r.handle;this->retain(); }return *this; }
  Reference &operator=(std::nullptr_t) { this->release();this->handle=nullptr;return *this; }
  ~Reference() { this->release(); }
};
struct DeviceState { unsigned failures=0; };
}
struct WMTBufferInfo {
  uint64_t gpu_address; size_t length; int options;
  struct { void *ptr;void set(void *p){ptr=p;} } memory;
};
namespace WMT {
struct Device {
  DeviceState *state;
  Reference<Buffer> newBuffer(WMTBufferInfo &info) {
    ++native.calls;
    if(state->failures) { --state->failures;return {}; }
    return Reference<Buffer>(new Payload(info.length));
  }
  bool supportsBCTextureCompression() { return true; }
};
}
constexpr int WMTResourceStorageModePrivate=1,WMTResourceHazardTrackingModeUntracked=2;
constexpr int WMTTextureUsageRenderTarget=4;
constexpr int WMTTextureType1D=1,WMTTextureType1DArray=2,WMTTextureType2D=3,WMTTextureType3D=4;
enum WMTPixelFormat {
  WMTPixelFormatRGBA8,WMTPixelFormatDepth,
  WMTPixelFormatBC1_RGBA,WMTPixelFormatBC1_RGBA_sRGB,WMTPixelFormatBC2_RGBA,WMTPixelFormatBC2_RGBA_sRGB,
  WMTPixelFormatBC3_RGBA,WMTPixelFormatBC3_RGBA_sRGB,WMTPixelFormatBC4_RSnorm,WMTPixelFormatBC4_RUnorm,
  WMTPixelFormatBC5_RGUnorm,WMTPixelFormatBC5_RGSnorm,WMTPixelFormatBC6H_RGBUfloat,WMTPixelFormatBC6H_RGBFloat,
  WMTPixelFormatBC7_RGBAUnorm,WMTPixelFormatBC7_RGBAUnorm_sRGB
};
struct Texture {
  uint32_t w=4,h=4,d=1; WMTPixelFormat format=WMTPixelFormatRGBA8;int type=WMTTextureType2D,flags=0;
  uint32_t width()const{return w;}uint32_t height()const{return h;}uint32_t depth()const{return d;}
  WMTPixelFormat pixelFormat()const{return format;}int textureType()const{return type;}int usage()const{return flags;}
};
size_t MTLGetTexelSize(WMTPixelFormat f) {
  return f==WMTPixelFormatBC1_RGBA || f==WMTPixelFormatBC1_RGBA_sRGB ? 8 : f>=WMTPixelFormatBC1_RGBA ? 16 : 4;
}
uint32_t DepthStencilPlanarFlags(WMTPixelFormat f){return f==WMTPixelFormatDepth ? 3:0;}
int bc_decode_kind(WMTPixelFormat){return 0;}
bool bc_is_unsupported_src(WMTPixelFormat){return false;}
static inline uint32_t bc_fill_texel_size(WMTPixelFormat){return 4;}
void bc_fill_pattern(WMTPixelFormat,uint8_t*,uint32_t,uint32_t,uint32_t){assert(false);}
uint32_t bc_decode_texel_size(int){assert(false);return 0;}
void bc_decode_image(const uint8_t*,size_t,uint8_t*,uint32_t,uint32_t,int){assert(false);}
template<class T,class U> size_t align(T value,U alignment){return (size_t(value)+alignment-1)&~(size_t(alignment)-1);}
size_t align_forward_adjustment(void *p,size_t alignment){return (alignment-(uintptr_t(p)%alignment))%alignment;}
void *ptr_add(const void *p,size_t offset){return (void*)((uintptr_t)p+offset);}
struct Allocation { unsigned refs=1;void incRef(){++refs;}void decRef(){assert(refs);--refs;} };
struct TextureAllocation:Allocation {
  WMT::Reference<WMT::Buffer> backing;
  explicit TextureAllocation(size_t bytes):backing(new Payload(bytes)){}
  WMT::Buffer texture(){return backing;}
};
struct BufferAllocation:TextureAllocation { using TextureAllocation::TextureAllocation;WMT::Buffer buffer(){return backing;} };
struct Pointer { void *ptr=nullptr;template<class T>void set(T *p){ptr=p;}void set(std::nullptr_t){ptr=nullptr;} };
struct wmtcmd_base { uint32_t type;Pointer next; };
struct wmtcmd_blit_nop:wmtcmd_base {};
struct wmtcmd_blit_fillbuffer:wmtcmd_base { WMT::Buffer buffer;size_t offset,length;uint8_t value; };
struct WMTSize { uint32_t width,height,depth; };struct WMTOrigin {uint32_t x,y,z;};
struct wmtcmd_blit_copy_from_buffer_to_texture:wmtcmd_base {
  WMT::Buffer src,dst;size_t src_offset,bytes_per_row,bytes_per_image;
  WMTSize size;uint32_t slice,level;WMTOrigin origin;
};
constexpr uint32_t WMTBlitCommandNop=1,WMTBlitCommandFillBuffer=2,WMTBlitCommandCopyFromBufferToTexture=3;
struct Attachment {WMT::Buffer texture;int load_action,store_action;uint32_t slice,level;double clear_depth;int clear_stencil;double clear_color[4];};
struct Color {double r,g,b,a;};
struct ColorAttachment {WMT::Buffer texture;int load_action,store_action;uint32_t slice,level;Color clear_color;};
struct WMTRenderPassInfo { uint32_t render_target_array_length,render_target_width,render_target_height;Attachment depth,stencil;ColorAttachment colors[8];};
constexpr int WMTLoadActionClear=1,WMTStoreActionStore=2;
namespace WMT {void InitializeRenderPassInfo(WMTRenderPassInfo &p){std::memset(&p,0,sizeof(p));}}
constexpr int MEMOWN_INIT_UPLOAD=1;static size_t census;
void mem_census_add(int,size_t n){census+=n;}
void mem_census_sub(int,size_t n){assert(census>=n);census-=n;}
namespace dxmt {using mutex=std::mutex;}
constexpr size_t kResourceInitializerCpuCommandHeapSize=4096,kResourceInitializerFlushThreshold=1<<20;
struct RefTracker {
  size_t capacity=29; std::vector<Allocation*> tracked;
  bool track(Allocation *a) {if(tracked.size()>=capacity)return false;a->incRef();tracked.push_back(a);return true;}
  void addStorage(void*,size_t bytes){capacity+=bytes/sizeof(intptr_t)-3;}
  void clear(){for(auto a:tracked)a->decRef();tracked.clear();capacity=29;}
};
class ResourceInitializer {
public:
  struct ClearRenderPassInfo {WMTRenderPassInfo info;ClearRenderPassInfo *next;};
  std::recursive_mutex creation_mutex_;
  dxmt::mutex mutex_;WMT::DeviceState state;WMT::Device device_{&state};
  WMT::Reference<WMT::Buffer> zero_buffer_;
  size_t zero_buffer_size_=0,zero_buffer_census_=0;bool zero_allocation_failed_=false;
  void *cpu_command_heap;size_t cpu_command_heap_offset=0,upload_bytes_since_flush_=0;
  uint64_t current_seq_id_=1;unsigned flushes=0,executed=0;
  wmtcmd_blit_nop blit_cmd_head;wmtcmd_base *blit_cmd_tail;
  ClearRenderPassInfo clear_render_pass_head,*clear_render_pass_tail;RefTracker ref_tracker;
  std::vector<WMT::Reference<WMT::Buffer>> gpu;
  std::vector<size_t> upload_requests;
  ResourceInitializer(){cpu_command_heap=std::malloc(kResourceInitializerCpuCommandHeapSize);assert(cpu_command_heap);reset();}
  ~ResourceInitializer(){ref_tracker.clear();if(zero_buffer_census_)mem_census_sub(MEMOWN_INIT_UPLOAD,zero_buffer_census_);std::free(cpu_command_heap);}
  void reset();uint64_t flushInternal();uint64_t initializationFence();bool prepareUploadLocked(size_t){return true;}
  bool pending()const{return blit_cmd_head.next.ptr || clear_render_pass_head.next;}
  bool retainAllocation(Allocation*);
  WMT::Buffer allocateZeroBuffer(size_t);size_t forecastZeroGrowth(size_t);
  WMT::Buffer allocateGpuHeap(size_t bytes,size_t &offset){
    upload_requests.push_back(bytes);
    WMTBufferInfo info{};info.length=bytes;auto buffer=device_.newBuffer(info);offset=0;
    if(!buffer)return {};
    upload_bytes_since_flush_+=bytes;gpu.push_back(std::move(buffer));return gpu.back();
  }
  uint64_t initWithZero(BufferAllocation*,uint64_t,uint64_t);
  uint64_t initWithZero(const Texture*,TextureAllocation*,uint32_t,uint32_t);
  uint64_t initDepthStencilWithZero(const Texture*,TextureAllocation*,uint32_t,uint32_t,uint32_t);
  uint64_t initRenderTargetWithZero(const Texture*,TextureAllocation*,uint32_t,uint32_t);
  uint64_t initWithData(const Texture*,TextureAllocation*,uint32_t,uint32_t,const void*,size_t,size_t);
CPU_HELPERS
};
uint64_t ResourceInitializer::flushInternal(){
  ++flushes;
  for(auto clear=clear_render_pass_head.next;clear;clear=clear->next){
    WMT::Buffer target=clear->info.depth.texture.handle ? clear->info.depth.texture : clear->info.colors[0].texture;
    assert(target);std::fill(target.handle->bytes.begin(),target.handle->bytes.end(),0);++executed;
  }
  unsigned count=0;
  for(auto base=(wmtcmd_base*)blit_cmd_head.next.ptr;base;base=(wmtcmd_base*)base->next.ptr){
    assert(++count<1000);
    if(base->type==WMTBlitCommandFillBuffer){auto c=(wmtcmd_blit_fillbuffer*)base;assert(c->buffer && c->offset<=c->buffer.handle->bytes.size() && c->length<=c->buffer.handle->bytes.size()-c->offset);std::fill_n(c->buffer.handle->bytes.begin()+c->offset,c->length,c->value);}
    else {assert(base->type==WMTBlitCommandCopyFromBufferToTexture);auto c=(wmtcmd_blit_copy_from_buffer_to_texture*)base;assert(c->src && c->dst && c->src_offset<=c->src.handle->bytes.size() && c->dst.handle->bytes.size()<=c->src.handle->bytes.size()-c->src_offset);std::memcpy(c->dst.handle->bytes.data(),c->src.handle->bytes.data()+c->src_offset,c->dst.handle->bytes.size());}
    ++executed;
  }
  const auto submitted=current_seq_id_++;reset();return submitted;
}
'''

# Use the actual format enumeration and capacity functions for the batch
# bound. The upload request is recorded from the real initWithData body;
# no second row/block-copy algorithm supplies its requested byte count.
wmt = (ROOT / 'dxmt/src/winemetal/winemetal.h').read_text()
pixel_enum = function(wmt, 'enum WMTPixelFormat :') + ';'
begin = PRELUDE.index('enum WMTPixelFormat {')
end = PRELUDE.index('\nstruct Texture {', begin)
PRELUDE = PRELUDE[:begin] + pixel_enum + '''
constexpr auto WMTPixelFormatRGBA8 = WMTPixelFormatRGBA8Unorm;
constexpr auto WMTPixelFormatDepth = WMTPixelFormatDepth32Float;
constexpr int WMTTextureTypeCube=5,WMTTextureTypeCubeArray=6;
struct WMTTextureInfo {
 WMTPixelFormat pixel_format;uint32_t width,height,depth,mipmap_level_count,array_length,sample_count;int type;
};
#define ORIGINAL_FORMAT(f) ((f) & ~WMTPixelFormatCustomSwizzle)
''' + PRELUDE[end:]
census = ACCOUNT.stage_file(ACCOUNT.FILES[0], (ROOT / 'dxmt' / ACCOUNT.FILES[0]).read_text())
capacity = function(census, 'inline uint32_t\nmem_census_texel_bytes(') + '\n' + ACCOUNT.HELPER + '\n'
old_texel = function(PRELUDE, 'size_t MTLGetTexelSize(')
PRELUDE = PRELUDE.replace(old_texel, capacity + '''
size_t MTLGetTexelSize(WMTPixelFormat format) {
 const uint32_t block=mem_census_bc_block_bytes(format);
 return block?block:mem_census_texel_bytes(format);
}''', 1)

MAIN = r'''
void require(bool condition,const char *message){if(!condition){std::cerr<<message<<'\n';std::exit(41);}}
#ifdef STAGED
static void actual_upload_batch_bounds(){
 struct Shape {uint32_t w,h,d,mips,arrays;WMTPixelFormat format;int type;};
 const Shape cases[]={
  {67,35,1,7,3,WMTPixelFormatRGBA8,WMTTextureType2D},
  {67,35,1,7,2,WMTPixelFormatBC1_RGBA,WMTTextureType2D},
  {65,33,1,7,2,WMTPixelFormatBC7_RGBAUnorm,WMTTextureTypeCubeArray},
  {31,17,7,5,1,WMTPixelFormatBC3_RGBA,WMTTextureType3D},
  {33,19,5,6,1,WMTPixelFormatRGBA8,WMTTextureType3D},
  {33,1,1,6,2,WMTPixelFormatRGBA8,WMTTextureType1DArray},
 };
 unsigned batches=0,total_subresources=0;
 for(const auto&shape:cases){
  ResourceInitializer init;Texture texture;texture.w=shape.w;texture.h=shape.h;texture.d=shape.d;
  texture.format=shape.format;texture.type=shape.type;
  WMTTextureInfo info{};info.pixel_format=shape.format;info.width=shape.w;info.height=shape.h;info.depth=shape.d;
  info.mipmap_level_count=shape.mips;info.array_length=shape.arrays;info.sample_count=1;info.type=shape.type;
  const uint64_t faces=shape.type==WMTTextureTypeCubeArray || shape.type==WMTTextureTypeCube?6:1;
  const uint64_t count=uint64_t(shape.mips)*shape.arrays*faces;
  const uint64_t creation=mem_census_texture_bytes(info,true);
  const uint64_t forecast_payload=creation+count*255;
  uint64_t actual=0,padded=0;
  for(uint32_t slice=0;slice<shape.arrays*faces;++slice)
   for(uint32_t level=0;level<shape.mips;++level){
    WMTTextureInfo sub=info;sub.width=std::max(1u,shape.w>>level);sub.height=std::max(1u,shape.h>>level);
    sub.depth=std::max(1u,shape.d>>level);sub.mipmap_level_count=sub.array_length=1;
    if(faces==6)sub.type=WMTTextureType2D;
    const size_t capacity=mem_census_texture_bytes(sub,true);
    WMTTextureInfo row=sub;row.height=row.depth=1;
    const size_t row_bytes=mem_census_texture_bytes(row,true);
    const size_t rows=capacity/(row_bytes*sub.depth);
    const size_t pitch=row_bytes+1+((slice+level)%13),depth_pitch=pitch*rows+3+level;
    const uint8_t value=uint8_t(0x40+(slice+level)%100);
    std::vector<uint8_t> data(depth_pitch*sub.depth,value);
    TextureAllocation target(capacity);
    const auto before=init.upload_requests.size();
    require(init.initWithData(&texture,&target,slice,level,data.data(),pitch,depth_pitch)!=0,"actual batch upload failed");
    require(init.upload_requests.size()==before+1,"actual batch upload did not issue exactly one allocation request");
    const size_t request=init.upload_requests.back();
    require(request==capacity,"texture accounting underestimated or mismatched actual initWithData request");
    actual+=request;padded+=align(request,size_t(256));
    init.flushInternal();require(target.refs==1,"actual batch upload retained a completed destination");
    require(std::all_of(target.backing.handle->bytes.begin(),target.backing.handle->bytes.end(),[&](auto byte){return byte==value;}),"odd row/depth pitch or native BC transfer bytes changed");
   }
  require(actual==creation,"multi-mip/face/array upload sum differs from actual texture capacity");
  require(padded<=forecast_payload&&padded<=align(forecast_payload,size_t(256)),"whole-batch compact forecast undercharges actual aligned allocation requests");
  ++batches;total_subresources+=count;
 }
 std::cout<<"PASS actual initWithData batch bounds: "<<batches<<" shapes / "<<total_subresources<<" subresources; odd rows/depth pitch, mips, cube arrays, 1D/3D and native BC use exact capacity plus bounded256-byte padding\n";
}
#endif
int main(int argc,char **argv){
  use_pow2=argc>1 && std::strcmp(argv[1],"pow2")==0;
  {
    ResourceInitializer init;BufferAllocation target(64);init.cpu_command_heap_offset=kResourceInitializerCpuCommandHeapSize;
    auto fence=init.initWithZero(&target,0,64);
    require(fence && init.pending(),"CPU heap exhaustion silently returned success without recording initialization");
    init.flushInternal();require(std::all_of(target.backing.handle->bytes.begin(),target.backing.handle->bytes.end(),[](auto b){return b==0;}),"buffer zero bytes changed");
  }
#ifdef STAGED
  actual_upload_batch_bounds();
  {
    ResourceInitializer init;Texture texture;TextureAllocation target(64);
    std::atomic<bool> started{false},finished{false};
    auto transaction=init.lockTextureCreation();
    require(init.forecastZeroGrowth(64)==(use_pow2 ? (1u<<20):64),"factory guard cannot reenter zero forecast");
    require(init.initWithZero(&texture,&target,0,0)!=0,"factory guard cannot reenter initialization");
    require(init.initializationFence()==init.current_seq_id_,"factory guard cannot reenter pending initialization fence");
    std::thread second([&]{started.store(true,std::memory_order_release);(void)init.forecastZeroGrowth(64);finished.store(true,std::memory_order_release);});
    while(!started.load(std::memory_order_acquire))std::this_thread::yield();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    require(!finished.load(std::memory_order_acquire),"second creator invalidated an owned forecast/enqueue transaction");
    transaction.unlock();second.join();
    require(finished.load(std::memory_order_acquire),"second creator stayed blocked after transaction release");
    init.flushInternal();
    require(init.initializationFence()==init.current_seq_id_-1,"idle fence fabricated a later completion/recording generation");
  }
  for(int kind=0;kind<4;++kind){
    ResourceInitializer init;Texture texture;TextureAllocation target(64);init.cpu_command_heap_offset=kResourceInitializerCpuCommandHeapSize;
    if(kind==0)texture.format=WMTPixelFormatDepth;
    if(kind==1)texture.flags=WMTTextureUsageRenderTarget;
    std::vector<uint8_t> data(64);for(size_t i=0;i<data.size();++i)data[i]=uint8_t(i*7+3);
    auto fence=kind==3 ? init.initWithData(&texture,&target,0,0,data.data(),16,64):init.initWithZero(&texture,&target,0,0);
    require(fence && init.pending() && init.flushes==1,"one CPU heap flush failed to retry the actual texture operation");
    init.flushInternal();require(target.refs==1,"destination retained beyond command completion");
    if(kind==3)require(target.backing.handle->bytes==data,"retried upload bytes differ");
    else require(std::all_of(target.backing.handle->bytes.begin(),target.backing.handle->bytes.end(),[](auto b){return b==0;}),"retried clear/zero bytes differ");
  }
  {
    ResourceInitializer init;Texture texture;TextureAllocation target(64);uint8_t data[64]{};
    init.state.failures=1;auto fence=init.initWithData(&texture,&target,0,0,data,16,64);
    require(!fence && !init.pending() && !init.flushes && target.refs==1,"native upload nil linked/flushed a partial blit or retained destination");
  }
  {
    ResourceInitializer init;Texture texture;TextureAllocation target(64);init.state.failures=1;
    const auto old_census=census;
    require(!init.initWithZero(&texture,&target,0,0),"native zero nil returned successful fence");
    require(!init.pending() && !init.zero_buffer_ && !init.zero_buffer_size_ && census==old_census && !init.flushes,"native zero nil published invalid cache/census/blit");
  }
  {
    ResourceInitializer init;Texture texture;TextureAllocation target(64);
    require(init.initWithZero(&texture,&target,0,0)!=0,"initial zero creation failed");init.flushInternal();
    const auto handle=init.zero_buffer_.handle;const auto old_size=init.zero_buffer_size_,old_census=census;
    const auto calls=native.calls;const auto flushes=init.flushes;
    require(init.forecastZeroGrowth(32)==0 && native.calls==calls && init.flushes==flushes,"zero reuse forecast allocates, flushes or charges cached storage");
    const size_t request=old_size+64;
    require(init.forecastZeroGrowth(request)==(use_pow2 ? old_size*2:request),"zero forecast differs from actual allocation size");
    Texture larger;larger.w=request/4;larger.h=1;TextureAllocation large_target(request);init.state.failures=1;
    require(!init.initWithZero(&larger,&large_target,0,0),"zero growth native nil returned success");
    require(init.zero_buffer_.handle==handle && census==old_census && !init.pending(),"failed zero replacement destroyed old backing, changed census or linked invalid command");
    require(init.initWithZero(&larger,&large_target,0,0)!=0,"zero native failure poisoned subsequent valid creation");init.flushInternal();
    require(std::all_of(large_target.backing.handle->bytes.begin(),large_target.backing.handle->bytes.end(),[](auto b){return b==0;}),"grown zero buffer contains uninitialized bytes");
  }
  {
    ResourceInitializer init;Texture texture;TextureAllocation target(64);std::free(init.cpu_command_heap);init.cpu_command_heap=nullptr;
    require(!init.initWithZero(&texture,&target,0,0) && init.flushes==2,"persistent CPU heap failure did not stop after two genuine retries");
    require(!init.pending() && !init.zero_buffer_size_,"persistent CPU failure published a zero cache or command");
  }
  {
    ResourceInitializer init;BufferAllocation target(64);init.ref_tracker.capacity=0;init.cpu_command_heap_offset=kResourceInitializerCpuCommandHeapSize;
    require(init.initWithZero(&target,0,64)!=0 && init.pending(),"reference-storage exhaustion silently skipped buffer init");init.flushInternal();require(target.refs==1,"reference retry leaked destination");
  }
  {
    ResourceInitializer init;const auto calls=native.calls;
    require(init.forecastZeroGrowth(SIZE_MAX)==SIZE_MAX,"zero forecast overflow wrapped");
    require(!init.allocateZeroBuffer(SIZE_MAX) && init.zero_allocation_failed_ && native.calls==calls && !init.pending(),"unrepresentable zero size linked/attempted a native allocation");
  }
  {
    ResourceInitializer init;Texture texture;texture.w=8;texture.h=8;texture.format=WMTPixelFormatBC1_RGBA;TextureAllocation target(32);uint8_t data[40];for(size_t i=0;i<sizeof(data);++i)data[i]=uint8_t(i+1);
    require(init.initWithData(&texture,&target,0,0,data,20,40)!=0,"native BC upload failed");init.flushInternal();
    std::vector<uint8_t> expected(data,data+16);expected.insert(expected.end(),data+20,data+36);require(target.backing.handle->bytes==expected,"native BC row padding/required bytes changed");
  }
  {
    ResourceInitializer init;Texture texture;TextureAllocation target(64);uint8_t data[64]{};
    require(init.initWithData(&texture,&target,0,0,data,16,64)!=0 && init.pending(),"record initial valid operation");
    const auto pending=init.blit_cmd_head.next.ptr;init.state.failures=1;
    require(!init.initWithData(&texture,&target,0,0,data,16,64),"second native failure falsely succeeded");
    require(init.blit_cmd_head.next.ptr==pending && !init.flushes,"native failure flushed or replaced prior pending commands");
    init.flushInternal();require(init.executed==1,"partial invalid second command entered encoding");
  }
#endif
  require(!census && !native.live && native.allocated==native.freed,"initializer/native reference leak");
  std::cout<<"PASS actual initializer retries, honest native failure, transactional zero growth/forecast, byte identity, partial-command protection and owned creation transactions (pow2="<<use_pow2<<")\n";
}
'''


def extract(cpp, header, staged):
    marker = 'ResourceInitializer::ResourceInitializer('
    macros = '#define ALLOC_BLIT' + cpp.split('#define ALLOC_BLIT', 1)[1].split(marker, 1)[0]
    helpers = '\n'.join(function(header, name) for name in (
        '  template <typename T>\n  T *\n  allocateCpuHeap()',
        '  template <typename T>\n  bool\n  allocateBlit(',
        '  bool\n  allocateClear('))
    if staged:
        helpers += '\n' + function(header, '  std::unique_lock<std::recursive_mutex> lockTextureCreation()')
        helpers += '\n' + function(header, '  bool\n  idle()')
    methods = '\n'.join(function(cpp, name) for name in (
        'uint64_t\nResourceInitializer::initWithZero(BufferAllocation',
        'uint64_t\nResourceInitializer::initDepthStencilWithZero(',
        'uint64_t\nResourceInitializer::initRenderTargetWithZero(',
        'uint64_t\nResourceInitializer::initWithZero(\n',
        'uint64_t\nResourceInitializer::initWithData(',
        'void\nResourceInitializer::reset()',
        'bool\nResourceInitializer::retainAllocation(',
        'WMT::Buffer\nResourceInitializer::allocateZeroBuffer('))
    if staged:
        methods += '\n' + function(cpp, 'size_t\nResourceInitializer::forecastZeroGrowth(')
        methods += '\n' + function(cpp, 'uint64_t\nResourceInitializer::initializationFence(')
    return PRELUDE.replace('CPU_HELPERS', helpers) + macros + methods + MAIN


original = {name: (ROOT / 'dxmt' / name).read_text() for name in FILES}
upload = {FILES[0]: UPLOAD.stage_initializer(original[FILES[0]]),
          FILES[1]: UPLOAD.stage_initializer_header(original[FILES[1]])}
staged = {name: STAGE.stage_file(name, upload[name]) for name in FILES}
assert staged[FILES[0]].count('for (unsigned retry = 0; retry < 2; ++retry)') == 5
assert 'zero_allocation_failed_' in staged[FILES[1]]
assert 'size_t forecastUploadGrowth(size_t total_payload_bytes, size_t first_subresource_bytes = 0, bool compact = false);' in staged[FILES[1]]
assert 'size_t forecastZeroGrowth(size_t bytes);' in staged[FILES[1]]
assert staged[FILES[0]].count('std::lock_guard<std::recursive_mutex> creation_lock(creation_mutex_);') == 11
assert staged[FILES[0]].count('std::lock_guard<dxmt::mutex> lock(mutex_);') == 11
# GPU event waits must remain independent of the CPU forecast/enqueue guard.
assert function(original[FILES[1]], '  void\n  wait(') == function(staged[FILES[1]], '  void\n  wait(')
assert staged[FILES[0]].index('auto replacement = device_.newBuffer(buffer_info);') < staged[FILES[0]].index('zero_buffer_ = std::move(replacement);')
for name in FILES:
    for invalid in [original[name], staged[name]]:
        try:
            STAGE.stage_file(name, invalid)
            raise AssertionError('accepted uncomposed or double-staged input')
        except ValueError:
            pass
with tempfile.TemporaryDirectory(prefix='madeira-init-failure-') as temporary:
    temp = Path(temporary)
    overlay = temp / 'overlay'
    for name, value in upload.items():
        target = overlay / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value)
    records = STAGE.stage(ROOT / 'dxmt', temp / 'output', overlay)
    assert len(records) == 2
    assert all((ROOT / 'dxmt' / name).read_text() == value for name, value in original.items())
    compiler = os.environ.get('CXX') or shutil.which('clang++') or shutil.which('g++')
    if not compiler:
        raise SystemExit('C++ compiler required')
    common = [compiler, '-std=c++20', '-O1', '-g', '-pthread', '-Wall', '-Wextra', '-Werror']
    if args.sanitize:
        common += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    for mode, files in [('old', upload), ('new', staged)]:
        source, binary = temp / (mode + '.cpp'), temp / mode
        source.write_text(extract(files[FILES[0]], files[FILES[1]], mode == 'new'))
        command = common + (['-DSTAGED=1'] if mode == 'new' else []) + [str(source), '-o', str(binary)]
        subprocess.run(command, check=True)
        result = subprocess.run([str(binary)], capture_output=True, text=True)
        if mode == 'old':
            assert result.returncode == 41 and 'silently returned success' in result.stderr, result
            print('PASS historical production do/while(0) reproduces successful fence with missing required initialization')
        else:
            if result.returncode:
                raise SystemExit(result.stdout + result.stderr)
            print(result.stdout.strip())
            subprocess.run([str(binary), 'pow2'], check=True)
print('PASS immutable pinned source, strict overlay composition and compiled actual-method failure tests; Metal/iPhone validation remains required')
