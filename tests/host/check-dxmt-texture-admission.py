#!/usr/bin/env python3
"""Run the complete production texture factory against owned host backends.

The factory, capacity helpers and PE-side permit class are actual sources.
Only the native memory-query/Metal/D3DKMT/initializer adapters are hosted;
these checks establish HRESULT, ownership and byte delivery, not iPhone RSS.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def declaration(source, signature):
    begin = source.index(signature)
    opening = source.index('{', begin)
    cursor, depth = opening + 1, 1
    while depth:
        depth += (source[cursor] == '{') - (source[cursor] == '}')
        cursor += 1
    return source[begin:cursor] + (';' if source[cursor:cursor + 1] == ';' else '') + '\n'


STAGE = module('texture_admission', 'tools/build/stage-dxmt-texture-admission.py')
ACCOUNT = module('texture_accounting', 'tools/build/stage-dxmt-texture-accounting.py')
UPLOAD = module('upload_memory', 'tools/build/stage-dxmt-upload-memory.py')
NAME = STAGE.FILES[0]
original = (ROOT / 'dxmt' / NAME).read_text()
staged = STAGE.stage_file(NAME, original)
initializer = UPLOAD.stage_initializer_header((ROOT / 'dxmt' / STAGE.FILES[1]).read_text())
staged_initializer = STAGE.stage_file(STAGE.FILES[1], initializer)
assert 'cached_coherent_seq_id' not in declaration(staged_initializer, 'bool waitForMemoryPressure(')
assert staged.index('info.mipmap_level_count = physDesc.MipLevels') < staged.index('ResourceGrowthPermit creation_permit')
assert staged.index('ResourceGrowthPermit creation_permit') < staged.index('auto texture = Rc<Texture>(new Texture')
assert staged.count('return E_OUTOFMEMORY;') == 7
for name, text in ((NAME, staged), (STAGE.FILES[1], staged_initializer)):
    try:
        STAGE.stage_file(name, text)
    except ValueError:
        pass
    else:
        raise AssertionError('duplicate admission staging accepted')

wmt = (ROOT / 'dxmt/src/winemetal/winemetal.h').read_text()
types = '\n'.join(declaration(wmt, signature) for signature in (
    'enum WMTPixelFormat :', 'enum WMTResourceOptions :', 'enum WMTTextureType :',
    'enum WMTTextureUsage :', 'struct WMTTextureInfo {', 'struct madeira_ctl_args {'))
memory_header = (ROOT / 'build/dxmt-ios/memory_pressure.hpp').read_text()
memory_header = '\n'.join(line for line in memory_header.splitlines()
                          if line != '#pragma once' and line != '#include "winemetal.h"')
census = (ROOT / 'dxmt/src/dxmt/dxmt_mem_census.hpp').read_text()
accounting = 'inline ' + declaration(census, 'uint32_t\nmem_census_texel_bytes(') + ACCOUNT.HELPER
mip_policy = (ROOT / 'dxmt/src/d3d11/d3d11_mip_clamp_policy.hpp').read_text().replace('#pragma once', '')

PREFIX = r'''
#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>
using mach_port_t = uint32_t;
using HRESULT = int32_t;
using UINT = uint32_t;
constexpr HRESULT S_OK=0, E_FAIL=(int32_t)0x80004005,
 E_INVALIDARG=(int32_t)0x80070057, E_OUTOFMEMORY=(int32_t)0x8007000e;
#define FAILED(result) ((result)<0)
static std::mutex failure_log_mutex;
static std::vector<std::string> failure_logs;
template<class...Args>static void capture_error(const Args&...args){
 std::ostringstream out;(out<<...<<args);
 if(out.str().find("[texture-admission-v1]")==0){
  std::lock_guard<std::mutex>lock(failure_log_mutex);failure_logs.push_back(out.str());
 }
}
#define ERR(...) capture_error(__VA_ARGS__)
constexpr UINT D3D11_USAGE_DEFAULT=0, D3D11_USAGE_IMMUTABLE=1;
constexpr UINT D3D11_BIND_SHADER_RESOURCE=8, D3D11_BIND_DEPTH_STENCIL=64;
constexpr UINT D3D11_RESOURCE_MISC_SHARED=2, D3D11_RESOURCE_MISC_TEXTURECUBE=4,
 D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX=256, D3D11_RESOURCE_MISC_SHARED_NTHANDLE=2048,
 D3D11_RESOURCE_MISC_RESOURCE_CLAMP=128;
struct Desc {
 UINT Width=16, Height=16, Depth=1, MipLevels=3, ArraySize=1, Format=98,
 Usage=D3D11_USAGE_IMMUTABLE, BindFlags=D3D11_BIND_SHADER_RESOURCE,
 CPUAccessFlags=0, MiscFlags=0;
 struct { UINT Count=1, Quality=0; } SampleDesc;
};
struct D3D11_TEXTURE2D_DESC1 : Desc {};
struct D3D11_TEXTURE1D_DESC : Desc {};
struct D3D11_TEXTURE3D_DESC1 : Desc {};
struct D3D11_SUBRESOURCE_DATA { const void *pSysMem; UINT SysMemPitch, SysMemSlicePitch; };
struct D3DDDI_ALLOCATIONINFO {};
struct D3DDDI_ALLOCATIONINFO2 { void *pSystemMem=nullptr; };
struct D3DKMT_CREATESTANDARDALLOCATION { UINT Type=0; };
constexpr UINT D3DKMT_STANDARDALLOCATIONTYPE_EXISTINGHEAP=1;
struct D3DKMT_CREATEALLOCATION {
 UINT hDevice=0,hResource=41,hGlobalShare=43,PrivateRuntimeDataSize=0,NumAllocations=0;
 void *pPrivateRuntimeData=nullptr;
 D3DDDI_ALLOCATIONINFO2 *pAllocationInfo2=nullptr;
 D3DKMT_CREATESTANDARDALLOCATION *pStandardAllocation=nullptr;
 struct { bool StandardAllocation=false, ExistingSysMem=false, CreateResource=false,
 CreateShared=false, NtSecuritySharing=false; } Flags;
};
static int D3DKMTCreateAllocation2(D3DKMT_CREATEALLOCATION*) { return 0; }
static void MakeUniqueSharedName(char *out) { std::strcpy(out,"owned-test-resource"); }
static bool WMTBootstrapRegister(const char*,mach_port_t) { return true; }
struct SharedResourceData { char mach_port_name[54]; int dimension; char desc[sizeof(Desc)+32]; };
'''

BUDGET = r'''
static std::mutex budget_mutex;
static std::map<uint64_t,uint64_t> receipts;
static uint64_t next_token=1, credit_bytes=0, last_charge=0;
static unsigned acquire_calls=0,release_calls=0, reply_code=1;
static std::vector<uint64_t> acquire_flags;
static bool unknown_backend=false, deny_always=false, grant_after_wait=false, grant_completion_lane=false;
static uint64_t available_bytes=2ull<<30;
static bool single_slot=false;
static void MadeiraCtl(madeira_ctl_args *args) {
 std::lock_guard<std::mutex> lock(budget_mutex);
 if(args->op==40) {
  if(unknown_backend){args->ret=0;return;}
  args->ret=1; args->ptr=(6ull<<30)-available_bytes; args->len=available_bytes;return;
 }
 if(args->op==41) {
  const auto flags=args->len;assert(flags<=1);acquire_flags.push_back(flags);
  ++acquire_calls;last_charge=args->ptr;
  if(unknown_backend){args->ret=0;return;}
  const auto bytes=args->ptr;args->len=available_bytes;
  if((deny_always && !(grant_completion_lane && flags==1)) ||
     (single_slot&&!receipts.empty()) || bytes==UINT64_MAX) {
   args->ret=3;args->ptr=0;return;
  }
  const auto token=next_token++;receipts[token]=bytes;credit_bytes+=bytes;
  args->ret=reply_code;args->ptr=token;return;
 }
 if(args->op==42) {
  auto found=receipts.find(args->ptr);assert(found!=receipts.end());
  credit_bytes-=found->second;receipts.erase(found);++release_calls;args->ret=1;return;
 }
 assert(false);
}
'''

BACKEND = r'''
static std::atomic<unsigned> texture_born{0}, texture_alive{0}, backing_calls{0},
 allocation_alive{0}, initialize_calls{0}, invalid_initializations{0}, com_alive{0},
 trim_calls{0}, flush_calls{0}, wait_calls{0}, sweep_calls{0}, bc_queries{0},
 emergency_trim_calls{0}, emergency_sweep_calls{0}, transient_trim_calls{0};
static bool native_bc=true, fail_native=false, force_bias=false, throw_initialization=false;
static mach_port_t native_shared_port=0;
static uint64_t waited_seq=0, waited_ms=0;
static unsigned flush_with_credit=0, last_flush_initializations=0;
static std::atomic<bool> block_initialization{false}, initialization_entered{false}, unblock_initialization{false};
namespace dxmt {
template<class T> class Rc : public std::shared_ptr<T> {
 using Base=std::shared_ptr<T>;
public:
 Rc()=default; Rc(T *ptr):Base(ptr){} T *ptr() const {return this->get();}
};
template<class T>T *ref(T *p){return p;}
template<class T>struct Flags { unsigned value=0; void set(T bit){value|=1u<<unsigned(bit);} };
enum class TextureAllocationFlag { GpuPrivate, GpuReadonly, Shared, GpuManaged };
class NativeDevice {public: bool supportsBCTextureCompression(){++bc_queries;return native_bc;} };
class Texture;
struct Handle { bool valid; explicit operator bool()const{return valid;} };
class TextureAllocation {
public:
 bool valid; mach_port_t machPort=0;
 std::vector<std::vector<uint8_t>> data;
 explicit TextureAllocation(bool ok):valid(ok){++allocation_alive;}
 ~TextureAllocation(){--allocation_alive;}
 Handle texture()const{return {valid};}
};
class Texture {
 Rc<TextureAllocation> allocation_;
public:
 WMTTextureInfo info; uint32_t bias=0;
 Texture(WMTTextureInfo value,NativeDevice):info(value){++texture_born;++texture_alive;}
 ~Texture(){--texture_alive;}
 void setMipBias(uint32_t value){bias=value;}
 Rc<TextureAllocation> allocate(Flags<TextureAllocationFlag> flags){
  ++backing_calls; auto allocation=Rc<TextureAllocation>(new TextureAllocation(!fail_native));
  if(flags.value&(1u<<unsigned(TextureAllocationFlag::Shared)))allocation->machPort=native_shared_port;
  allocation->data.resize(info.mipmap_level_count*info.array_length);
  return allocation;
 }
 void rename(Rc<TextureAllocation>&&allocation){allocation_=std::move(allocation);}
 TextureAllocation *current(){return allocation_.ptr();}
};
class FakeUploadEvent {
public:
 bool waitUntilSignaledValue(uint64_t seq,uint64_t timeout){
  ++wait_calls;waited_seq=seq;waited_ms=timeout;
  if(grant_after_wait){std::lock_guard<std::mutex>lock(budget_mutex);deny_always=false;return true;}
  return false;
 }
};
class Initializer {
public:
 FakeUploadEvent upload_queue_event_; uint64_t submitted=0;
 uint64_t trimMemoryPressure(bool release_warm=false){++trim_calls;if(release_warm)++emergency_trim_calls;return 0;}
 uint64_t flushToWait(){
  ++flush_calls;last_flush_initializations=initialize_calls;
  std::lock_guard<std::mutex>lock(budget_mutex);
  if(!receipts.empty())++flush_with_credit;
  return submitted;
 }
 INIT_PRESSURE_WAIT
 uint64_t initWithZero(Texture *texture,TextureAllocation *allocation,uint32_t slice,uint32_t mip){
  ++initialize_calls; if(!allocation||!allocation->valid){++invalid_initializations;return 1;}
  allocation->data[slice*texture->info.mipmap_level_count+mip].assign(4,0);return 1;
 }
 uint64_t initWithData(Texture *texture,TextureAllocation *allocation,uint32_t slice,uint32_t mip,
                       const void *bytes,size_t pitch,size_t){
  ++initialize_calls;
  if(!allocation||!allocation->valid){++invalid_initializations;return 1;}
  {
   std::lock_guard<std::mutex>lock(budget_mutex);
   if(!unknown_backend && expect_candidate)assert(!receipts.empty()&&credit_bytes>0);
  }
  if(throw_initialization)throw std::runtime_error("owned backend failure");
  if(block_initialization.load()){
   initialization_entered=true;
   while(!unblock_initialization.load())std::this_thread::sleep_for(std::chrono::microseconds(50));
  }
  const auto *input=static_cast<const uint8_t*>(bytes);
  allocation->data[slice*texture->info.mipmap_level_count+mip].assign(input,input+pitch);
  return 1;
 }
};
class CommandQueue {
public:
 Initializer initializer; uint64_t domain=1, coherent=1;
 std::atomic<bool> allocation_recovery_latched_{false};
 RECOVERY_LATCH_METHOD
 uint64_t memoryDomain()const{return domain;}
 uint64_t CoherentSeqId()const{return coherent;}
 uint64_t trimCompletedTransientMemory(){++transient_trim_calls;return 0;}
};
class DynamicBuffer {
public:
 static uint64_t TrimCompletedForQueue(uint64_t domain,uint64_t coherent,bool critical,
                                      const DynamicBuffer *pending,uint64_t upcoming){
  assert(domain&&coherent&&!pending&&upcoming);++sweep_calls;if(critical)++emergency_sweep_calls;return 0;
 }
};
class MTLD3D11Device {
 CommandQueue queue_;
public:
 NativeDevice GetMTLDevice(){return {};}
 MTLD3D11Device&GetDXMTDevice(){return *this;}
 CommandQueue&queue(){return queue_;}
 uint32_t GetLocalD3DKMT(){return 0xc0000000u;}
};
class RenamableTexturePool {
 Rc<Texture> texture_; Flags<TextureAllocationFlag> flags_; Rc<TextureAllocation> current_;
public:
 RenamableTexturePool(Texture *texture,size_t,Flags<TextureAllocationFlag> flags):
  texture_(texture),flags_(flags){ assert(false&&"raw owner must not be duplicated"); }
 Rc<TextureAllocation>getNext(uint64_t){if(!current_)current_=texture_->allocate(flags_);return current_;}
};
template<class Tag>class DeviceTexture;
struct tag_texture_2d {using DESC1=D3D11_TEXTURE2D_DESC1;using COM_IMPL=DeviceTexture<tag_texture_2d>;static constexpr int dimension=2;};
struct tag_texture_1d {using DESC1=D3D11_TEXTURE1D_DESC;using COM_IMPL=DeviceTexture<tag_texture_1d>;static constexpr int dimension=1;};
struct tag_texture_3d {using DESC1=D3D11_TEXTURE3D_DESC1;using COM_IMPL=DeviceTexture<tag_texture_3d>;static constexpr int dimension=3;};
template<class Tag>class DeviceTexture {
public:
 typename Tag::DESC1 logical; Rc<Texture> owner; Rc<RenamableTexturePool> pool; uint32_t bias=0;
 DeviceTexture(const typename Tag::DESC1*d,Rc<Texture>&&texture,MTLD3D11Device*):logical(*d),owner(std::move(texture)){++com_alive;}
 DeviceTexture(const typename Tag::DESC1*d,Rc<Texture>&&texture,Rc<RenamableTexturePool>&&p,MTLD3D11Device*):
  logical(*d),owner(std::move(texture)),pool(std::move(p)){++com_alive;}
 DeviceTexture(const typename Tag::DESC1*d,Rc<Texture>&&texture,uint32_t,uint32_t,MTLD3D11Device*):
  logical(*d),owner(std::move(texture)){++com_alive;}
 ~DeviceTexture(){--com_alive;}
 void SetMipBias(uint32_t value){bias=value;}
};
class Config {public:static Config&getInstance(){static Config c;return c;}
 template<class T>T getOption(const char*,T fallback){return fallback;}};
static uint32_t MipClampAutoBias(uint32_t,uint32_t,uint32_t){return force_bias?1:0;}
template<class DescType>HRESULT CreateMTLTextureDescriptor(MTLD3D11Device*,const DescType*input,DescType*normalized,WMTTextureInfo*info){
 if(!input||!input->Width||input->Width>16384||!input->MipLevels)return E_INVALIDARG;
 *normalized=*input;*info={};info->width=input->Width;info->height=input->Height;
 info->depth=input->Depth;info->array_length=input->ArraySize;info->mipmap_level_count=input->MipLevels;
 info->sample_count=input->SampleDesc.Count;info->type=WMTTextureType2D;
 if constexpr(std::is_same_v<DescType,D3D11_TEXTURE1D_DESC>) {info->height=1;info->depth=1;info->type=WMTTextureType1D;}
 if constexpr(std::is_same_v<DescType,D3D11_TEXTURE3D_DESC1>) {info->array_length=1;info->type=WMTTextureType3D;}
 info->pixel_format=input->Format==98?WMTPixelFormatBC7_RGBAUnorm:WMTPixelFormatRGBA8Unorm;
 return S_OK;
}
struct Subresource {uint32_t MipLevel,ArraySlice;};
template<class DescType>std::vector<Subresource>EnumerateSubresources(const DescType&desc){
 std::vector<Subresource> result;
 for(uint32_t slice=0;slice<desc.ArraySize;++slice)
  for(uint32_t mip=0;mip<desc.MipLevels;++mip)result.push_back({mip,slice});
 return result;
}
}
'''

TESTS = r'''
static void clean(){
 assert(texture_alive==0&&allocation_alive==0&&com_alive==0);
 std::lock_guard<std::mutex>lock(budget_mutex);assert(receipts.empty()&&credit_bytes==0);
}
static uint64_t next_domain=10;
static void reset(dxmt::MTLD3D11Device&device){
 clean();texture_born=0;backing_calls=0;initialize_calls=0;invalid_initializations=0;
 trim_calls=0;flush_calls=0;wait_calls=0;sweep_calls=0;bc_queries=0;
 emergency_trim_calls=0;emergency_sweep_calls=0;transient_trim_calls=0;
 acquire_flags.clear();
 acquire_calls=release_calls=0;last_charge=0;reply_code=1;unknown_backend=false;
 deny_always=false;grant_after_wait=false;grant_completion_lane=false;single_slot=false;available_bytes=2ull<<30;
 native_bc=true;fail_native=false;force_bias=false;throw_initialization=false;native_shared_port=0;
 block_initialization=false;initialization_entered=false;unblock_initialization=false;
 device.queue().domain=next_domain++;device.queue().coherent=1;device.queue().initializer.submitted=0;
 device.queue().allocationRecoveryDrain(1);
 waited_seq=waited_ms=0;flush_with_credit=last_flush_initializations=0;
}
template<class Tag>HRESULT create(dxmt::MTLD3D11Device&device,typename Tag::DESC1&desc,
 const D3D11_SUBRESOURCE_DATA*data,typename Tag::COM_IMPL**out){
 return dxmt::CreateDeviceTextureInternal<Tag>(&device,&desc,data,out);
}
int main(int argc,char**argv){
 using Tag=dxmt::tag_texture_2d;expect_candidate=argc==2&&argv[1][0]=='1';
 dxmt::MTLD3D11Device device;D3D11_TEXTURE2D_DESC1 desc;
 std::vector<std::vector<uint8_t>> bytes(8,std::vector<uint8_t>(64));
 D3D11_SUBRESOURCE_DATA initial[8];
 for(unsigned i=0;i<8;++i){std::fill(bytes[i].begin(),bytes[i].end(),uint8_t(i+1));initial[i]={bytes[i].data(),16,64};}
 // Reproduce the old successful wrapper around a failed native Metal texture.
 reset(device);fail_native=true;Tag::COM_IMPL*out=reinterpret_cast<Tag::COM_IMPL*>(1);
 auto hr=create<Tag>(device,desc,initial,&out);
 if(expect_candidate){
  assert(hr==E_OUTOFMEMORY&&!out&&initialize_calls==0&&failure_logs.size()==1);
  assert(failure_logs[0].find("reason=native-nil")!=std::string::npos);
  assert(failure_logs[0].find("bytes="+std::to_string(last_charge))!=std::string::npos);
  assert(failure_logs[0].find("available="+std::to_string(available_bytes))!=std::string::npos);
 }
 else{assert(hr==S_OK&&out&&invalid_initializations>0);delete out;}
 clean();
 std::printf("%s failed native backing: HRESULT=%08x initialization-calls=%u\n",expect_candidate?"candidate":"baseline",unsigned(hr),unsigned(initialize_calls));
 // An actual admission refusal cannot create metadata, Metal backing or data.
 reset(device);deny_always=true;out=reinterpret_cast<Tag::COM_IMPL*>(1);
 hr=create<Tag>(device,desc,initial,&out);
 if(expect_candidate){
  assert(hr==E_OUTOFMEMORY&&!out&&texture_born==0&&backing_calls==0&&initialize_calls==0&&acquire_calls==2);
  assert((acquire_flags==std::vector<uint64_t>{0,1}));
  assert(emergency_trim_calls==2&&emergency_sweep_calls==2&&transient_trim_calls==2);
  assert(failure_logs.size()==2&&failure_logs[1].find("reason=physical-budget")!=std::string::npos);
  assert(failure_logs[1].find("available="+std::to_string(available_bytes))!=std::string::npos);
 }
 else{assert(hr==S_OK&&out&&backing_calls==1);delete out;}
 clean();
 if(!expect_candidate){assert(failure_logs.empty());std::puts("PASS baseline reproduces unadmitted creation and S_OK with nil native backing");return 0;}
 // Hold the permit across all array/mip copies; return logical descriptors and
 // exactly the caller's mip/slice bytes after the existing physical profile.
 reset(device);force_bias=true;desc.ArraySize=2;
 out=nullptr;hr=create<Tag>(device,desc,initial,&out);assert(hr==S_OK&&out);
 assert(out->logical.Width==16&&out->logical.MipLevels==3&&out->bias==1);
 assert(out->owner->info.width==8&&out->owner->info.mipmap_level_count==2);
 assert(last_charge==dxmt::mem_census_texture_bytes(out->owner->info,true));
 assert(out->owner->current()->data[0][0]==2&&out->owner->current()->data[1][0]==3);
 assert(out->owner->current()->data[2][0]==5&&out->owner->current()->data[3][0]==6);
 assert(acquire_calls==1&&release_calls==1&&bc_queries==1&&flush_calls==0&&failure_logs.size()==2);delete out;clean();desc.ArraySize=1;
 std::puts("PASS permit precedes backing, covers every initial copy, releases at return; logical/physical mip and array bytes preserved");
 // Unknown native measurements keep the genuine allocator behavior.
 reset(device);unknown_backend=true;out=nullptr;
 assert(create<Tag>(device,desc,initial,&out)==S_OK&&out&&backing_calls==1&&release_calls==0&&flush_calls==0);delete out;clean();
 reset(device);unknown_backend=true;fail_native=true;out=reinterpret_cast<Tag::COM_IMPL*>(1);
 assert(create<Tag>(device,desc,initial,&out)==E_OUTOFMEMORY&&!out&&initialize_calls==0&&flush_calls==0);clean();
 // A soft grant trims completed resources but does not wait on every texture.
 reset(device);reply_code=2;out=nullptr;
 assert(create<Tag>(device,desc,initial,&out)==S_OK&&out&&wait_calls==0&&flush_calls==1);
 assert((acquire_flags==std::vector<uint64_t>{0})&&emergency_trim_calls==0&&emergency_sweep_calls==0);
 assert(flush_with_credit==1&&last_flush_initializations==desc.MipLevels);delete out;clean();
 reset(device);reply_code=2;desc.Usage=D3D11_USAGE_DEFAULT;out=nullptr;
 assert(create<Tag>(device,desc,nullptr,&out)==S_OK&&out);
 assert(flush_calls==1&&wait_calls==0&&flush_with_credit==1&&last_flush_initializations==desc.MipLevels);
 for(const auto&sub:out->owner->current()->data)assert(!sub.empty()&&sub[0]==0);
 delete out;clean();desc.Usage=D3D11_USAGE_IMMUTABLE;
 // A denied allocation waits only for an actual submitted GPU upload. Success
 // requires a fresh real permit; timeout never manufactures initialization.
 reset(device);deny_always=true;grant_after_wait=true;device.queue().initializer.submitted=7;
 out=nullptr;assert(create<Tag>(device,desc,initial,&out)==S_OK&&out);
 assert(wait_calls==1&&waited_seq==7&&waited_ms==50&&acquire_calls==2);delete out;clean();
 assert((acquire_flags==std::vector<uint64_t>{0,1})&&emergency_sweep_calls==2&&transient_trim_calls==2);
 reset(device);deny_always=true;device.queue().initializer.submitted=9;
 out=reinterpret_cast<Tag::COM_IMPL*>(1);assert(create<Tag>(device,desc,initial,&out)==E_OUTOFMEMORY&&!out);
 assert(wait_calls==1&&waited_seq==9&&waited_ms==50&&backing_calls==0);clean();
 std::puts("PASS unknown-backend fallback, soft grants without waits, bounded GPU-event retry and truthful timeout/OOM");
 // Recovery is a queue-wide pressure episode, not one emergency block churn
 // per small texture. Run the actual queue latch and factory for every case.
 reset(device);deny_always=true;grant_completion_lane=true;reply_code=2;
 for(unsigned i=0;i<100;++i){
  out=nullptr;assert(create<Tag>(device,desc,initial,&out)==S_OK&&out);
  assert(out->owner->current()->data[0][0]==1);delete out;
 }
 assert(acquire_calls==200&&emergency_sweep_calls==2&&transient_trim_calls==2&&emergency_trim_calls==2);
 deny_always=false;reply_code=1;
 out=nullptr;assert(create<Tag>(device,desc,initial,&out)==S_OK&&out);delete out;
 deny_always=true;reply_code=2;
 out=nullptr;assert(create<Tag>(device,desc,initial,&out)==S_OK&&out);delete out;
 assert(emergency_sweep_calls==4&&transient_trim_calls==4&&emergency_trim_calls==4);clean();
 reset(device);std::atomic<unsigned> recovery_winners{0};std::vector<std::thread> recovery_workers;
 for(unsigned i=0;i<8;++i)recovery_workers.emplace_back([&]{
  if(device.queue().allocationRecoveryDrain(3))++recovery_winners;
 });
 for(auto&worker:recovery_workers){worker.join();}
 assert(recovery_winners==1);
 device.queue().allocationRecoveryDrain(2);assert(!device.queue().allocationRecoveryDrain(3));
 device.queue().allocationRecoveryDrain(1);assert(device.queue().allocationRecoveryDrain(3));
 std::puts("PASS one emergency drain per shared recovery episode; 100 small textures reuse warm uploads; healthy native grant alone rearms it");
 // Native failures are checked in the shared and renamable-depth branches too.
 reset(device);fail_native=true;desc.MiscFlags=D3D11_RESOURCE_MISC_SHARED;
 out=reinterpret_cast<Tag::COM_IMPL*>(1);assert(create<Tag>(device,desc,initial,&out)==E_OUTOFMEMORY&&!out&&initialize_calls==0);clean();
 desc.MiscFlags=0;
 reset(device);fail_native=true;desc.MipLevels=1;desc.BindFlags=D3D11_BIND_DEPTH_STENCIL;
 out=reinterpret_cast<Tag::COM_IMPL*>(1);assert(create<Tag>(device,desc,initial,&out)==E_OUTOFMEMORY&&!out&&initialize_calls==0);clean();
 desc.MipLevels=3;desc.BindFlags=D3D11_BIND_SHADER_RESOURCE;
 for(mach_port_t port:{0u,17u}){
  reset(device);reply_code=2;native_shared_port=port;desc.MiscFlags=D3D11_RESOURCE_MISC_SHARED;
  out=nullptr;assert(create<Tag>(device,desc,initial,&out)==S_OK&&out&&flush_calls==1&&flush_with_credit==1);
  delete out;clean();desc.MiscFlags=0;
 }
 reset(device);
 D3D11_TEXTURE1D_DESC one;one.Height=1;
 dxmt::tag_texture_1d::COM_IMPL*one_out=nullptr;
 assert(create<dxmt::tag_texture_1d>(device,one,initial,&one_out)==S_OK&&one_out);
 delete one_out;clean();
 reset(device);
 D3D11_TEXTURE3D_DESC1 volume;volume.Depth=4;volume.Format=28;
 dxmt::tag_texture_3d::COM_IMPL*volume_out=nullptr;
 assert(create<dxmt::tag_texture_3d>(device,volume,initial,&volume_out)==S_OK&&volume_out);
 assert(volume_out->owner->info.depth==4&&bc_queries==0);delete volume_out;clean();
 std::puts("PASS healthy and pressured initial-zero/shared/importable/1D/3D creation retain real backing and credit cleanup");
 // Exception unwind cannot leak admission credits or publish an output.
 reset(device);throw_initialization=true;out=reinterpret_cast<Tag::COM_IMPL*>(1);
 try{create<Tag>(device,desc,initial,&out);assert(false);}catch(const std::runtime_error&){}
 assert(!out);clean();
 std::puts("PASS shared/depth nil backing and initialization exception leave no output, credit or resource leak");
 // Concurrent creator1 holds its real permit while the complete initial data
 // is being enqueued. A second denied creator must never allocate a texture.
 reset(device);single_slot=true;block_initialization=true;
 auto first=std::async(std::launch::async,[&]{Tag::COM_IMPL*p=nullptr;auto r=create<Tag>(device,desc,initial,&p);delete p;return r;});
 const auto end=std::chrono::steady_clock::now()+std::chrono::seconds(5);
 while(!initialization_entered.load()){assert(std::chrono::steady_clock::now()<end);std::this_thread::sleep_for(std::chrono::microseconds(50));}
 out=reinterpret_cast<Tag::COM_IMPL*>(1);hr=create<Tag>(device,desc,initial,&out);
 assert(hr==E_OUTOFMEMORY&&!out&&backing_calls==1);
 unblock_initialization=true;assert(first.get()==S_OK);clean();
 std::puts("PASS concurrent denied creator creates no backing while another creator owns its initialization credit");
 // Repeated soft-pressure creates must not walk the full dynamic registry on
 // every texture at the same unchanged queue/completion frontier.
 reset(device);reply_code=2;
 for(unsigned i=0;i<100;++i){out=nullptr;assert(create<Tag>(device,desc,initial,&out)==S_OK);delete out;}
 assert(sweep_calls==1);device.queue().coherent++;
 out=nullptr;assert(create<Tag>(device,desc,initial,&out)==S_OK);delete out;assert(sweep_calls==2);
 clean();
 std::puts("PASS fresh permits per create with one cold-cache sweep per unchanged frontier; hot policy and GPU proof retained");
 reset(device);desc.Width=0;out=reinterpret_cast<Tag::COM_IMPL*>(1);
 assert(create<Tag>(device,desc,initial,&out)==E_INVALIDARG&&!out&&acquire_calls==0);clean();
 // Failure reporting is one path-free, atomically bounded trail for every
 // texture factory instantiation, never an allocation-success hot-path log.
 assert(failure_logs.size()==7);desc.Width=16;
 for(unsigned i=0;i<32;++i){
  reset(device);fail_native=true;out=reinterpret_cast<Tag::COM_IMPL*>(1);
  assert(create<Tag>(device,desc,initial,&out)==E_OUTOFMEMORY&&!out&&initialize_calls==0);clean();
 }
 assert(failure_logs.size()==8);
 for(const auto&report:failure_logs){
  assert(report.find("[texture-admission-v1] result=E_OUTOFMEMORY reason=")==0);
  assert(report.find("bytes=")!=std::string::npos&&report.find("available=")!=std::string::npos);
 }
 std::puts("PASS failure-only marker reports actual capacity/headroom and stops after eight total failures");
 std::puts("PASS actual production factory returns genuine failures and preserves all owned backend data; no GPU/RSS claim");
}
'''

# The depth pool retains the same existing Texture object without inventing a
# second independent shared_ptr owner. This adapter models that intrusive Rc.
BACKEND = BACKEND.replace('class Texture {', 'class Texture : public std::enable_shared_from_this<Texture> {')
BACKEND = BACKEND.replace('texture_(texture),flags_(flags){ assert(false&&"raw owner must not be duplicated"); }',
                          'texture_(texture->shared_from_this()),flags_(flags){}')
BACKEND = BACKEND.replace('Rc()=default; Rc(T *ptr):Base(ptr){}',
                          'Rc()=default; Rc(T *ptr):Base(ptr){} Rc(Base ptr):Base(std::move(ptr)){}')
BACKEND = BACKEND.replace(' INIT_PRESSURE_WAIT', ' ' + declaration(staged_initializer, 'bool waitForMemoryPressure('))
queue_header = UPLOAD.stage_queue_header((ROOT / 'dxmt/src/dxmt/dxmt_command_queue.hpp').read_text())
BACKEND = BACKEND.replace(' RECOVERY_LATCH_METHOD', declaration(queue_header, 'bool allocationRecoveryDrain('))

def factory(text):
    return declaration(text, 'template <typename tag>\nHRESULT CreateDeviceTextureInternal(')


def main():
    common = PREFIX + types + '\nstatic bool expect_candidate=false;\n' + BUDGET + memory_header
    common += '\n#define ORIGINAL_FORMAT(format) (format & ~WMTPixelFormatCustomSwizzle)\nnamespace dxmt {\n' + accounting + '\n}\n'
    common += mip_policy + '\nstatic_assert(dxmt::mip_clamp::kHeadroomUnknown == -1);\n' + BACKEND
    is_bc = declaration(original, 'static inline bool IsBCFormatForClamp(')
    with tempfile.TemporaryDirectory(prefix='madeira-texture-admission-') as temp:
        temp = Path(temp)
        for name, text in (('baseline', original), ('candidate', staged)):
            body = ('namespace dxmt {\n' + is_bc +
                    (STAGE.ADMISSION_HELPER if name == 'candidate' else '') + factory(text) + '\n}\n')
            path = temp / (name + '.cpp')
            binary = temp / name
            path.write_text(common + body + TESTS)
            compiler = shlex.split(os.environ.get('CXX', 'c++'))
            subprocess.run([*compiler, '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
                            '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                            str(path), '-o', str(binary)], check=True)
            subprocess.run([str(binary), '1' if name == 'candidate' else '0'], check=True, timeout=30)
    assert (ROOT / 'dxmt' / NAME).read_text() == original
    print('PASS production texture admission/failure propagation, real PE permit RAII, full factory paths and source immutability')


if __name__ == '__main__':
    main()
