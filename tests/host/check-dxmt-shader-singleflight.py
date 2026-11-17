#!/usr/bin/env python3
"""Exercise the extracted production shader-cache path with native threads.

The CreateShader body, constructor/destructor and digest implementation are
actual DXMT source. The SM50 platform API is a deliberately blocking host stub;
this test measures duplicated preparation/copy ownership, not Metal or CS2 FPS.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
NAME = 'src/d3d11/d3d11_pipeline_cache.cpp'
spec = importlib.util.spec_from_file_location('shader_singleflight', ROOT / 'tools/build/stage-dxmt-shader-singleflight.py')
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
CXX = shlex.split(os.environ.get('CXX', 'c++'))
CC = shlex.split(os.environ.get('CC', 'cc'))


def function(source, start):
    a = source.index(start)
    b = source.index('{', a)
    depth = 1
    end = b + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[a:end]


PREFIX = r'''
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>
#include "sha1_util.hpp"
using namespace std::chrono_literals;
namespace dxmt {
using mutex = std::mutex; // Host adapter for the production Windows SRW mutex.
static void check(bool ok, const char *why) { if (!ok) { std::fprintf(stderr,"FAIL %s\n",why); std::abort(); } }
template<class Fn> static void eventually(Fn fn, const char *why) {
  auto end=std::chrono::steady_clock::now()+5s;
  while(!fn()){check(std::chrono::steady_clock::now()<end,why);std::this_thread::sleep_for(100us);}
}
static std::atomic<unsigned> prepares, active, high_active, native_live, native_destroyed, constructors, deleted, failures, error_frees;
static std::atomic<bool> block_prepare;
static std::mutex gate_mutex;
static std::condition_variable gate;
struct NativeShader {std::vector<uint8_t> bytes;};
using sm50_shader_t=NativeShader*;
using sm50_error_t=const char*;
struct MTL_SHADER_REFLECTION {unsigned NumConstantBuffers=1, NumArguments=1;};
struct MTL_SM50_SHADER_ARGUMENT {uint32_t value;};
static int SM50Initialize(const void *data, uint32_t length, sm50_shader_t *out, MTL_SHADER_REFLECTION *reflection, sm50_error_t *err) {
  prepares.fetch_add(1);
  unsigned now=active.fetch_add(1)+1, peak=high_active.load();
  while(now>peak&&!high_active.compare_exchange_weak(peak,now)){}
  {std::unique_lock<std::mutex> lock(gate_mutex);gate.wait(lock,[]{return !block_prepare.load();});}
  active.fetch_sub(1);
  unsigned pending=failures.load();
  while(pending&&!failures.compare_exchange_weak(pending,pending-1)){}
  if(pending){*err="host-injected validation failure";return 1;}
  auto shader=new NativeShader;
  shader->bytes.assign((const uint8_t*)data,(const uint8_t*)data+length);
  native_live.fetch_add(1);*out=shader;*reflection={1,1};return 0;
}
static void SM50Destroy(sm50_shader_t shader){check(shader!=nullptr,"destroy real parsed owner");delete shader;native_live.fetch_sub(1);native_destroyed.fetch_add(1);}
static void SM50GetArgumentsInfo(sm50_shader_t shader,MTL_SM50_SHADER_ARGUMENT *cb,MTL_SM50_SHADER_ARGUMENT *arg){check(shader!=nullptr,"reflection has parsed shader");cb->value=17;arg->value=29;}
static const char *SM50GetErrorMessageString(sm50_error_t err){return err;}
static void SM50FreeError(sm50_error_t err){check(err!=nullptr,"free actual error");error_frees.fetch_add(1);}
#define ERR(...) ((void)0)
class PipelineCache {
public:
 class CachedSM50Shader {
 public:
  PipelineCache *cache;
  sm50_shader_t shader=nullptr;
  Sha1Digest sha1_;
  MTL_SHADER_REFLECTION reflection_;
  MTL_SM50_SHADER_ARGUMENT *arguments_info_buffer;
  std::vector<uint8_t> bytecode_;
  static void *operator new(size_t n){constructors.fetch_add(1);return ::operator new(n);}
  static void operator delete(void*p){deleted.fetch_add(1);::operator delete(p);}
__CONSTRUCTOR__
__DESTRUCTOR__
 };
__CACHE_MEMBERS__
 bool keep_shader_ir_=false;
 unsigned published=0;
 void NoteShaderCached(size_t){published++;} // Already inside the production map lock.
__CREATE__
};
static void reset(bool block=false,unsigned fail=0){
  check(native_live==0,"previous native owners released");
  prepares=active=high_active=native_destroyed=constructors=deleted=error_frees=0;
  failures=fail;block_prepare=block;
}
static void release(){ {std::lock_guard<std::mutex> lock(gate_mutex);block_prepare=false;}gate.notify_all();}
static std::vector<uint8_t> bytes(unsigned seed=3){std::vector<uint8_t> out(16387);for(size_t i=0;i<out.size();i++)out[i]=(uint8_t)(seed+i*17+(i>>4));return out;}
static unsigned stripe(const std::vector<uint8_t>&v){return std::hash<Sha1Digest>{}(Sha1HashState::compute(v.data(),v.size()))%64;}
static void validate(PipelineCache::CachedSM50Shader *shader,const std::vector<uint8_t>&data,bool keep){
 check(shader!=nullptr,"genuine success returns cached shader");
 check(shader->reflection_.NumArguments==1&&shader->arguments_info_buffer[0].value==17&&shader->arguments_info_buffer[1].value==29,"reflection preserved");
 if(keep){check(shader->shader&&shader->shader->bytes==data&&shader->bytecode_.empty(),"kept native IR ownership");}
 else{check(!shader->shader&&shader->bytecode_==data,"exact retained bytecode ownership");}
}
'''

SUFFIX = r'''
static void duplicate_case(bool keep){
 reset(true);
 auto data=bytes();
 std::array<PipelineCache::CachedSM50Shader*,8> result{};
 std::atomic<unsigned> started{0};
 {
  PipelineCache cache;cache.keep_shader_ir_=keep;
  std::array<std::thread,8> threads;
  for(unsigned i=0;i<threads.size();i++)threads[i]=std::thread([&,i]{started.fetch_add(1);while(started.load()!=8)std::this_thread::yield();result[i]=cache.CreateShader(data.data(),data.size());});
  eventually([&]{return prepares.load()==EXPECTED_DUPLICATES;},"concurrent preparation reached expected count");
  std::this_thread::sleep_for(20ms);
  check(prepares==EXPECTED_DUPLICATES,"duplicate preparation stays bounded before publication");
  release();for(auto&t:threads)t.join();
  for(auto*p:result){check(p==result[0],"same digest returns same actual owner");validate(p,data,keep);}
  check(cache.published==1&&cache.shaders_.size()==1,"one cache entry published");
  check(constructors==EXPECTED_DUPLICATES,"constructor/copy only for actual preparations");
  check(native_live==(keep?1u:0u),"losing native owners retired");
  const auto before=prepares.load();
  for(unsigned i=0;i<10000;i++)check(cache.CreateShader(data.data(),data.size())==result[0],"cache hit preserves identity");
  check(prepares==before&&constructors==EXPECTED_DUPLICATES,"cache hits do not prepare or recopy");
#if CANDIDATE
  {
    // A held miss stripe must never obstruct a published cache hit.
    std::lock_guard<mutex> held(cache.shader_prepare_mutexes_[stripe(data)]);
    std::atomic<bool> hit_done{false};
    std::thread hit([&]{check(cache.CreateShader(data.data(),data.size())==result[0],"hit identity while miss stripe held");hit_done=true;});
    eventually([&]{return hit_done.load();},"published hit bypasses preparation stripe");
    hit.join();
  }
#endif
  std::printf("duplicate keep-ir=%d prepares=%u constructors=%u bytecode-copies=%u preparation-input-bytes=%zu retained-bytecode=%zu\n",keep,(unsigned)prepares,(unsigned)constructors,keep?0u:constructors.load(),data.size()*prepares.load(),keep?0u:data.size());
 }
 check(native_live==0&&constructors==deleted,"all retained and losing owners destroyed once");
}
static void distinct_case(bool collision){
 reset(true);
 auto one=bytes(9),two=bytes(10);
 for(unsigned seed=10;(stripe(one)==stripe(two))!=collision;seed++)two=bytes(seed);
 check(one!=two,"test uses different content");
 {
  PipelineCache cache;
  PipelineCache::CachedSM50Shader *a=nullptr,*b=nullptr;
  std::thread ta([&]{a=cache.CreateShader(one.data(),one.size());});
  eventually([&]{return prepares.load()==1;},"first distinct parse entered");
  std::thread tb([&]{b=cache.CreateShader(two.data(),two.size());});
  if(collision&&CANDIDATE){std::this_thread::sleep_for(20ms);check(prepares==1,"same stripe waits without duplicating entry");}
  else eventually([&]{return active.load()==2;},"different stripes parse concurrently");
  release();ta.join();tb.join();
  check(a!=b&&cache.published==2&&cache.shaders_.size()==2,"different digests retain distinct owners");
  validate(a,one,false);validate(b,two,false);
  check(prepares==2,"each distinct shader prepared exactly once");
  if(!collision)check(high_active==2,"no global preparation serialization");
  std::printf("distinct collision=%d prepares=%u peak-parallel=%u exact-content=PASS\n",collision,(unsigned)prepares,(unsigned)high_active);
 }
 check(native_live==0&&constructors==deleted,"distinct owners destroyed once");
}
static void failure_case(){
 reset(false,1);
 auto data=bytes(19);
 {
  PipelineCache cache;
  check(cache.CreateShader(data.data(),data.size())==nullptr,"validation failure remains an actual failure");
  check(cache.shaders_.empty()&&constructors==0&&error_frees==1,"failure publishes no fake shader or copied bytes");
  auto*shader=cache.CreateShader(data.data(),data.size());validate(shader,data,false);
  check(prepares==2&&cache.published==1,"failure releases stripe and later request retries");
 }
 check(native_live==0&&constructors==deleted,"retry ownership balanced");
}
int main(){
 duplicate_case(false);duplicate_case(true);
 distinct_case(false);distinct_case(true);failure_case();
 std::puts("PASS actual CreateShader/constructor/destructor; native SM50 API stub; no GPU/FPS claim");
 return 0;
}
} // namespace dxmt
int main(){return dxmt::main();}
'''

source = (ROOT / 'dxmt' / NAME).read_text()
candidate = stage.stage_file(NAME, source)
assert source == (ROOT / 'dxmt' / NAME).read_text(), 'vendor input unchanged'
try:
    stage.stage_file(NAME, candidate)
except ValueError:
    pass
else:
    raise AssertionError('already staged input must fail closed')
try:
    stage.stage_file(NAME, source.replace('  std::shared_mutex mutex_shares;', '  std::shared_mutex changed_contract;'))
except ValueError:
    pass
else:
    raise AssertionError('changed production input must fail closed')
assert candidate.count(stage.MARKER) == 1
assert 'std::array<dxmt::mutex, 64> shader_prepare_mutexes_' in candidate
constructor = function(source, '    CachedSM50Shader(PipelineCache *cache,')
destructor = function(source, '    ~CachedSM50Shader()')
name = '  CachedSM50Shader *CreateShader('
sha_dir = ROOT / 'dxmt/src/util/sha1'
with tempfile.TemporaryDirectory(prefix='madeira-shader-singleflight-') as temp:
    temp = Path(temp)
    subprocess.run(CC + ['-O2', '-c', str(sha_dir/'sha1.c'), '-o', str(temp/'sha1.o')], check=True)
    for label, text, expected in [('baseline', source, 8), ('candidate', candidate, 1)]:
        first = text.index('  std::unordered_map<Sha1Digest, std::unique_ptr<CachedSM50Shader>> shaders_;')
        end = text.index('  /* ml1222: d3d11.keepShaderIR=', first)
        harness = PREFIX.replace('__CONSTRUCTOR__', constructor).replace('__DESTRUCTOR__', destructor)
        harness = harness.replace('__CACHE_MEMBERS__', text[first:end]).replace('__CREATE__', function(text, name))
        harness += SUFFIX.replace('EXPECTED_DUPLICATES', str(expected)).replace('CANDIDATE', str(int(label=='candidate')))
        path = temp / (label+'.cpp')
        path.write_text(harness)
        binary = temp / label
        subprocess.run(CXX + ['-std=c++20', '-O2', '-pthread', '-I'+str(sha_dir), str(path),
                              str(sha_dir/'sha1_util.cpp'), str(temp/'sha1.o'), '-o', str(binary)], check=True)
        print(label, 'CreateShader SHA256', hashlib.sha256(function(text,name).encode()).hexdigest(), flush=True)
        subprocess.run([str(binary)], check=True, timeout=30)
print('PASS staging fail-closed/idempotence, actual source bodies, digest, concurrency, failure retry, ownership')
