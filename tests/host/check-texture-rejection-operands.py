#!/usr/bin/env python3
"""Replay the eight a1ab native admission records against production code.

The export records destination capacity, not its complete prospective charge.
Ring cursor and initial-data state are missing. These cases therefore compare
explicit warm, empty-upload-ring and zero-scratch states; they do not infer
which hidden state occurred on the iPhone.
"""
import ast
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
fixture_path = ROOT / 'tests/host/check-dxmt-resource-budget.py'
tree = ast.parse(fixture_path.read_text())
prefix = []
for node in tree.body:
    if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'abi' for t in node.targets):
        break
    prefix.append(node)
namespace = {'__file__': str(fixture_path), '__name__': 'operand_fixture'}
exec(compile(ast.Module(prefix, type_ignores=[]), str(fixture_path), 'exec'), namespace)
code = namespace['code'].split('int main(){', 1)[0]

def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded

upload = module('operand_upload', 'tools/build/stage-dxmt-upload-memory.py')
zero = module('operand_zero', 'tools/build/stage-dxmt-initializer-failure.py')
admission = module('operand_admission', 'tools/build/stage-dxmt-texture-admission.py')
factory = admission.stage_factory((ROOT / 'dxmt' / admission.FILES[0]).read_text())
assert 'if (!compact && temporary_bytes && payload > (uint64_t{4} << 20))' in factory
ring = upload.stage_ring((ROOT / 'dxmt/src/dxmt/dxmt_ring_bump_allocator.hpp').read_text())
ring_class = ring[ring.index('template <typename Allocator, size_t BlockSize ='):ring.index('\nclass GpuPrivateBufferBlockAllocator')]
ring_methods = ring[ring.index('template <typename Allocator, size_t BlockSize, class mutex>\nstd::pair'):ring.rindex('\n} // namespace dxmt')]
code += r'''
#include <algorithm>
#include <queue>
#define WARN(...) ((void)0)
namespace dxmt {
using mutex = std::mutex;
template<class T,class U>size_t align(T v,U a){return (size_t(v)+size_t(a)-1)&~(size_t(a)-1);}
constexpr size_t kStagingBlockSize = 32ull<<20;
constexpr size_t kStagingBlockLifetime = 300;
size_t madeiraRingBlockSize(size_t n){return n;}
bool ringOversizeReuseEnabled(){return false;}
bool madeiraSwitch(const char*){return true;}
struct Logger {template<class...T>static void info(const T&...) {}};
''' + ring_class + ring_methods + zero.ZERO_SIZE + r'''
}
static unsigned backing_allocations;
static size_t backing_bytes, peak_backing_bytes;
struct ForecastAllocator {
 struct Block {std::vector<uint8_t> bytes;size_t charged;
  explicit Block(size_t size):bytes(size),charged(size){backing_bytes+=size;peak_backing_bytes=std::max(peak_backing_bytes,backing_bytes);}
  Block(Block&&other):bytes(std::move(other.bytes)),charged(std::exchange(other.charged,0)){}
  ~Block(){assert(backing_bytes>=charged);backing_bytes-=charged;}
  Block(const Block&)=delete;};
 Block allocate(size_t size){++backing_allocations;return Block(size);}
};
int main(){
 struct Row {uint64_t bytes,available,physical;};
 const Row rows[] = {
  {22543008,221808272,6220642672},
  {10485760,209127080,6233323864},
  {10485760,209077928,6233373016},
  {10485760,208324264,6234126680},
  {22020096,208209576,6234241368},
  {15360,204899864,6237551080},
  {16384,206964248,6235486696},
  {65536,206538264,6235912680},
 };
 constexpr uint64_t floor = 201326592;
 dxmt::RingBumpState<ForecastAllocator,32ull<<20> ring(ForecastAllocator{});
 for(unsigned index=0;index<8;++index){
  const auto&r=rows[index];
  assert(r.available+r.physical==6144*MiB && !md_resource_growth_held);
  const uint64_t extra=ring.batch_growth(0,r.bytes+255,r.bytes,256);
  assert(extra==32*MiB&&!backing_allocations);
  sample(r.available);md_resource_growth_pressure=1;
  auto cold=acquire(r.bytes+extra,1);
  assert(cold.ret==3&&!cold.ptr&&cold.len==r.available);
  assert(detail(cold,0)==r.physical&&detail(cold,1)==0&&detail(cold,2)==floor&&detail(cold,3)==1);
  auto warm=acquire(r.bytes,1);
  const uint64_t zero_growth=dxmt::zeroAllocationSize(r.bytes);
  // Keep these calls independent: warm ownership is not another pending
  // creator in the recorded pending=0 conditions.
  if(warm.ptr){assert(release(warm.ptr));}
  auto scratch=acquire(r.bytes+zero_growth,1);
  assert(detail(scratch,1)==0);
  if(scratch.ptr){assert(release(scratch.ptr));}
  if(index<5){
   assert(warm.ret==3&&!warm.ptr&&detail(warm,3)==1);
   assert(scratch.ret==3&&!scratch.ptr&&detail(scratch,3)==1);
  }else{
   assert(warm.ret==2&&warm.ptr&&detail(warm,1)==0&&detail(warm,3)==0);
   assert(scratch.ret==2&&scratch.ptr&&detail(scratch,3)==0);
  }
  assert(!md_resource_growth_held);
  std::printf("PASS record%u destination=%llu above-floor=%llu empty-ring-extra=%llu cold=E_OUTOFMEMORY warm=%s zero-extra=%llu\n",
   index+1,(unsigned long long)r.bytes,(unsigned long long)(r.available-floor),
   (unsigned long long)extra,warm.ptr?"grant":"deny",(unsigned long long)zero_growth);
 }
 // These are explicitly controlled three-part transfer traces, not recovered
 // game descriptors. The original upload/descriptor state is absent from the
 // archive. Native admission still sees each row's identical available bytes,
 // footprint, floor and pending=0. Only actual prospective growth changes.
 for(unsigned index=0;index<8;++index){
  const auto&r=rows[index];
  const uint64_t payload=r.bytes+3*255;
  const size_t minimum=dxmt::align(payload,size_t(256));
  dxmt::RingBumpState<ForecastAllocator,32ull<<20> compact(ForecastAllocator{});
  const unsigned before=backing_allocations;
  const uint64_t extra=compact.batch_growth(0,payload,r.bytes-512,256,minimum);
  assert(extra==minimum&&backing_allocations==before);
  sample(r.available);events[0].value=0;
  // The native-BC compact factory reserves destination plus this whole-batch
  // ring capacity. Its extra rotation surcharge applies only to healthy
  // fixed-size blocks, as checked against the actual factory above.
  const uint64_t charge=r.bytes+extra;
  auto admitted=acquire(charge,1);
  assert(detail(admitted,1)==0&&detail(admitted,2)==floor&&admitted.len==r.available);
  uint64_t measured_available=r.available;
  if(index<5){
   assert(admitted.ret==3&&!admitted.ptr&&detail(admitted,3)==1);
   assert(backing_allocations==before&&!backing_bytes);
   // This is an explicitly supplied fresh physical measurement. Releasing
   // cache wrappers alone does not update or invent native headroom.
   measured_available=r.available+68*MiB;
   sample(measured_available);admitted=acquire(charge,1);
   assert(admitted.ptr&&admitted.len==measured_available&&detail(admitted,1)==0);
  }
  {
   assert(admitted.ret==2&&admitted.ptr&&!detail(admitted,3));
   assert(handoff(admitted.ptr,0x51,UINT64_MAX).ret==1);
   const size_t parts[]={size_t(r.bytes-512),256,256};
   std::vector<uint8_t> expected(extra,0);
   ForecastAllocator::Block *owned=nullptr;
   for(unsigned part=0;part<3;++part){
    const auto allocation=compact.allocate(1,0,parts[part],256,minimum);
    if(!owned)owned=&allocation.first;
    assert(owned==&allocation.first&&allocation.second+parts[part]<=extra);
    const uint8_t value=uint8_t(0x40+index*3+part);
    std::fill_n(allocation.first.bytes.begin()+allocation.second,parts[part],value);
    std::fill_n(expected.begin()+allocation.second,parts[part],value);
   }
   assert(backing_allocations==before+1&&backing_bytes==extra&&owned->bytes==expected);
   assert(handoff(admitted.ptr,0x51,1).ret==1&&md_resource_growth_held==charge);
   assert(compact.trim_completed(0,true)==0&&owned->bytes==expected);
   assert(compact.batch_growth(0,payload,parts[0],256,minimum)==extra);
   // Advance only the owned fixture event; the actual receipt producer must
   // retire the GPU credit, and the fresh snapshot still counts residency.
   sample(measured_available-charge);events[0].value=1;
   auto polled=acquire(1);assert(polled.ptr&&md_resource_growth_held==1&&release(polled.ptr));
   assert(!md_resource_growth_held&&event_loans.empty()&&available>=floor);
   assert(compact.batch_growth(1,payload,parts[0],256,minimum)==0);
   const auto *owned_bytes=owned->bytes.data();
   auto reused=compact.allocate(2,1,parts[0],256,minimum);
   // FIFO rotation moves its wrapper, while reusing the same backing.
   assert(reused.first.bytes.data()==owned_bytes&&backing_allocations==before+1);
   assert(compact.trim_completed(1,true)==0&&backing_bytes==extra);
   assert(compact.trim_completed(2,true)==0&&backing_bytes==extra);
   assert(compact.batch_growth(2,payload,parts[0],256,minimum)==0);
   assert(compact.trim_completed(2,false)==extra&&!backing_bytes);
  }
  assert(!md_resource_growth_held&&!backing_bytes);
  std::printf("PASS compact record%u destination=%llu upload=%llu ring-backed-charge=%llu original-headroom=%llu original-result=%s transfer-after-fresh-measurement=%llu\n",
   index+1,(unsigned long long)r.bytes,(unsigned long long)extra,(unsigned long long)charge,
   (unsigned long long)r.available,index<5?"E_OUTOFMEMORY":"grant",
   (unsigned long long)measured_available);
 }
 assert(peak_backing_bytes<=32*MiB);
 std::puts("PASS pressure-sized forecast equals actual transfer backing; three parts and byte guards preserved, pending resources retained, completed warm reuse bounded and native GPU credits balanced");
 {
  dxmt::RingBumpState<ForecastAllocator,32ull<<20> warm(ForecastAllocator{});
  const unsigned before=backing_allocations;
  warm.preallocate(1);assert(backing_allocations==before+1);
  assert(warm.batch_growth(0,15360+255,15360,256)==0);
  warm.allocate(1,0,32*MiB-16384,256);
  // A completed latest block with enough tail for the first subresource
  // cannot promise full-batch reuse: that first append makes it pending.
  assert(warm.batch_growth(1,65536+255,15360,256)==32*MiB);
  warm.seal_latest();
  assert(warm.batch_growth(1,65536+255,15360,256)==0);
  warm.allocate(2,1,15360,256);assert(backing_allocations==before+1);
  sample(rows[5].available);auto reused=acquire(rows[5].bytes);
  assert(reused.ptr&&release(reused.ptr));
  assert(warm.trim_completed(1)==0); // Current upload is still pending.
  assert(warm.trim_completed(2)==32*MiB);
  // CPU release alone must not invent os_proc_available_memory progress.
  auto not_measured=acquire(rows[5].bytes+32*MiB);
  assert(not_measured.ret==3&&!not_measured.ptr&&detail(not_measured,3)==1);
  sample(rows[5].available+32*MiB);auto measured=acquire(rows[5].bytes+32*MiB);
  assert(measured.ptr&&release(measured.ptr)&&!md_resource_growth_held);
 }
 assert(!backing_bytes&&peak_backing_bytes<=32*MiB);
 std::puts("PASS actual ring cursor/completion states distinguish warm reuse, pending tail, completed rotation and newly measured capacity; forecast never allocates");
 std::puts("PASS exact native predicates: printed destination alone explains first five denials; final three need additional prospective growth state");
 std::puts("NOTE pending=0, floor=192MiB, pressure latch=1; ring/initial-data state was not captured on the iPhone; no device allocation success claim");
}
'''

abi = (ROOT / 'dxmt/src/winemetal/winemetal.h').read_text()
abi = abi[abi.index('struct madeira_ctl_args {'):abi.index('WINEMETAL_API void MadeiraCtl')]
with tempfile.TemporaryDirectory(prefix='madeira-texture-operands-') as directory:
    path = Path(directory)
    (path/'winemetal.h').write_text('#pragma once\n#include <stdint.h>\n'+abi+'\nvoid MadeiraCtl(struct madeira_ctl_args*);\n')
    (path/'mach').mkdir()
    (path/'mach/mach.h').write_text('''#pragma once
#include <stdint.h>
extern "C" {
typedef struct {uint64_t phys_footprint;} task_vm_info_data_t;
typedef unsigned mach_msg_type_number_t;
typedef int* task_info_t;
#define TASK_VM_INFO_COUNT 42
#define TASK_VM_INFO_REV1_COUNT 12
#define TASK_VM_INFO 22
#define KERN_SUCCESS 0
int mach_task_self(void);int task_info(int,int,task_info_t,mach_msg_type_number_t*);
}
''')
    (path/'os').mkdir();(path/'os/proc.h').write_text('#pragma once\n#include <stddef.h>\nextern "C" size_t os_proc_available_memory(void);\n')
    (path/'sys').mkdir();(path/'sys/sysctl.h').write_text('#pragma once\n#include <stddef.h>\nextern "C" int sysctlbyname(const char*,void*,size_t*,void*,size_t);\n')
    source,binary=path/'operands.cpp',path/'operands'
    source.write_text(code)
    subprocess.run([os.environ.get('CXX','c++'),'-std=c++20','-O1','-Wall','-Wextra','-Werror','-Wno-unused-function','-pthread',
        '-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer',
        '-I',str(path),'-I',str(ROOT/'build/dxmt-ios'),str(source),'-o',str(binary)],check=True,timeout=60)
    subprocess.run([str(binary)],check=True,timeout=30)
