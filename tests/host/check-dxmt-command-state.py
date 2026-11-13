#!/usr/bin/env python3
"""Execute production vertex-binding and swapchain statistics bodies.

BindingSet and frame-statistics types come from the pinned source. The hosted
encoder records state, not GPU execution; std::format is the real C++20 library.
These measurements do not establish CS2 frame rate or productive GPU load.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('dxmt_command_state', ROOT / 'tools/build/stage-dxmt-command-state.py')
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
CXX = shlex.split(os.environ.get('CXX', 'c++'))


def function(source, signature):
    start = source.index(signature)
    begin = source.index('{', start)
    depth = 0
    pattern = r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]'
    for token in re.finditer(pattern, source[begin:], re.S):
        if token[0] == '{':
            depth += 1
        elif token[0] == '}':
            depth -= 1
            if not depth:
                return source[start:begin + token.end()]
    raise AssertionError(signature)


VERTEX_PREFIX = r'''
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>
#include <mutex>
#include <tuple>
#include <utility>
#include <vector>
#include "dxmt_binding_set.hpp"
#define ERR(...) ((void)0)
#define WARN(...) ((void)0)
#define IID_PPV_ARGS(x) (x)
using UINT = unsigned;
struct Buffer { unsigned identity, generation=1; };
struct D3D11ResourceCommon;
using ID3D11Buffer = D3D11ResourceCommon;
using IUnknown = D3D11ResourceCommon;
struct D3D11ResourceCommon {
  std::shared_ptr<Buffer> native;
  int refs=0;
  explicit D3D11ResourceCommon(unsigned id): native(std::make_shared<Buffer>(Buffer{id})) {}
  void AddRef(){++refs;}
  void Release(){assert(refs>0);--refs;}
  auto buffer(){return native;}
  void QueryInterface(ID3D11Buffer **p){*p=this;AddRef();}
};
template<class T> struct Com {
  T *p=nullptr;
  Com()=default; Com(T *v):p(v){if(p)p->AddRef();}
  Com(const Com &o):Com(o.p){}
  Com(Com &&o)noexcept:p(std::exchange(o.p,nullptr)){}
  ~Com(){if(p)p->Release();}
  Com& operator=(Com o){std::swap(p,o.p);return *this;}
  Com& operator=(T *v){return *this=Com(v);}
  T *operator->()const{return p;}
};
template<class T> auto forward_rc(T &p){return std::move(p);}
namespace dxmt {
@ENTRY@
struct ArgumentEncodingContext {
  struct Slot{std::shared_ptr<Buffer> buffer;unsigned offset=0,stride=0;};
  std::array<Slot,16> slots{};
  unsigned callbacks=0;
  void bindVertexBuffer(unsigned slot,unsigned offset,unsigned stride,std::shared_ptr<Buffer>&& buffer){
    slots[slot]={std::move(buffer),offset,stride};++callbacks;
  }
  void bindVertexBufferOffset(unsigned slot,unsigned offset,unsigned stride){
    slots[slot].offset=offset;slots[slot].stride=stride;++callbacks;
  }
  void clearState(){slots={};++callbacks;}
};
struct Context {
  using mutex_t=std::recursive_mutex;
  mutex_t mutex;
  struct State{struct IA{BindingSet<VERTEX_BUFFER_B,16> VertexBuffers;}InputAssembler;}state_;
  std::vector<std::function<void(ArgumentEncodingContext&)>> commands;
  ArgumentEncodingContext encoder;
  size_t recorded=0;
  template<class F>void EmitST(F &&f){commands.emplace_back(std::forward<F>(f));++recorded;}
  void InvalidateCurrentPass(bool){}
  void execute(ArgumentEncodingContext &target){for(auto &f:commands)f(target);commands.clear();}
  void flush(){execute(encoder);}
@SET@
@GET@
@RESET@
@RESET_API@
  void restoreVertexState(){
@RESTORE@
  }
};
}
'''

VERTEX_DRIVER = r'''
static uint64_t digest=14695981039346656037ull;
static unsigned draws=0;
static void draw(dxmt::Context &c){
  c.flush();
  for(unsigned slot=0;slot<16;slot++){
    auto &v=c.encoder.slots[slot];
    auto &set=c.state_.InputAssembler.VertexBuffers;
    if(set.test_bound(slot)){
      auto &entry=set[slot];
      assert(v.buffer==entry.Buffer->buffer());
      assert(v.offset==entry.Offset&&v.stride==entry.Stride);
    }else assert(!v.buffer);
    for(auto value:{v.buffer?v.buffer->identity:0,v.buffer?v.buffer->generation:0,v.offset,v.stride})
      digest=(digest^value)*1099511628211ull;
  }
  c.state_.InputAssembler.VertexBuffers.clear_dirty();++draws;
}
int main(){
  D3D11ResourceCommon a(11),b(22);
  {
    dxmt::Context c,deferred;
    ID3D11Buffer *bindings[]={&a,&b};UINT strides[]={12,24},offsets[]={0,4};
    c.SetVertexBuffers(3,2,bindings,strides,offsets);assert(c.recorded==2);
    assert(a.refs==1&&b.refs==1);draw(c);
    auto before=c.recorded;
    for(unsigned n=0;n<10000;n++)c.SetVertexBuffers(3,2,bindings,strides,offsets);
    assert(!c.state_.InputAssembler.VertexBuffers.any_dirty());
    const auto duplicate_commands=c.recorded-before;
    draw(c);assert(a.refs==1&&b.refs==1);
    strides[0]=16;c.SetVertexBuffers(3,2,bindings,strides,offsets);
    assert(c.state_.InputAssembler.VertexBuffers.test_dirty(3));draw(c);
    offsets[1]=8;c.SetVertexBuffers(3,2,bindings,strides,offsets);
    assert(c.state_.InputAssembler.VertexBuffers.test_dirty(4));draw(c);
    strides[0]=32;offsets[0]=64;c.SetVertexBuffers(3,1,bindings,strides,offsets);draw(c);
    c.SetVertexBuffers(3,2,bindings,nullptr,nullptr);draw(c);
    // The encoder keeps the same Buffer object; DISCARD changes its backing
    // generation, not the IA metadata and not a hidden setter side effect.
    a.native->generation=2;c.SetVertexBuffers(3,2,bindings,strides,offsets);draw(c);
    ID3D11Buffer *empty[]={nullptr};
    c.SetVertexBuffers(3,1,empty,nullptr,nullptr);draw(c);assert(a.refs==0);
    auto unbound=c.recorded;c.SetVertexBuffers(3,1,empty,nullptr,nullptr);assert(c.recorded==unbound);
    c.SetVertexBuffers(3,1,bindings,strides,offsets);draw(c);assert(a.refs==1);
    // Actual encoder reset and full vertex restore used around deferred lists.
    c.ResetEncodingContextState();c.flush();assert(!c.encoder.slots[3].buffer);
    c.restoreVertexState();c.SetVertexBuffers(3,2,bindings,strides,offsets);draw(c);
    UINT other_stride[]={48},other_offset[]={128};
    deferred.SetVertexBuffers(3,1,bindings,other_stride,other_offset);
    c.ResetEncodingContextState();c.flush();deferred.execute(c.encoder);
    c.restoreVertexState();c.SetVertexBuffers(3,2,bindings,strides,offsets);draw(c);
    // RestoreContextState=false: the API binding set is cleared, so the next
    // bind must still record a complete Buffer binding, even with old metadata.
    c.ResetEncodingContextState();c.flush();c.ResetD3D11ContextState();
    c.SetVertexBuffers(3,2,bindings,strides,offsets);draw(c);
    ID3D11Buffer *out[2]{};UINT got_stride[2]{},got_offset[2]{};
    c.GetVertexBuffers(3,2,out,got_stride,got_offset);
    assert(out[0]==&a&&out[1]==&b&&got_stride[0]==32&&got_offset[0]==64);
    out[0]->Release();out[1]->Release();
    auto zero=c.recorded;c.SetVertexBuffers(0,0,nullptr,nullptr,nullptr);assert(zero==c.recorded);
    std::printf("vertex trace=%llu draws=%u duplicate-commands=%zu callbacks=%u\n",
                (unsigned long long)digest,draws,duplicate_commands,c.encoder.callbacks);
  }
  assert(a.refs==0&&b.refs==0);
}
'''

HUD_PREFIX = r'''
#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <new>
#include <string>
#include <utility>
#include <vector>
#include "dxmt_statistics.hpp"
static bool measure_allocations=false;
static size_t allocations=0,allocation_bytes=0,format_calls=0;
void *operator new(size_t bytes){
  if(measure_allocations){++allocations;allocation_bytes+=bytes;}
  if(void *p=std::malloc(bytes))return p;throw std::bad_alloc();
}
void operator delete(void *p)noexcept{std::free(p);}
void operator delete(void *p,size_t)noexcept{std::free(p);}
namespace format_probe {
template<class... Args> std::string format(std::format_string<Args...> f,Args&&...args){
  ++format_calls;return std::format(f,std::forward<Args>(args)...);
}
}
static std::vector<std::string> logged,hud_lines;
static unsigned begins=0,ends=0;
struct Logger{static void info(const std::string &s){logged.push_back(s);}};
struct Hud {
  void begin(){
#ifdef DXMT_DEBUG
    ++begins;
#endif
  }
  void printLine(const std::string &s){printLine(s.c_str());}
  void printLine(const char *s){
#ifdef DXMT_DEBUG
    hud_lines.emplace_back(s);
#else
    (void)s;
#endif
  }
  void end(){
#ifdef DXMT_DEBUG
    ++ends;
#endif
  }
};
namespace dxmt {
class Swapchain {
public:
  Hud hud;
@UPDATE@
};
}
'''

HUD_DRIVER = r'''
int main(){
  using namespace dxmt;
  FrameStatisticsContainer stats;
  for(unsigned frame=0;frame<kFrameStatisticsCount;frame++){
    auto &s=stats.at(frame);s.reset();
    s.compatibility_flags.set(FeatureCompatibility::UnsupportedGeometryDraw);
    s.command_buffer_count=2;s.render_pass_count=15;s.render_pass_optimized=1;
    s.clear_pass_count=3;s.clear_pass_optimized=1;s.latency=3;
    s.encode_prepare_interval=std::chrono::microseconds(1850);
    s.encode_flush_interval=std::chrono::microseconds(950);
    s.drawable_blocking_interval=std::chrono::microseconds(50);
    s.last_scaler_info.input_width=800;s.last_scaler_info.input_height=450;
    s.last_scaler_info.output_width=1600;s.last_scaler_info.output_height=900;
    s.last_scaler_info.auto_exposure=true;s.last_scaler_info.motion_vector_highres=true;
  }
  stats.compute(0);
  Swapchain chain;
  logged.reserve(8);hud_lines.reserve(4000);
  // Exercise all format/capability branches and preserve actual diagnostic text.
  for(auto type:{ScalerType::None,ScalerType::Spatial,ScalerType::Temporal}){
    stats.at(1).last_scaler_info.type=type;
    for(unsigned n=0;n<128;n++)chain.UpdateStatistics(stats,2);
  }
  assert(logged.size()==6);
#ifdef DXMT_DEBUG
  assert(begins==384&&ends==384&&hud_lines.size()==2432);
#else
  assert(!begins&&!ends&&hud_lines.empty());
#endif
  uint64_t digest=14695981039346656037ull;
  for(auto &s:logged)for(unsigned char ch:s)digest=(digest^ch)*1099511628211ull;
  for(auto &s:hud_lines)for(unsigned char ch:s)digest=(digest^ch)*1099511628211ull;
  std::printf("hud trace=%llu lines=%zu frames=%u\n",(unsigned long long)digest,hud_lines.size(),begins);
  // Keep reporting frontier clear: this next63-frame span contains no periodic
  // logger call. Only useless release HUD formatting can allocate here.
  logged.clear();hud_lines.clear();format_calls=allocations=allocation_bytes=0;
  stats.at(1).last_scaler_info.type=ScalerType::Temporal;
  measure_allocations=true;
  for(unsigned n=0;n<63;n++)chain.UpdateStatistics(stats,2);
  measure_allocations=false;
  assert(logged.empty());
  std::printf("hud benchmark frames=63 format-calls=%zu allocations=%zu bytes=%zu\n",format_calls,allocations,allocation_bytes);
}
'''


with tempfile.TemporaryDirectory(prefix='madeira-command-state-') as directory:
    directory = Path(directory)
    originals = {name: (ROOT / 'dxmt' / name).read_text() for name in stage.FILES}
    patched = {name: stage.stage_file(name, source) for name, source in originals.items()}
    state_source = (ROOT / 'dxmt/src/d3d11/d3d11_context_state.hpp').read_text()
    entry = state_source[state_source.index('struct VERTEX_BUFFER_B {'):state_source.index('struct D3D11InputAssemblerStageState {')]
    traces = {}
    hud_results = {}
    for new, texts in ((False, originals), (True, patched)):
        impl = texts[stage.FILES[0]]
        restore = function(impl, '  void\n  RestoreEncodingContextState()')
        restore = restore[restore.index('    for (const auto &[slot, element]'):restore.index('\n    if (state_.InputAssembler.IndexBuffer)')]
        source = VERTEX_PREFIX.replace('@ENTRY@', entry)
        for key, signature in (('SET', '  void\n  SetVertexBuffers('), ('GET', '  void\n  GetVertexBuffers('),
                               ('RESET', '  void ResetEncodingContextState('), ('RESET_API', '  void ResetD3D11ContextState(')):
            source = source.replace('@' + key + '@', function(impl, signature))
        source = source.replace('@RESTORE@', restore) + VERTEX_DRIVER
        cpp = directory / ('vertex-' + str(new) + '.cpp')
        cpp.write_text(source)
        exe = cpp.with_suffix('')
        includes = ['-I', str(ROOT / 'dxmt/src/dxmt'), '-I', str(ROOT / 'dxmt/src/util')]
        subprocess.run([*CXX, '-std=c++20', '-O2', '-g', '-pthread', *includes, str(cpp), '-o', str(exe)], check=True)
        traces[new] = subprocess.check_output([str(exe)], text=True)
        update = function(texts[stage.FILES[1]], '  void UpdateStatistics(')
        update = update.replace('std::format(', 'format_probe::format(')
        for debug in (False, True):
            cpp = directory / ('hud-' + str(new) + '-' + str(debug) + '.cpp')
            cpp.write_text(HUD_PREFIX.replace('@UPDATE@', update) + HUD_DRIVER)
            exe = cpp.with_suffix('')
            subprocess.run([*CXX, '-std=c++20', '-O2', '-g', '-pthread', *(['-DDXMT_DEBUG=1'] if debug else []),
                            *includes, str(cpp), '-o', str(exe)], check=True)
            hud_results[new, debug] = subprocess.check_output([str(exe)], text=True)
    before, after = (re.search(r'vertex trace=(\d+) draws=(\d+) duplicate-commands=(\d+)', traces[new]).groups() for new in (False, True))
    assert before[:2] == after[:2] and int(before[2]) == 20000 and int(after[2]) == 0, (traces, before, after)
    print('PASS actual SetVertexBuffers + BindingSet: identical draw states/dirty bits, getters, rename visibility, unbind/rebind, encoder reset/deferred restore and resource references')
    print('PASS bounded repeated-binding workload: 20,000 redundant native encoder commands before, zero afterward; no game-frequency/FPS claim')
    for debug in (False, True):
        assert hud_results[False, debug].splitlines()[0] == hud_results[True, debug].splitlines()[0], hud_results
    assert hud_results[False, True] == hud_results[True, True], hud_results
    old_release = re.search(r'format-calls=(\d+) allocations=(\d+) bytes=(\d+)', hud_results[False, False])
    new_release = re.search(r'format-calls=(\d+) allocations=(\d+) bytes=(\d+)', hud_results[True, False])
    assert int(old_release[1]) == 63 * 6 and int(old_release[2]) > 0
    assert tuple(map(int, new_release.groups())) == (0, 0, 0), hud_results
    print('PASS actual UpdateStatistics + real std::format: release HUD work removed; debug HUD text and existing64-frame FRAME_STATS output byte-identical')
    print('BEFORE ' + hud_results[False, False].splitlines()[1])
    print('AFTER ' + hud_results[True, False].splitlines()[1])
    # Assert the existing release HUD implementation really is a no-op. This
    # staging must not silently disable an enabled production HUD implementation.
    hud_impl = (ROOT / 'dxmt/src/dxmt/dxmt_hud_state.cpp').read_text()
    for name in ('begin', 'printLine', 'end'):
        body = function(hud_impl, 'HUDState::' + name + '(')
        assert '#ifndef DXMT_DEBUG\n  return;\n#endif' in body
    assert "value : false" in (ROOT / 'dxmt/meson.options').read_text().split("option('dxmt_debug'", 1)[1].split('\n', 1)[0]
    output = directory / 'staged'
    stage.stage(ROOT / 'dxmt', output)
    for name, source in originals.items():
        assert (ROOT / 'dxmt' / name).read_text() == source
        try:
            stage.stage_file(name, patched[name])
        except ValueError:
            pass
        else:
            raise AssertionError('duplicate staging accepted')
    print('PASS pinned vendor source remains unchanged; changed/duplicate staging contracts fail closed')
