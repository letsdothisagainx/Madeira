#!/usr/bin/env python3
"""Run existing production BC-profile policy and resource/view mappings.

Native memory-query results are fixture inputs. Actual policy, eligibility,
physical descriptor, initial-upload indexing and SRV translation are extracted
from pinned source; tests do not claim pixel execution or transparent full LOD.
"""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
factory = (ROOT / 'dxmt/src/d3d11/d3d11_texture_device.cpp').read_text()


def block(text, marker):
    start = text.index(marker)
    brace = text.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


format_check = block(factory, 'static inline bool IsBCFormatForClamp(')
eligible = factory[factory.index('    const bool eligible ='):factory.index('    if (eligible && cached_clamp)')]
# Keep the actual factory's physical descriptor assignments and upload index.
physical = block(factory, '\n    if (mip_bias) {')
upload = factory[factory.index('        auto &data = pInitialData['):factory.index('        initializer.initWithData(', factory.index('        auto &data = pInitialData['))]
srv_start = factory.index('    D3D11_SHADER_RESOURCE_VIEW_DESC1 physDesc = finalDesc;')
srv_end = factory.index('    if (FAILED(InitializeAndNormalizeViewDescriptor(', srv_start)
srv = factory[srv_start:srv_end]
stream = block(factory, '  uint32_t TranslateSubresource(')
auto_start = factory.index('static std::atomic<uint64_t> g_auto_candidates')
auto_end = factory.index('template <typename tag>', auto_start)
auto = factory[auto_start:auto_end]

PRELUDE = r'''
#include <algorithm>
#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <vector>
#include "d3d11_mip_clamp_policy.hpp"
#define ERR(...) ((void)0)
using UINT = uint32_t;
enum { D3D11_USAGE_DEFAULT=0, D3D11_USAGE_IMMUTABLE=1, D3D11_USAGE_DYNAMIC=2, D3D11_USAGE_STAGING=3,
 D3D11_BIND_SHADER_RESOURCE=8, D3D11_BIND_RENDER_TARGET=32, D3D11_BIND_UNORDERED_ACCESS=128,
 D3D11_RESOURCE_MISC_TEXTURECUBE=4, D3D11_RESOURCE_MISC_RESOURCE_CLAMP=128 };
struct Desc { uint32_t Format=97, Usage=1, BindFlags=8, CPUAccessFlags=0, MipLevels=11,
 Width=1024, Height=1024, ArraySize=1, MiscFlags=0; struct { uint32_t Count=1; } SampleDesc; };
struct Info { uint32_t width=0,height=0,mipmap_level_count=0; };
struct D3D11_SHADER_RESOURCE_VIEW_DESC1 { union {
 struct { uint32_t MostDetailedMip,MipLevels; } Texture2D;
 struct { uint32_t MostDetailedMip,MipLevels,FirstArraySlice,ArraySize; } Texture2DArray;
 struct { uint32_t MostDetailedMip,MipLevels; } TextureCube;
 struct { uint32_t MostDetailedMip,MipLevels,First2DArrayFace,NumCubes; } TextureCubeArray;
 }; };
namespace dxmt {
struct MipClampAutoConfig { bool enabled=true; uint32_t threshold_mb=768; };
static MipClampAutoConfig config;
static int64_t fixture_headroom=0;
static unsigned queries=0;
static const MipClampAutoConfig &GetMipClampAutoConfig(){return config;}
static int64_t QueryHeadroomMB(int64_t *footprint){++queries;*footprint=5000;return fixture_headroom;}
FORMAT_CHECK
AUTO_POLICY
static uint32_t bias(const Desc &finalDesc,int64_t room=600){
 ELIGIBILITY
 g_auto_candidates=0;g_auto_headroom_mb=mip_clamp::kHeadroomUnknown;fixture_headroom=room;
 if(!eligible||!auto_misc_ok)return 0;
 return MipClampAutoBias(finalDesc.Width,finalDesc.Height,finalDesc.MipLevels);
}
static Desc physical(Desc finalDesc,uint32_t mip_bias){const Desc original=finalDesc;Desc physDesc=finalDesc;Info info;
 PHYSICAL
 assert(finalDesc.Width==original.Width&&finalDesc.Height==original.Height&&finalDesc.MipLevels==original.MipLevels);
 assert(info.width==physDesc.Width&&info.height==physDesc.Height&&info.mipmap_level_count==physDesc.MipLevels);
 return physDesc;
}
static uint32_t initial(const Desc &finalDesc,const std::vector<uint32_t>&input,uint32_t mip_bias,uint32_t mip,uint32_t slice){
 const uint32_t *pInitialData=input.data();struct {uint32_t MipLevel,ArraySlice;}sub{mip,slice};
 UPLOAD
 return data;
}
struct Resource {Desc desc;uint32_t mip_bias_=1;
 STREAM
 D3D11_SHADER_RESOURCE_VIEW_DESC1 view(D3D11_SHADER_RESOURCE_VIEW_DESC1 finalDesc){
 SRV
 assert(physMips==desc.MipLevels-mip_bias_);return physDesc;
 }};
}
using namespace dxmt;
int main(){
 Desc base;assert(bias(base)==1);assert(bias(base,768)==0);assert(bias(base,-2)==0);
 config.enabled=false;assert(bias(base)==0);config.enabled=true;
 config.threshold_mb=0;assert(bias(base)==0);config.threshold_mb=768;
 for(uint32_t f: {70u,71u,72u,73u,74u,75u,76u,77u,78u,79u,80u,81u,82u,83u,84u,94u,95u,96u,97u,98u,99u}){auto d=base;d.Format=f;assert(bias(d)==1);}
 for(uint32_t f:{0u,28u,61u,85u,93u,100u}){auto d=base;d.Format=f;assert(bias(d)==0);}
 auto d=base;d.Width=d.Height=512;assert(bias(d)==0);
 d=base;d.Width=1025;assert(bias(d)==1);d.Width=1027;assert(bias(d)==0);
 d=base;d.MipLevels=1;assert(bias(d)==0);d=base;d.Height=4;assert(bias(d)==0);
 for(uint32_t usage:{2u,3u}){d=base;d.Usage=usage;assert(bias(d)==0);}
 for(uint32_t flags:{0u,32u,128u,40u}){d=base;d.BindFlags=flags;assert(bias(d)==0);}
 for(uint32_t cpu:{0x10000u,0x20000u}){d=base;d.CPUAccessFlags=cpu;assert(bias(d)==0);}
 d=base;d.SampleDesc.Count=2;assert(bias(d)==0);
 for(unsigned bit=0;bit<31;bit++){d=base;d.MiscFlags=1u<<bit;assert(bias(d)==((bit==2||bit==7)?1u:0u));}
 puts("PASS actual factory/profile eligibility: native BC family, pressure, small UI, odd dimensions, shared/exotic/MSAA/CPU/RT exclusions");
 for(uint32_t slices:{1u,3u,6u,12u}){
  d=base;d.ArraySize=slices;d.MiscFlags=slices>=6?4:0;assert(bias(d)==1);
  const Desc p=physical(d,1);assert(p.Width==512&&p.Height==512&&p.MipLevels==10&&p.ArraySize==slices);
  std::vector<uint32_t> input;for(uint32_t s=0;s<slices;s++)for(uint32_t m=0;m<11;m++)input.push_back((s<<16)|m);
  Resource r{d,1};uint32_t physical_index=0;
  for(uint32_t s=0;s<slices;s++)for(uint32_t m=0;m<11;m++){
   const uint32_t index=s*11+m;if(m==0)assert(r.TranslateSubresource(index,11)==~0u);
   else {assert(r.TranslateSubresource(index,11)==physical_index++);assert(initial(d,input,1,m-1,s)==((s<<16)|m));}
  }
  D3D11_SHADER_RESOURCE_VIEW_DESC1 v{};v.TextureCubeArray={3,4,6,2};auto mapped=r.view(v);
  assert(mapped.TextureCubeArray.MostDetailedMip==2&&mapped.TextureCubeArray.MipLevels==4);
  assert(mapped.TextureCubeArray.First2DArrayFace==6&&mapped.TextureCubeArray.NumCubes==2);
  assert(v.TextureCubeArray.MostDetailedMip==3&&v.TextureCubeArray.MipLevels==4);
  v.Texture2D={0,~0u};mapped=r.view(v);assert(mapped.Texture2D.MostDetailedMip==0&&mapped.Texture2D.MipLevels==~0u);
  v.Texture2D={10,1};mapped=r.view(v);assert(mapped.Texture2D.MostDetailedMip==9&&mapped.Texture2D.MipLevels==1);
 }
 d=base;d.Width=1025;d.Height=257;d.MipLevels=6;assert(bias(d)==1);
 const auto odd=physical(d,1);assert(odd.Width==512&&odd.Height==128&&odd.MipLevels==5);
 for(uint32_t m=0;m<odd.MipLevels;m++)assert((odd.Width>>m)==(d.Width>>(m+1))&&(odd.Height>>m)==(d.Height>>(m+1)));
 puts("PASS actual physical descriptor/upload/subresource/SRV formulas for arrays and cube faces; logical descriptors retained");
 puts("LIMIT: shader explicit LOD/GetDimensions use lower-resolution physical storage; no full-resolution or GPU-pixel claim");
}
'''
code=PRELUDE
for key,value in [('FORMAT_CHECK',format_check),('AUTO_POLICY',auto),('ELIGIBILITY',eligible),('PHYSICAL',physical),('UPLOAD',upload),('STREAM',stream),('SRV',srv)]:
    assert code.count('\n '+key+'\n') == 1 or code.count('\n'+key+'\n') == 1, key
    code=code.replace(key,value,1)
with tempfile.TemporaryDirectory(prefix='madeira-mip-profile-') as directory:
    source=Path(directory)/'profile.cpp';output=Path(directory)/'profile';source.write_text(code)
    compiler=shlex.split(os.environ.get('CXX','c++'))
    subprocess.run([*compiler,'-std=c++20','-O2','-pthread','-fsanitize=address,undefined','-fno-omit-frame-pointer',
                    '-I',str(ROOT/'dxmt/src/d3d11'),str(source),'-o',str(output)],check=True)
    subprocess.run([str(output)],check=True,timeout=30,env=dict(os.environ,UBSAN_OPTIONS='halt_on_error=1'))
