#!/usr/bin/env python3
"""Ordinary fence metadata; actual staged handoff helper, no device/fault test."""
from pathlib import Path
import importlib.util,subprocess,tempfile,os
r=Path(__file__).resolve().parents[2]
def load(name):
 p=r/('tools/build/stage-dxmt-'+name+'.py');s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def block(text,signature):
 a=text.index(signature);b=text.index('{',a);d=1;e=b+1
 while d:d+=(text[e]=='{')-(text[e]=='}');e+=1
 return text[a:e]+';'
a=load('texture-admission');w=load('upload-window')
base=a.stage_file(a.FILES[0],(r/'dxmt'/a.FILES[0]).read_text())
new=w.stage_file(w.FILES[2],base)
old=block(base,'class TextureInitializationCredit {');corrected=block(new,'class TextureInitializationCredit {')
assert 'request.gpu(initializer.event().handle,gpu_credit.observedFence())' in new
assert 'request.gpu(initializer.event().handle,initializer.initializationFence())' not in new
prefix='''#include <cstdint>
#include <cassert>
#include <cstdio>
struct ResourceGrowthPermit{unsigned begins=0,finishes=0;uint64_t target=0;
 bool beginGpuInitialization(uint64_t e){assert(e==123);++begins;return true;}
 bool finishGpuInitialization(uint64_t f){++finishes;target=f;return true;}};
struct ResourceInitializer {unsigned calls=0;struct Event{uint64_t handle=123;};Event event(){return {};}
 uint64_t initializationFence(){++calls;return 77;}};
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d)
 for label,helper,body in [('baseline',old,'auto observed=i.initializationFence();assert(c.finish());assert(observed==p.target);assert(i.calls==2);'),('corrected',corrected,'assert(c.observedFence()==0);assert(c.finish());assert(c.observedFence()==p.target);assert(i.calls==1);')]:
  src=p/(label+'.cpp');out=p/label
  src.write_text(prefix+helper+'\nint main(){ResourceGrowthPermit p;ResourceInitializer i;{TextureInitializationCredit c(p,i);assert(c.valid());'+body+'}assert(p.begins==1&&p.finishes==1&&p.target==77);printf("'+label+': actual fence queries=%u, handoffs=%u, target=%llu\\n",i.calls,p.finishes,(unsigned long long)p.target);}')
  subprocess.run([os.getenv('CXX','c++'),'-std=c++17','-O2',str(src),'-o',str(out)],check=True);subprocess.run([str(out)],check=True)
print('PASS same real handoff frontier; observer removes redundant initializer flush/reclamation query')
