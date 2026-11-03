#!/usr/bin/env python3
from pathlib import Path
import hashlib,json,os,re,subprocess
here=Path(__file__).resolve().parent
sources=[here/'stream_codec.cpp',here.parent/'wire-codec/wire_codec.cpp',here/'test_stream_codec.cpp']
exe=here/'test_stream_codec'
subprocess.run(['g++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror','-pthread',
    '-fsanitize=address,undefined','-fno-omit-frame-pointer',*[str(s) for s in sources],'-o',str(exe)],check=True)
result=subprocess.run([str(exe)],check=True,text=True,capture_output=True,
    env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:halt_on_error=1'))
print(result.stdout,end='')
checks=int(re.search(r'(\d+) checks passed',result.stdout)[1])
zig=os.environ.get('MADEIRA_ZIG','/workspace/madeira-tools/bin/python-zig')
obj=here/'stream_codec.obj'
subprocess.run([zig,'c++','-target','x86_64-windows-msvc','-std=c++20','-O2',
    '-fno-exceptions','-fno-rtti','-fno-builtin','-Wall','-Wextra','-Werror',
    '-Wno-unused-command-line-argument','-c',str(sources[0]),'-o',str(obj)],check=True,
    env=dict(os.environ,PYTHONPATH='/workspace/madeira-tools'))
report={'scope':'incremental stream codec and Microsoft ABI callback fixtures; no Steam activation',
    'asan_ubsan':'passed','threaded_partial_zero_and_read_ahead':'passed',
    'checks':checks,'windows_compile_target':'x86_64-windows-msvc',
    'source_sha256':{s.name:hashlib.sha256(s.read_bytes()).hexdigest() for s in sources},
    'windows_object_sha256':hashlib.sha256(obj.read_bytes()).hexdigest(),
    'large_ring_test':{'payload_bytes':26*1024*1024,'ring_capacity':25*1024*1024,'genuine_chunk':1024*1024},
    'workspace_owner':'caller','dynamic_allocations_in_codec':0,'io_budget_tested':64}
(here/'results.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
