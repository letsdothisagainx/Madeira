#!/usr/bin/env python3
"""Run exact native Ready DATA publisher under host ASan/UBSan."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='madeira-htmlipc-ready-') as folder:
    binary=Path(folder)/'ready'
    # Compile the production source with three test-only preemption points.
    # No production file or publication predicate is changed. The fixture can
    # hold an actual publisher in flight instead of hoping to sample an odd
    # sequence before the scheduler lets all publications finish.
    production=ROOT/'build/htmlipc/runtime/ready_state.cpp'
    source=production.read_text()
    assert 'MadeiraReadyTestCheckpoint' not in source
    checkpoints=[
        '__atomic_store_n(&MadeiraRuntimeReady.magic,MADEIRA_HTMLIPC_READY_MAGIC,__ATOMIC_RELAXED);',
        '__atomic_store_n(&MadeiraRuntimeReady.flags,flags,__ATOMIC_SEQ_CST);',
        '__atomic_store_n(&MadeiraRuntimeReady.sequence,sequence+2,__ATOMIC_RELEASE);',
    ]
    for point,needle in enumerate(checkpoints,1):
        assert source.count(needle)==1, 'publication checkpoint changed: '+needle
        call=f'MadeiraReadyTestCheckpoint({point});'
        source=source.replace(needle,needle+'\n    '+call if point==2 else call+'\n    '+needle)
    instrumented=Path(folder)/'ready_state.cpp'
    instrumented.write_text('extern "C" void MadeiraReadyTestCheckpoint(unsigned);\n'+source)
    flags=['-fno-pie','-no-pie'] if sys.platform.startswith('linux') else []
    compiler=[os.environ.get('CXX','c++'),'-std=c++20','-O1','-g','-Wall','-Wextra','-Werror',
             '-pthread','-fno-omit-frame-pointer','-fsanitize=address,undefined',
             '-fno-sanitize-recover=all',*flags,'-I'+str(ROOT/'build/scm-rpc'),
             '-I'+str(ROOT/'build/htmlipc/runtime')]
    environment=dict(os.environ,ASAN_OPTIONS=('detect_leaks=0:halt_on_error=1' if sys.platform == 'darwin' else 'detect_leaks=1:halt_on_error=1'),UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    ordinary=['valid',*[f'owner{i}' for i in range(7)],'partial','stock','revoke','detach','busy','wrap','writers']
    races=[f'race{point}' for point in (1,2,3) for _ in range(4)]
    for writer,modes in [(production,ordinary),(instrumented,races)]:
        subprocess.run([*compiler,str(writer),str(ROOT/'tests/host/htmlipc/test_ready_state.cpp'),'-o',str(binary)],check=True)
        for mode in modes:subprocess.run([str(binary),mode],check=True,env=environment,timeout=30)
print('PASS HTMLIPC Ready DATA: ABI80, all owner/mode guards, sticky failures/detach, bounded publication and concurrent revoke races')
