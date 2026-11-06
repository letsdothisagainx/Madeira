#!/usr/bin/env python3
"""Exercise production direct-BL proof against the captured FEX counter."""
from pathlib import Path
import os
import subprocess
import tempfile

root=Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='madeira-direct-call-') as folder:
    folder=Path(folder)
    header=(root/'build/ntdll-unix/native_data_alias.h').read_text()
    predicate='base==8&&!madeira_nd_direct_callee_kills_x8(code,count,at)'
    assert header.count(predicate)==1
    # Restore the exact previous X8-call rejection inside the otherwise same
    # production planner, rather than implementing a separate decoder/model.
    (folder/'native_data_alias.h').write_text(header.replace(predicate,'base==8',1))
    previous=folder/'previous-direct-call'
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror',
                    '-DTEST_PREVIOUS_REJECTION','-I'+str(folder),
                    '-I'+str(root/'build/ntdll-unix'),
                    str(root/'tests/host/native_data_direct_call_test.c'),'-o',str(previous)],check=True)
    subprocess.run([str(previous)],check=True)
    output=Path(folder)/'direct-call'
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all',
                    '-I'+str(root/'build/ntdll-unix'),
                    str(root/'tests/host/native_data_direct_call_test.c'),'-o',str(output)],check=True)
    subprocess.run([str(output)],check=True)
