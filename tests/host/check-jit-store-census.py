#!/usr/bin/env python3
"""Check production observation masks, including the actual native FEX sites."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
code = r'''
#include <assert.h>
#include "jit_store_census.h"
int main(void) {
    assert(madeira_jit_store_family(0xf82a0129) == MADEIRA_STORE_LSE);
    assert(madeira_jit_store_family(0xf8210108) == MADEIRA_STORE_LSE);
    assert(madeira_jit_store_family(0xc8e67c20) == MADEIRA_STORE_LSE);
    assert(madeira_jit_store_family(0xc80b7d49) == MADEIRA_STORE_EXCLUSIVE);
    assert(madeira_jit_store_family(0xc8097dc8) == MADEIRA_STORE_EXCLUSIVE);
    assert(madeira_jit_store_family(0x8809fc08) == MADEIRA_STORE_EXCLUSIVE);
    assert(madeira_jit_store_family(0xb8e98108) == MADEIRA_STORE_SWAP);
    assert(madeira_jit_store_family(0xc89ffcc1) == MADEIRA_STORE_RELEASE);
    assert(madeira_jit_store_family(0x19000128) == MADEIRA_STORE_RELEASE);
    assert(madeira_jit_store_family(0xf8010d1f) == MADEIRA_STORE_GPR);
    assert(madeira_jit_store_family(0xb9000128) == MADEIRA_STORE_GPR);
    assert(madeira_jit_store_family(0x39000128) == MADEIRA_STORE_GPR);
    assert(madeira_jit_store_family(0xa9007d1f) == MADEIRA_STORE_SIMD_PAIR);
    assert(madeira_jit_store_family(0x3d800120) == MADEIRA_STORE_SIMD_PAIR);
    assert(madeira_jit_store_family(0xd503201f) == MADEIRA_STORE_OTHER);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-store-census-') as tmp:
    source = Path(tmp) / 'census.c'
    source.write_text(code)
    binary = Path(tmp) / 'census'
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-I', str(root / 'build/ntdll-unix'), str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('PASS actual store-family census masks: captured atomics, releases, scalar/SIMD stores')
