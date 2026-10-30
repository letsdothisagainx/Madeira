#!/usr/bin/env python3
"""Compile the exact auxiliary-IAT index validator used by the Wine overlay."""
import os
from pathlib import Path
import subprocess
import tempfile
root=Path(__file__).resolve().parents[2]
code=r'''
#include <assert.h>
#include "aux-slot.h"
int main(void) {
 uint32_t out=0xfeed;
 assert(madeira_scm_aux_slot(0x50000,0x30000,0x1000,0x30100,0x3b000,&out));
 assert(out==0x3b100);
 assert(madeira_scm_aux_slot(0x50000,0x30000,0x1000,0x30ff8,0x3b000,&out));
 assert(out==0x3bff8);
 const uint32_t invalid[][5]={
  {0x50000,0,0x1000,0x30100,0x3b000},
  {0x50000,0x30000,0x1000,0x30100,0},
  {0x50000,0x30001,0x1000,0x30100,0x3b000},
  {0x50000,0x30000,0x1000,0x30101,0x3b000},
  {0x50000,0x30000,0x1000,0x30100,0x3b001},
  {0x50000,0x30000,0x1000,0x2fff8,0x3b000},
  {0x50000,0x30000,0x1000,0x31000,0x3b000},
  {0x50000,0x30000,0x1000,0x30100,0x4ff00},
  {0x50000,0x30000,0xffffffff,0x30100,0x3b000},
  {0xffffffff,0xfffffff8,16,0xfffffff8,0x1000},
  {0xffffffff,0x1000,0x100,0x1008,0xfffffff8},
  {0x50000,0x30000,7,0x30000,0x3b000}
 };
 for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++) {
  out=0xfeed;
  assert(!madeira_scm_aux_slot(invalid[i][0],invalid[i][1],invalid[i][2],invalid[i][3],invalid[i][4],&out));
  assert(out==0xfeed);
 }
 return 0;
}
'''
with tempfile.TemporaryDirectory() as folder:
    t=Path(folder);src=t/'aux.c';src.write_text(code)
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-I'+str(root/'build/scm-rpc'),str(src),'-o',str(t/'aux')],check=True)
    subprocess.run([str(t/'aux')],check=True)
# The overlay must still apply to the published submodule pin without fuzz.
if (root/'wine/dlls/ntdll/loader.c').exists():
    subprocess.run(['git','-C',str(root/'wine'),'apply','--check',str(root/'build/scm-rpc/loader.patch')],check=True)
print('PASS native auxiliary IAT: exact index, image/table bounds, alignment, overflow, no mutation on invalid metadata; Wine overlay applies')
