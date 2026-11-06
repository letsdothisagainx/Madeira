#!/usr/bin/env python3
"""Replay the exact shipped DXMT peak-CAS loop through production recovery.

The existing adjacent discard/add helpers are the failing control. New recovery
must validate the entire captured conditional/retry sequence and publication
tokens; real shared RX/RW file aliases remain intact. No guest code is changed.
"""
from pathlib import Path
import os
import platform
import runpy
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
base = runpy.run_path(str(root / "tests/host/check-jit-alias-exclusive.py"), run_name="conditional_fixture_base")
source = (root / "build/ntdll-unix/signal_arm64_ios.c").read_text()
name = "ios_mach_emulate_exclusive_conditional_loop"
present = ("static int " + name + "(") in source or ("static int " + name + " (") in source
prefix = base["prefix"]
# Earlier adjacent helpers query their own short windows before rejecting the
# conditional shape. Inject retirement during THIS helper's full-span query,
# after its initial tokens, instead of before it begins a valid new snapshot.
mutation = "if (mutate_generation) change_generation();"
assert prefix.count(mutation) == 1
prefix = prefix.replace(mutation,
    "if (mutate_generation && *address == (uintptr_t)rx + 0x100) change_generation();")
header = prefix + base["helpers"] + base["primitive"]
header += "\n#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))\n"
header += "\nstatic unsigned ios_mach_alias_exclusive_store(uintptr_t p,uint64_t v,unsigned s) {return exclusive_primitive_actual(p,v,s);}\n"
for helper in ("ios_mach_emulate_exclusive_loop", "ios_mach_emulate_exclusive_add_loop"):
    header += base["function"](source, helper)
header += "\n#define HAVE_CONDITIONAL_RECOVERY " + str(int(present)) + "\n"
if present:
    header += base["function"](source, name)
header += base["function"](source, "ios_mach_emulate_exclusive_compare_loop")
header += r'''
struct state { uint64_t __x[29],__fp,__lr,__sp,__pc; uint32_t __cpsr; };
static pthread_mutex_t route_lock=PTHREAD_MUTEX_INITIALIZER;
#define IOS_STORE_SRC(r) ((r)==31?0ull:state.__x[r])
static int old_route(uint32_t insn,uintptr_t rw_addr,uintptr_t fault_addr,struct state *input)
{
    struct state state=*input;uint64_t fault_pc=state.__pc;int emulated=0;
    if(0){}
''' + base["old_case"] + r'''
    *input=state;return emulated;
}
/* Adapt only the standalone fixture state used by the extracted PC advance. */
#ifdef __darwin_arm_thread_state64_set_pc_fptr
#undef __darwin_arm_thread_state64_set_pc_fptr
#endif
#define __darwin_arm_thread_state64_set_pc_fptr(st,value) ((st).__pc=(uintptr_t)(value))
static int route(uint32_t insn,uintptr_t fault_addr,struct state *input,void *owner)
{
    assert(!pthread_mutex_lock(&route_lock));
    struct state state=*input;
    uint64_t fault_pc=state.__pc;int handled=0,emulated=0,in_jit=1;
    uintptr_t thread_teb=(uintptr_t)&fixture_teb;
    fixture_teb.Peb=owner?owner:(void *)0x1111;
''' + base["route_case"] + r'''
    if(emulated){
''' + base["pc_advance"] + r'''
    }
    *input=state;assert(handled==emulated);
    assert(!pthread_mutex_unlock(&route_lock));return handled;
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix="madeira-exclusive-conditional-") as folder:
        directory = Path(folder)
        (directory / "conditional-production.h").write_text(header)
        binary = directory / "conditional"
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-pthread",
                        "-I" + str(directory), str(root / "tests/host/jit_alias_exclusive_conditional_test.c"),
                        "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
    print("PASS production conditional-exclusive recovery on " + platform.machine())


if __name__ == "__main__":
    main()
