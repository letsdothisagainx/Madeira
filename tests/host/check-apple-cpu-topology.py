#!/usr/bin/env python3
"""Exercise actual pinned/staged Apple topology builders and Windows records.

Only sysctl answers and allocator-failure injection are controlled. The fixture
compiles Wine's real relationship builders, CPU-set derivation, affinity getter
and the complete old/new Apple create_logical_proc_info functions using Wine's
real public record types. This is not a CS2 dispatch or device acceptance test.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
script = ROOT / 'tools/build/stage-apple-cpu-topology.py'
spec = importlib.util.spec_from_file_location('apple_topology', script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
vendor = ROOT / 'wine/dlls/ntdll/unix/system.c'
original = vendor.read_text()
staged = module.stage(original)
assert vendor.read_text() == original
assert staged.count('[apple-cpu-topology-v1]') == 1
assert staged.replace(module.apple_function(staged), module.apple_function(original)).replace(
    str(ROOT / 'build/madeira_cfg.h'), '../../../../build/madeira_cfg.h') == original
for changed in (original.replace('lcpu_no = peb->NumberOfProcessors;', 'lcpu_no = 1;', 1), staged):
    try:
        module.stage(changed)
    except ValueError:
        pass
    else:
        raise AssertionError('changed/already-staged topology accepted')


def function(source, signature):
    at = source.index(signature)
    return source[at:source.index('\n}\n', at) + 3]


helpers = original[original.index('static BOOL grow_logical_proc_buf(void)'):original.index('\n#ifdef linux\n', original.index('static BOOL grow_logical_proc_buf(void)'))]
cpuset = function(original, 'static NTSTATUS create_cpuset_info(')
affinity = function((ROOT / 'build/ntdll-unix/virtual_ios.c').read_text(), 'ULONG_PTR get_system_affinity_mask(void)')

fixture = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ntstatus.h"
#include "windef.h"
#include "winternl.h"
#define TRACE(...) ((void)0)
#define FIXME(...) ((void)0)
static PEB process_peb, *peb = &process_peb;
static SYSTEM_LOGICAL_PROCESSOR_INFORMATION *logical_proc_info;
static SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *logical_proc_info_ex;
static unsigned int logical_proc_info_len, logical_proc_info_alloc_len;
static unsigned int logical_proc_info_ex_size, logical_proc_info_ex_alloc_size;
static ULONG_PTR system_cpu_mask;
static unsigned int performance_cores[2], performance_cores_capacity;
static unsigned int host_cores, host_packages, cache_mode, fail_physical;
static unsigned int allocations, fail_at;
static void *test_realloc(void *p, size_t n)
{
    if (++allocations == fail_at) return NULL;
    return realloc(p,n);
}
#define realloc test_realloc
''' + helpers + r'''
#undef realloc
static int sysctlbyname(const char *name, void *out, size_t *length, const void *set, size_t set_length)
{
    unsigned int small = 0;
    LONGLONG large = 0, config[10] = {0};
    (void)set; (void)set_length;
    if (!strcmp(name,"hw.packages")) small = host_packages;
    else if (!strcmp(name,"hw.physicalcpu")) {
        if (fail_physical) return -1;
        small = host_cores;
    }
    else if (!strcmp(name,"machdep.cpu.cache.L2_associativity")) small = 16;
    else if (!strcmp(name,"hw.cachelinesize")) large = 128;
    else if (!strcmp(name,"hw.l1icachesize") || !strcmp(name,"hw.l1dcachesize")) large = 65536;
    else if (!strcmp(name,"hw.l2cachesize")) large = 4194304;
    else if (!strcmp(name,"hw.l3cachesize")) large = 8388608;
    else if (!strcmp(name,"hw.cacheconfig")) {
        if (!cache_mode) return -1;
        if (cache_mode == 1) { config[1] = 1; config[2] = host_cores==1?1:2; config[3] = host_cores; }
        if (cache_mode == 4) { config[1] = -1; config[2] = 4096; config[3] = 4096; }
        size_t bytes = cache_mode == 3 ? sizeof(config[0]) : sizeof(config);
        assert(*length >= bytes); memcpy(out,config,bytes); *length = bytes; return 0;
    }
    else return -1;
    if (large) { assert(*length >= sizeof(large)); memcpy(out,&large,sizeof(large)); *length=sizeof(large); }
    else { assert(*length >= sizeof(small)); memcpy(out,&small,sizeof(small)); *length=sizeof(small); }
    return 0;
}
''' + module.apple_function(original).replace('create_logical_proc_info(void)', 'baseline_create_logical_proc_info(void)') + '\n' + module.apple_function(staged) + '\n' + cpuset + '\n' + affinity + r'''
static void reset(unsigned int logical, unsigned int physical, unsigned int packages, unsigned mode)
{
    free(logical_proc_info); free(logical_proc_info_ex);
    logical_proc_info=NULL; logical_proc_info_ex=NULL;
    logical_proc_info_len=logical_proc_info_alloc_len=0;
    logical_proc_info_ex_size=logical_proc_info_ex_alloc_size=0;
    system_cpu_mask=0; allocations=fail_at=0; fail_physical=0;
    peb->NumberOfProcessors=logical; host_cores=physical; host_packages=packages; cache_mode=mode;
}
static ULONG_PTR expected_mask(void)
{
    ULONG_PTR mask=0;
    for(unsigned int i=0;i<peb->NumberOfProcessors;i++) mask|=(ULONG_PTR)1<<i;
    return mask;
}
struct normalized_record {
    ULONG_PTR mask;
    unsigned int relation, level, type, size, line, associativity, flags;
};
static int compare_record(const void *a,const void *b) { return memcmp(a,b,sizeof(struct normalized_record)); }
static unsigned int normalized_records(struct normalized_record *records)
{
    for(unsigned int i=0;i<logical_proc_info_len;i++) {
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION *p=logical_proc_info+i;
        struct normalized_record *r=records+i;
        memset(r,0,sizeof(*r)); r->mask=p->ProcessorMask; r->relation=p->Relationship;
        if(p->Relationship==RelationCache) {
            r->level=p->Cache.Level; r->type=p->Cache.Type; r->size=p->Cache.Size;
            r->line=p->Cache.LineSize; r->associativity=p->Cache.Associativity;
        } else if(p->Relationship==RelationProcessorCore) r->flags=p->ProcessorCore.Flags;
    }
    qsort(records,logical_proc_info_len,sizeof(*records),compare_record);
    return logical_proc_info_len;
}
static void validate(void)
{
    ULONG_PTR expected=expected_mask(), cores=0, packages=0, numa=0;
    ULONG_PTR caches[5][4]={{0}};
    unsigned int core_count=0, package_count=0, numa_count=0, ex_count=0, groups=0;
    BYTE cpu_core[64]={0}, cpu_cache[64]={0};
    for(unsigned int i=0;i<logical_proc_info_len;i++) {
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION *p=logical_proc_info+i;
        ULONG_PTR mask=p->ProcessorMask;
        assert(mask && !(mask & ~expected));
        if(p->Relationship==RelationProcessorCore) {
            assert(!(cores&mask)); cores|=mask;
            /* Preserve the pinned helper's existing legacy union behavior;
             * Ex exposes the SMT flag and is checked independently below. */
            assert(p->ProcessorCore.Flags==0);
            for(unsigned int j=0;j<peb->NumberOfProcessors;j++) if(mask&((ULONG_PTR)1<<j)) cpu_core[j]=core_count;
            core_count++;
        } else if(p->Relationship==RelationProcessorPackage) {
            assert(!(packages&mask)); packages|=mask; package_count++;
        } else if(p->Relationship==RelationNumaNode) {
            assert(p->NumaNode.NodeNumber==0); numa|=mask; numa_count++;
        } else if(p->Relationship==RelationCache) {
            CACHE_DESCRIPTOR *c=&p->Cache;
            assert(c->Level>=1 && c->Level<=3 && c->Type<=CacheTrace);
            assert(c->LineSize==128 && c->Associativity==(c->Level==1?8:c->Level==2?16:12));
            assert(c->Size==(c->Level==1?65536:c->Level==2?4194304:8388608));
            assert(!(caches[c->Level][c->Type]&mask)); caches[c->Level][c->Type]|=mask;
        } else assert(0);
    }
    assert(cores==expected && packages==expected && numa==expected && numa_count==1);
    unsigned int expected_cores=host_cores?min(host_cores,peb->NumberOfProcessors):peb->NumberOfProcessors;
    unsigned int expected_packages=host_packages?min(host_packages,expected_cores):1;
    assert(core_count==expected_cores && package_count==expected_packages);
    assert(caches[1][CacheInstruction]==expected && caches[1][CacheData]==expected);
    assert(caches[2][CacheUnified]==expected && caches[3][CacheUnified]==expected);
    unsigned int cache_index=0;
    for(unsigned int at=0;at<logical_proc_info_ex_size;) {
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *p=(void*)((char*)logical_proc_info_ex+at);
        assert(p->Size>=8 && p->Size<=logical_proc_info_ex_size-at);
        if(p->Relationship==RelationGroup) {
            assert(p->Group.MaximumGroupCount==1 && p->Group.ActiveGroupCount==1);
            assert(p->Group.GroupInfo[0].ActiveProcessorCount==peb->NumberOfProcessors);
            assert(p->Group.GroupInfo[0].MaximumProcessorCount==peb->NumberOfProcessors);
            assert(p->Group.GroupInfo[0].ActiveProcessorMask==expected); groups++;
        } else {
            ULONG_PTR mask;
            if(p->Relationship==RelationProcessorCore || p->Relationship==RelationProcessorPackage) {
                assert(p->Processor.GroupCount==1 && p->Processor.GroupMask[0].Group==0);
                mask=p->Processor.GroupMask[0].Mask;
                if(p->Relationship==RelationProcessorCore)
                    assert(p->Processor.Flags==(count_bits(mask)>1?LTP_PC_SMT:0));
            } else if(p->Relationship==RelationCache) {
                assert(p->Cache.GroupMask.Group==0); mask=p->Cache.GroupMask.Mask;
                if(p->Cache.Level==3) for(unsigned int j=0;j<peb->NumberOfProcessors;j++)
                    if(mask&((ULONG_PTR)1<<j)) cpu_cache[j]=cache_index;
                cache_index++;
            } else {
                assert(p->Relationship==RelationNumaNode && p->NumaNode.GroupMask.Group==0);
                mask=p->NumaNode.GroupMask.Mask;
            }
            assert(mask && !(mask & ~expected)); ex_count++;
        }
        at+=p->Size;
    }
    assert(groups==1 && ex_count==logical_proc_info_len);
    assert(system_cpu_mask==expected && get_system_affinity_mask()==expected);
    SYSTEM_CPU_SET_INFORMATION sets[64]; memset(sets,0xcc,sizeof(sets));
    assert(create_cpuset_info(sets)==STATUS_SUCCESS);
    for(unsigned int j=0;j<peb->NumberOfProcessors;j++) {
        assert(sets[j].Type==CpuSetInformation && sets[j].Size==sizeof(sets[j]));
        assert(sets[j].CpuSet.Id==0x100+j && sets[j].CpuSet.LogicalProcessorIndex==j);
        assert(sets[j].CpuSet.CoreIndex==cpu_core[j] && sets[j].CpuSet.LastLevelCacheIndex==cpu_cache[j]);
        assert(sets[j].CpuSet.NumaNodeIndex==0 && sets[j].CpuSet.Group==0);
    }
}
int main(void)
{
    reset(4,6,1,0);
    assert(baseline_create_logical_proc_info()==STATUS_SUCCESS);
    assert(system_cpu_mask==0 && logical_proc_info_len>0 && get_system_affinity_mask()==0xf);
    printf("BASELINE actual Apple builder: logical=4 physical=6 affinity=0xf topology-group-mask=%#lx core-mask=%#lx\n",
        (unsigned long)system_cpu_mask,(unsigned long)logical_proc_info[1].ProcessorMask);
    reset(4,6,1,0);
    assert(create_logical_proc_info()==STATUS_SUCCESS); validate();
    printf("CORRECTED actual Apple builder: logical=4 physical=6 topology-group-mask=%#lx coherent core/cache/NUMA/CPU-set records\n",
        (unsigned long)system_cpu_mask);
    for(unsigned int n=1;n<=64;n++) {
        if(n>1 && (n&1)) continue;
        struct normalized_record before[512],after[512];
        reset(n,n,1,1); assert(baseline_create_logical_proc_info()==STATUS_SUCCESS);
        unsigned int before_count=normalized_records(before);
        reset(n,n,1,1); assert(create_logical_proc_info()==STATUS_SUCCESS);
        unsigned int after_count=normalized_records(after);
        assert(before_count==after_count && !memcmp(before,after,before_count*sizeof(*before)));
        validate();
    }
    puts("PASS 33 unchanged single-package non-SMT default topologies retain identical relationship records (order-independent)");
    unsigned int cases=0;
    const unsigned visible[]={1,2,3,4,5,6,7,8,12,16,31,32,33,48,63,64};
    const unsigned physical[]={0,1,2,4,6,8,12,24,64};
    const unsigned packages[]={0,1,2,3,8};
    for(unsigned a=0;a<sizeof(visible)/sizeof(*visible);a++)
    for(unsigned b=0;b<sizeof(physical)/sizeof(*physical);b++)
    for(unsigned c=0;c<sizeof(packages)/sizeof(*packages);c++)
    for(unsigned mode=0;mode<5;mode++) {
        reset(visible[a],physical[b],packages[c],mode);
        assert(create_logical_proc_info()==STATUS_SUCCESS); validate(); cases++;
    }
    for(unsigned bad=0;bad<=65;bad+=65) {
        reset(bad,6,1,0);
        assert(create_logical_proc_info()==STATUS_INVALID_PARAMETER);
        assert(!logical_proc_info && !logical_proc_info_ex);
    }
    reset(4,6,1,0); fail_physical=1;
    assert(create_logical_proc_info()==STATUS_SUCCESS);
    host_cores=4; validate();
    reset(6,6,1,1);
    assert(create_logical_proc_info()==STATUS_SUCCESS); unsigned count=allocations;
    for(unsigned i=1;i<=count;i++) {
        reset(6,6,1,1); fail_at=i;
        assert(create_logical_proc_info()==STATUS_NO_MEMORY);
    }
    reset(6,6,1,1);
    assert(create_logical_proc_info()==STATUS_SUCCESS); validate();
    reset(1,1,1,0);
    printf("PASS actual Wine legacy/Ex/CPU-set/affinity records: %u override/default/SMT/nonmultiple/package/cache-answer cases; %u real realloc failure edges\n",cases,count);
    return 0;
}
'''

build = (ROOT / 'build/ntdll-unix/build.sh').read_text()
system_case = build[build.index('        system)'):build.index('        file|socket)')]
assert 'stage-apple-cpu-topology.py' in system_case and '--source "$src" --output "$OBJ_DIR/system_ios.c"' in system_case
assert 'compile_one "$OBJ_DIR/system_ios.c" "system"' in system_case
assert 'signal_arm64|nsi_ip|system)' in build

with tempfile.TemporaryDirectory(prefix='madeira-apple-topology-') as temp:
    path = Path(temp) / 'topology.c'
    path.write_text(fixture)
    for sanitize in (False, True):
        binary = Path(temp) / ('topology-asan' if sanitize else 'topology')
        command = [os.environ.get('CC', 'cc'), '-std=gnu11', '-O1', '-g', '-D__WINESRC__', '-DWINE_UNIX_LIB', '-D_WIN64',
                   '-I', str(ROOT / 'wine/include'), str(path), '-o', str(binary)]
        if sanitize:
            command += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        subprocess.run(command, check=True, capture_output=True, text=True)
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr[-4000:])
        print(result.stdout, end='')
print('PASS pinned Wine is unchanged; altered/double staging fails closed; production system compile cannot reuse a stale object')
