#!/usr/bin/env python3
"""Stage coherent Apple CPU relationships for Madeira's visible CPU count.

The pinned Wine source remains unchanged. Its original Apple topology assumes
the reported logical count is divisible by the host's physical count. A
per-launch count override can violate that assumption (4 / 6 == 0), producing
zero core/package/NUMA affinity masks while reporting four active processors.
"""
from pathlib import Path
import argparse
import hashlib

ROOT = Path(__file__).resolve().parents[2]
APPLE_FUNCTION_SHA256 = '6e68011e23d1694c1f3201e81dca6d1120fe9f774389a285467f153d3cf923de'


def apple_function(source):
    start = source.index('static NTSTATUS create_logical_proc_info(void)',
                         source.index('#elif defined(__APPLE__)'))
    end = source.index('\n}\n', start) + 3
    return source[start:end]


def stage(source):
    original = apple_function(source)
    if hashlib.sha256(original.encode()).hexdigest() != APPLE_FUNCTION_SHA256:
        raise ValueError('pinned Apple CPU topology changed; refusing an unreviewed transform')
    corrected = original.replace(
        'unsigned int pkgs_no, cores_no, lcpu_no, lcpu_per_core, cores_per_package, assoc;\n'
        '    unsigned int cache_ctrs[10] = {0};',
        'unsigned int pkgs_no, cores_no, host_cores_no, lcpu_no, lcpu_per_core, assoc;')
    corrected = corrected.replace('LONGLONG cache_size, cache_line_size, cache_sharing[10];',
                                  'LONGLONG cache_size, cache_line_size, cache_sharing[10] = {0};')
    corrected = corrected.replace('    lcpu_no = peb->NumberOfProcessors;',
        '    lcpu_no = peb->NumberOfProcessors;\n'
        '    if (!lcpu_no || lcpu_no > sizeof(ULONG_PTR) * 8) return STATUS_INVALID_PARAMETER;')
    corrected = corrected.replace(
        '    lcpu_per_core = lcpu_no / cores_no;\n'
        '    cores_per_package = cores_no / pkgs_no;',
        '''    /* Report relationships for the visible logical CPUs, not an unfiltered
     * host core count. Each visible core/package must own at least one CPU.
     * Keep the host's SMT grouping when compatible; divide nonmultiples by
     * contiguous index ranges so every visible CPU appears exactly once. */
    host_cores_no = cores_no;
    if (!cores_no) cores_no = lcpu_no;
    cores_no = min(cores_no, lcpu_no);
    if (!pkgs_no) pkgs_no = 1;
    pkgs_no = min(pkgs_no, cores_no);
    lcpu_per_core = (lcpu_no + cores_no - 1) / cores_no;''')
    loop_start = corrected.index('    for(p = 0; p < pkgs_no; ++p)')
    loop_end = corrected.index('    /* OSX doesn\'t support NUMA', loop_start)
    corrected = corrected[:loop_start] + '''    for (p = 0; p < pkgs_no; ++p)
    {
        unsigned int core_end = (p + 1) * cores_no / pkgs_no;
        for (j = p * cores_no / pkgs_no; j < core_end; ++j)
        {
            unsigned int first = j * lcpu_no / cores_no;
            unsigned int end = (j + 1) * lcpu_no / cores_no;
            ULONG_PTR mask = 0;

            for (k = first; k < end; ++k) mask |= (ULONG_PTR)1 << k;
            all_cpus_mask |= mask;
            if (!logical_proc_info_add_by_id(RelationProcessorPackage, p, mask) ||
                !logical_proc_info_add_by_id(RelationProcessorCore, j, mask))
                return STATUS_NO_MEMORY;
        }
    }

    /* Host cache metadata can describe more CPUs than this process exposes.
     * Bound every group to the visible mask and include partial final groups.
     * A failed/short/zero host cache-sharing answer gets a nonzero core-sized
     * fallback; cache capacity, type, level and line size remain unchanged. */
    for (i = 1; i < 5; ++i)
    {
        unsigned int sharing = lcpu_per_core;
        if (!cache[i].Size) continue;
        if (cache_sharing[i] > 0 && cache_sharing[i] <= lcpu_no)
            sharing = cache_sharing[i];
        else if (cache_sharing[i] > lcpu_no)
            sharing = lcpu_no;
        for (j = 0; j < lcpu_no; j += sharing)
        {
            unsigned int end = min(j + sharing, lcpu_no);
            ULONG_PTR mask = 0;
            for (k = j; k < end; ++k) mask |= (ULONG_PTR)1 << k;
            if (!logical_proc_info_add_cache(mask, &cache[i])) return STATUS_NO_MEMORY;
        }
    }

''' + corrected[loop_end:]
    corrected = corrected.replace(
        '    logical_proc_info_add_group( lcpu_no, all_cpus_mask );\n\n    return STATUS_SUCCESS;',
        '''    if (!logical_proc_info_add_group(lcpu_no, all_cpus_mask)) return STATUS_NO_MEMORY;
    fprintf(stderr, "[apple-cpu-topology-v1] logical=%u host-cores=%u visible-cores=%u packages=%u mask=%#lx\\n",
            lcpu_no, host_cores_no, cores_no, pkgs_no, (unsigned long)all_cpus_mask);

    return STATUS_SUCCESS;''')
    if '[apple-cpu-topology-v1]' not in corrected or 'cores_per_package' in corrected:
        raise ValueError('Apple topology transformation incomplete')
    output = source.replace(original, corrected, 1)
    old_include = '#include "../../../../build/madeira_cfg.h"'
    if output.count(old_include) != 1:
        raise ValueError('native CPU configuration include boundary changed')
    return output.replace(old_include, '#include "' + str(ROOT / 'build/madeira_cfg.h') + '"', 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / 'wine/dlls/ntdll/unix/system.c')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    text = stage(args.source.read_text())
    args.output.write_text(text)


if __name__ == '__main__':
    main()
