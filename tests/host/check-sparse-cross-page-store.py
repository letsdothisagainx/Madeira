#!/usr/bin/env python3
"""Run the captured stores on genuinely untouched sparse-file mappings.

Unlike check-cross-page-vector-store.py's cold cases, the destination file has
only been ftruncated: neither pwrite nor a destination memset populates its
pages. The source is a separate anonymous mapping. This is a native host
reproducer, not an iPhone loading or kernel-fault result.
"""
import argparse
import ast
import os
from pathlib import Path
import platform
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--require-arm64', action='store_true')
args = parser.parse_args()
if platform.machine().lower() not in ('arm64', 'aarch64'):
    if args.require_arm64:
        raise SystemExit('FAIL native ARM64 execution is required')
    print('SKIP sparse crossing-store execution: native ARM64 host required')
    raise SystemExit(0)

root = Path(__file__).resolve().parents[2]
fixture = ast.parse((root / 'tests/host/check-cross-page-vector-store.py').read_text())
C = next(ast.literal_eval(n.value) for n in fixture.body
         if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'C'
                                             for t in n.targets))


def replace_once(old, new):
    global C
    assert C.count(old) == 1, f'captured fixture changed: {old[:70]}'
    C = C.replace(old, new)


start = C.index('static unsigned char *mapping(int kind, int *fd_out)')
end = C.index('\nstatic void split_control(', start)
C = C[:start] + r'''
static unsigned char *mapping(int kind, int *fd_out)
{
    unsigned char *p = aligned_mapping(REGION, requested_hint);
    int fd = -1;
    if (!kind)
        assert(mmap(p, REGION, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == p);
    else
    {
        char name[] = "/tmp/madeira-sparse-store-XXXXXX";
        fd = mkstemp(name); assert(fd >= 0); assert(!unlink(name));
        /* No pwrite, fcntl preallocation, memset, prefault or readback here.
         * New sparse holes read zero; the tested vector store is the first
         * user write to either of its destination host pages. */
        assert(!ftruncate(fd, BOUNDARY * 6));
        if (kind == 1)
            assert(mmap(p, REGION, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED, fd, 0) == p);
        else if (kind == 2)
            for (unsigned i = 0; i < 3; ++i)
                assert(mmap(p + i * BOUNDARY, BOUNDARY, PROT_READ | PROT_WRITE,
                            MAP_FIXED | MAP_SHARED, fd, i * BOUNDARY * 2) == p + i * BOUNDARY);
        else if (kind == 3)
        {
            /* A small anonymous header followed by a shared-file interior,
             * as can arise when only the host-aligned commit interior is backed. */
            assert(mmap(p, BOUNDARY, PROT_READ | PROT_WRITE,
                        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == p);
            assert(mmap(p + BOUNDARY, REGION - BOUNDARY, PROT_READ | PROT_WRITE,
                        MAP_FIXED | MAP_SHARED, fd, 0) == p + BOUNDARY);
        }
        else
        {
            /* Reservation first, then separately commit the initial host page
             * and body. No page data is touched while changing protections. */
            assert(kind == 4);
            assert(mmap(p, REGION, PROT_NONE, MAP_FIXED | MAP_SHARED, fd, 0) == p);
            assert(!mprotect(p, BOUNDARY, PROT_READ | PROT_WRITE));
            assert(!mprotect(p + BOUNDARY, REGION - BOUNDARY, PROT_READ | PROT_WRITE));
        }
        struct stat stat;
        assert(!fstat(fd, &stat) && stat.st_size == BOUNDARY * 6);
        printf("SPARSE kind=%d file-bytes=%lld allocated-blocks=%lld before-first-destination-touch\n",
               kind, (long long)stat.st_size, (long long)stat.st_blocks);
    }
    *fd_out = fd;
    return p;
}
''' + C[end:]
replace_once('#include <sys/types.h>', '#include <sys/types.h>\n#include <sys/stat.h>')
replace_once('initial_byte = cold && !kind ? 0 : 0xcc;', 'initial_byte = 0;')
replace_once('for (int cold = 0; cold < 2; ++cold)', 'for (int cold = 1; cold < 2; ++cold)')
replace_once('for (int variant = 0; variant < 3; ++variant)', 'for (int variant = 0; variant < 1; ++variant)')
replace_once('for (int kind = 0; kind < 3; ++kind)', 'for (int kind = 0; kind < 5; ++kind)')
replace_once('PASS exact ARM64 STR Q / observed loop: anonymous, file-shared, noncontiguous shared extents; valid writes, genuine faults, unchanged-PC recovery, byte guards',
             'PASS 120 untouched-sparse ARM64 STR Q / observed-loop cases: anonymous, shared holes, disjoint extents, anonymous/shared boundary, reservation/commit; valid writes, genuine faults, unchanged-PC recovery, zero byte guards')

with tempfile.TemporaryDirectory(prefix='madeira-sparse-cross-page-') as directory:
    source, binary = Path(directory) / 'sparse.c', Path(directory) / 'sparse'
    source.write_text(C)
    subprocess.run([os.environ.get('CC', 'clang'), '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                    str(source), '-o', str(binary)], check=True, timeout=60)
    subprocess.run([str(binary)], check=True, timeout=300)
