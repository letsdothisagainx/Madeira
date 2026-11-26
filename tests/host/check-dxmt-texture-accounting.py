#!/usr/bin/env python3
"""Compile actual DXMT capacity helpers against independent byte references.

These are tight format-capacity calculations, not physical residency tests.
The pinned WMT enums/descriptor and original/staged C++ helpers run unchanged;
ordinary texture creation, data upload, API validation and GPU lifetime are
not replaced or claimed by this host check.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import random
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
NAME = 'src/dxmt/dxmt_mem_census.hpp'
spec = importlib.util.spec_from_file_location('texture_accounting', ROOT / 'tools/build/stage-dxmt-texture-accounting.py')
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


def declaration(text, signature):
    begin = text.index(signature)
    opening = text.index('{', begin)
    depth = 1
    cursor = opening + 1
    while depth:
        depth += (text[cursor] == '{') - (text[cursor] == '}')
        cursor += 1
    return text[begin:cursor] + (';' if text[cursor:cursor + 1] == ';' else '') + '\n'


def function(text, signature):
    return 'inline ' + declaration(text, signature)


source = (ROOT / 'dxmt' / NAME).read_text()
staged = stage.stage_file(NAME, source)
texture_name = 'src/dxmt/dxmt_texture.cpp'
texture_source = (ROOT / 'dxmt' / texture_name).read_text()
producer = stage.stage_file(texture_name, texture_source)
assert 'device_.supportsBCTextureCompression()' in producer
assert 'mem_census_texture_bytes(info, native_bc)' in producer
# Accounting cannot alter the object, descriptor, resource creation or lifetime.
assert producer.count('device_.newTexture(info)') == texture_source.count('device_.newTexture(info)')
assert producer.count('mem_census_add(MEMOWN_TEX_PRIVATE, ta->census_bytes_)') == 1
for name, text in ((NAME, staged), (texture_name, producer)):
    try:
        stage.stage_file(name, text)
    except ValueError:
        pass
    else:
        raise AssertionError('duplicate staging accepted: ' + name)
for name, text in (
        (NAME, source.replace('mem_census_texture_bytes(const WMTTextureInfo &info)',
                              'mem_census_texture_bytes_changed(const WMTTextureInfo &info)')),
        (texture_name, texture_source + '\n  ta->census_bytes_ = mem_census_texture_bytes(info);\n'),
        ('src/dxmt/unowned.cpp', texture_source)):
    try:
        stage.stage_file(name, text)
    except ValueError:
        pass
    else:
        raise AssertionError('changed or unowned source contract accepted: ' + name)

wmt = (ROOT / 'dxmt/src/winemetal/winemetal.h').read_text()
definitions = '\n'.join(declaration(wmt, name) for name in (
    'enum WMTPixelFormat :', 'enum WMTResourceOptions :',
    'enum WMTTextureType :', 'enum WMTTextureUsage :', 'struct WMTTextureInfo {'))
old = function(source, 'uint64_t\nmem_census_texture_bytes(')
old = old.replace('mem_census_texture_bytes(', 'legacy_texture_bytes(', 1)
old = old.replace('mem_census_texel_bytes(', 'legacy_texel_bytes(')
old_texels = function(source, 'uint32_t\nmem_census_texel_bytes(')
old_texels = old_texels.replace('mem_census_texel_bytes(', 'legacy_texel_bytes(', 1)
helpers = function(staged, 'uint32_t\nmem_census_texel_bytes(')
for signature in ('uint32_t\nmem_census_bc_block_bytes(',
                  'uint64_t\nmem_census_capacity_mul(',
                  'uint64_t\nmem_census_texture_bytes('):
    helpers += function(staged, signature)

MAX = (1 << 64) - 1
# WMT/Metal formats (not DXGI): explicit expectations are independent of the
# production switch. Every native format gets linear/sRGB or signed coverage.
formats = [(130, 8, 4), (131, 8, 4), (132, 16, 4), (133, 16, 4),
           (134, 16, 4), (135, 16, 4), (140, 8, 1), (141, 8, 1),
           (142, 16, 2), (143, 16, 2), (150, 16, 8), (151, 16, 8),
           (152, 16, 4), (153, 16, 4)]
rgba = [(70, 0, 4), (71, 0, 4), (80, 0, 4), (81, 0, 4),
        (10, 0, 1), (30, 0, 2), (25, 0, 2), (115, 0, 8),
        (125, 0, 16), (252, 0, 4), (112, 0, 8), (253, 0, 1),
        (260, 0, 8), (552, 0, 8), (553, 0, 8)]


def reference(width, height, depth, mips, arrays, samples, kind, block, decoded, native):
    levels = mips or 1
    if levels > 32:
        return MAX
    # Calculate with arbitrary-precision integers, using encoded block rows
    # and columns rather than the C++ helper's saturating intermediate math.
    total = 0
    for level in range(levels):
        w, h, d = [max(1, value // (2 ** level)) for value in (width, height, depth)]
        if block and native:
            total += ((w + 3) // 4) * ((h + 3) // 4) * block * d
        else:
            total += w * h * d * decoded
    return min(MAX, total * max(1, arrays) * max(1, samples) * (6 if kind in (5, 6) else 1))


cases = []
# Run25 request 27487: array_length counts cubes, not individual faces.
# Each BC6H face has 87,376 bytes across its seven mips; 116 * 6 faces
# require 60,813,696 bytes before staging. This is a capacity fixture, not
# a claim that a Metal allocation or iPhone gameplay was exercised.
assert reference(256, 256, 1, 7, 116, 1, 6, 16, 8, True) == 60_813_696
cases.append((151, 256, 256, 1, 7, 116, 1, 6, True, 60_813_696))
for fmt, block, decoded in formats + rgba:
    for shape in ((1, 1, 1, 1, 1, 1, 2), (4, 4, 1, 1, 1, 1, 2),
                  (5, 7, 1, 3, 1, 1, 2), (4096, 4096, 1, 13, 1, 1, 2),
                  (17, 9, 5, 5, 1, 1, 7), (128, 128, 1, 8, 1, 1, 5),
                  (8, 8, 1, 4, 696, 1, 6), (16, 16, 1, 1, 4, 4, 8),
                  (0, 0, 0, 0, 0, 0, 2), (1, 1, 1, 33, 1, 1, 2),
                  (0xffffffff, 0xffffffff, 0xffffffff, 32, 0xffffffff, 255, 6)):
        for native in (False, True):
            cases.append((fmt, *shape, native,
                          reference(*shape, block, decoded, native)))
rng = random.Random(0xBC20261115)
for _ in range(1500):
    fmt, block, decoded = rng.choice(formats + rgba)
    shape = (rng.randrange(1, 16385), rng.randrange(1, 16385), rng.randrange(1, 33),
             rng.randrange(0, 16), rng.randrange(0, 25), rng.choice((0, 1, 2, 4, 8)),
             rng.choice((2, 3, 5, 6, 7, 8)))
    native = bool(rng.randrange(2))
    cases.append((fmt, *shape, native, reference(*shape, block, decoded, native)))

rows = ',\n'.join('{%s}' % ','.join(str(int(v)) + ('ull' if i == 9 else 'u')
                                         for i, v in enumerate(row)) for row in cases)
code = '''#include <cassert>
#include <cstdint>
#include <cstdio>
using mach_port_t = uint32_t;
''' + definitions + '''
#define ORIGINAL_FORMAT(format) (format & ~WMTPixelFormatCustomSwizzle)
''' + helpers + old_texels + old + '''
struct Case { uint32_t f,w,h,d,m,a,s,t,n; uint64_t expected; };
static const Case cases[] = {
''' + rows + '''
};
int main() {
  unsigned native_failures_before=0, decoded_equal=0, nonbc_failures_before=0;
  for(const auto &c: cases) {
    WMTTextureInfo info{};
    info.pixel_format=(WMTPixelFormat)c.f;
    info.width=c.w;info.height=c.h;info.depth=c.d;
    info.mipmap_level_count=c.m;info.array_length=c.a;info.sample_count=c.s;
    info.type=(WMTTextureType)c.t;
    const auto result=mem_census_texture_bytes(info,c.n);
    if(result!=c.expected) {
      std::fprintf(stderr,"mismatch fmt=%u size=%ux%ux%u mip=%u arr=%u samples=%u type=%u native=%u got=%llu expected=%llu\\n",
        c.f,c.w,c.h,c.d,c.m,c.a,c.s,c.t,c.n,(unsigned long long)result,(unsigned long long)c.expected);
      return 1;
    }
    // Avoid running the old undefined-shift/overflow cases in the negative
    // control. Ordinary scalar/array decoded layouts remain byte-for-byte.
    if(c.m<=16 && c.w<=16384 && c.h<=16384 && c.d<=32 && c.a<=24 && c.t!=5 && c.t!=6) {
      const auto before=legacy_texture_bytes(info);
      const bool corrected_nonbc=c.f==112 || c.f==253 || c.f==260 || c.f==552 || c.f==553;
      if(!c.n && !corrected_nonbc) { assert(before==result); ++decoded_equal; }
      if(corrected_nonbc && before!=result) ++nonbc_failures_before;
      if(c.n && mem_census_bc_block_bytes(info.pixel_format) && before!=result) ++native_failures_before;
    }
    assert(mem_census_texture_bytes(info)==mem_census_texture_bytes(info,false));
  }
  assert(native_failures_before>100 && decoded_equal>100 && nonbc_failures_before>20);
  assert(mem_census_capacity_mul(UINT64_MAX,2)==UINT64_MAX);
  assert(mem_census_capacity_mul(UINT64_MAX,0)==0);
  std::printf("PASS %zu actual WMT capacity cases: nativeBC old-mismatches=%u, nonBC old-mismatches=%u, unchanged decoded/RGBA cases=%u; odd/tiny mips, arrays, cubes, 3D, samples, invalid levels and saturation\\n",
    sizeof(cases)/sizeof(cases[0]),native_failures_before,nonbc_failures_before,decoded_equal);
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-texture-accounting-') as temp:
    path = Path(temp) / 'test.cpp'
    binary = Path(temp) / 'test'
    path.write_text(code)
    compiler = shlex.split(os.environ.get('CXX', 'c++'))
    subprocess.run([*compiler, '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    str(path), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=15)
assert (ROOT / 'dxmt' / NAME).read_text() == source
assert (ROOT / 'dxmt' / texture_name).read_text() == texture_source
print('PASS source staging is strict, native capability reaches actual census producer, and vendor bytes remain unchanged; no physical-memory or GPU claim')
