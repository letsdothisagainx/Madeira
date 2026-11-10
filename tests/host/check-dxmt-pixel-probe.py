#!/usr/bin/env python3
"""Exercise actual probe PE rejection and packaging/UI contracts, without claiming GPU results."""
import argparse
import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--image', type=Path, default=ROOT / 'app/Madeira/arm64ec-windows/pixel-readback-x64.exe')
parser.add_argument('--preflight', action='store_true', help='check real C input vectors and build/UI integration before the PE is built')
args = parser.parse_args()
spec = importlib.util.spec_from_file_location('probe_contract', ROOT / 'tools/check-dxmt-pixel-probe.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
if not args.preflight:
    module.validate(args.image)
    image = args.image.read_bytes()
    offset = struct.unpack_from('<I', image, 0x3c)[0]
    wrong_machine = bytearray(image)
    struct.pack_into('<H', wrong_machine, offset + 4, 0x14c)
    wrong_console = bytearray(image)
    struct.pack_into('<H', wrong_console, offset + 24 + 68, 2)
    wrong_backend = bytearray(image)
    import_name = image.lower().index(b'd3d11.dll')
    wrong_backend[import_name:import_name + 9] = b'd3d12.dll'
    missing_reporting = image.replace(b'DXMT device identity', b'X' * len(b'DXMT device identity'))
    old_contract = image.replace(b'contract=extended-v2 expected-readbacks=184 baseline=113',
                                 b'X' * len(b'contract=extended-v2 expected-readbacks=184 baseline=113'))
    with tempfile.TemporaryDirectory(prefix='madeira-pixel-contract-') as folder:
        for number, bad in enumerate((wrong_machine, wrong_console, wrong_backend, missing_reporting, old_contract)):
            path = Path(folder) / (str(number) + '.exe')
            path.write_bytes(bad)
            try:
                module.validate(path)
            except AssertionError:
                pass
            else:
                raise AssertionError('malformed probe contract was accepted: ' + str(number))
build = (ROOT / 'tools/build-ipa.sh').read_text()
assert build.index('setup-llvm-mingw.sh') < build.index('tests/dxmt/build-pixel-readback.sh')
package = (ROOT / 'tools/build/package-ipa.sh').read_text()
assert 'check-dxmt-pixel-probe.py" "$ROOT/app/Madeira/arm64ec-windows/pixel-readback-x64.exe"' in package
assert 'check-dxmt-pixel-probe.py" "$APP/arm64ec-windows/pixel-readback-x64.exe"' in package
assert 'ERROR: Xcode packaged stale DXMT pixel probe' in package
view = (ROOT / 'app/Madeira/ContentView.swift').read_text()
button = view[view.index('Button("DX11 pixel readback")'):]
button = button[:button.index('.buttonStyle')]
assert '"MADEIRA_EXE", "pixel-readback-x64.exe"' in button
assert 'runWineFullSequence(standaloneProbe: true)' in button
assert 'WINEDLLOVERRIDES' not in button
source = (ROOT / 'tests/dxmt/pixel-readback.c').read_text()
assert 'D3D_DRIVER_TYPE_HARDWARE' in source and 'D3D_DRIVER_TYPE_WARP' not in source
assert 'DXMT device identity' in source and 'GetData(GPU completion)' in source
assert 'fabsf(value - expected[c])' in source and 'ID3D11DeviceContext_Map(' in source
assert 'CreateBlendState' in source and 'CreateDepthStencilState' in source
assert 'CopySubresourceRegion' in source and 'D3D11_USAGE_IMMUTABLE' in source

def function(signature):
    start = source.index(signature)
    return source[start:source.index('\n}', start) + 2]

# Compile the actual C vector builder, with literal wire encodings and fixed
# expected texels derived from format endpoints. No GPU or DXMT decoder is
# replaced by this check, and no host-generated pixel PASS is possible.
fixture = '#include <assert.h>\n#include <math.h>\n#include <stdint.h>\n#include <string.h>\n'
fixture += function('static void put_bits(') + '\n'
fixture += function('static unsigned block_for(') + '\n'
fixture += function('static float srgb_to_linear(') + '\n'
fixture += '#include "pixel-reference-vectors.h"\n'
palette = source.index('static const float quadrants[4][4]')
fixture += source[palette:source.index(';', palette) + 1] + '\n'
fixture += function('static void indexed_expected(') + '\n'
fixture += r'''
int main(void) {
    uint8_t block[16]; float rgba[4];
    static const uint8_t bc7[16] = {0xc0,0x60,0x10,0x04,0x02,0x83,0xff,0x7f,0,0,0,0,0,0,0,0};
    static const uint8_t bc1[16] = {0x10,0x84,0,0,0,0,0,0};
    static const uint8_t bc3[16] = {0x80,0x80,0,0,0,0,0,0,0x10,0x84,0,0,0,0,0,0};
    static const uint8_t zero[16] = {0};
    assert(block_for(1,0,block,rgba)==8 && !memcmp(block,bc1,16));
    assert(fabsf(rgba[0]-.517647059f)<.000001f && fabsf(rgba[1]-.509803922f)<.000001f && rgba[3]==1);
    assert(block_for(3,0,block,rgba)==16 && !memcmp(block,bc3,16));
    assert(fabsf(rgba[3]-.501960784f)<.000001f);
    assert(block_for(4,0,block,rgba)==8 && block[0]==128 && block[1]==128 && rgba[1]==0 && rgba[3]==1);
    assert(block_for(5,0,block,rgba)==16 && block[8]==64 && block[9]==64 && fabsf(rgba[1]-.250980392f)<.000001f);
    /* BC6H low bits 00 select valid mode 0, whose zero endpoints/indices decode
       to RGB 0 and implicit alpha 1. BC7 low seven bits 1000000 select mode 6;
       this is deliberately not the invalid all-zero BC7 mode prefix. */
    assert(block_for(6,0,block,rgba)==16 && !memcmp(block,zero,16));
    assert(rgba[0]==0 && rgba[1]==0 && rgba[2]==0 && rgba[3]==1);
    assert(block_for(7,0,block,rgba)==16 && !memcmp(block,bc7,16) && (block[0]&127)==64);
    assert(fabsf(rgba[0]-.509803922f)<.000001f && fabsf(rgba[1]-.250980392f)<.000001f);
    assert(fabsf(rgba[2]-.752941176f)<.000001f && fabsf(rgba[3]-.996078431f)<.000001f);
    assert(fabsf(srgb_to_linear(132/255.f)-.230740049f)<.000001f);
    assert(fabsf(srgb_to_linear(130/255.f)-.223227957f)<.000001f);
    assert(srgb_to_linear(0)==0 && srgb_to_linear(1)==1);
    float grid[16][4]; const float tint[4] = {.25f,.5f,.75f,1};
    indexed_expected(grid,tint,0);
    for (unsigned y=0;y<4;y++) for (unsigned x=0;x<4;x++) {
        unsigned which=(y>=2?2:0)+(x>=2?1:0);
        const float known[4][4]={{.25f,0,0,1},{0,.5f,0,1},{0,0,.75f,1},{.25f,.5f,.75f,1}};
        assert(!memcmp(grid[y*4+x],known[which],16));
    }
    indexed_expected(grid,tint,1);
    for (unsigned y=0;y<4;y++) for (unsigned x=0;x<4;x++) {
        unsigned which=(y>=2?2:0)+(x%2);
        const float known[4][4]={{.25f,0,0,1},{0,.5f,0,1},{0,0,.75f,1},{.25f,.5f,.75f,1}};
        assert(!memcmp(grid[y*4+x],known[which],16));
    }
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-pixel-inputs-') as folder:
    path = Path(folder)
    code, executable = path / 'inputs.c', path / 'inputs'
    code.write_text(fixture)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-I', str(ROOT / 'tests/dxmt'), str(code), '-lm', '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
    # Wine's separate decoder validates the new BC6H encoder inputs. Expected
    # palette values below are literal, not read from the DXMT/GPU output.
    bcdec = ROOT / 'wine/dlls/d3dx9_36/bcdec.h'
    assert bcdec.is_file(), 'initialize the pinned Wine source for independent BC6H vector validation'
    independent = r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "pixel-reference-vectors.h"
#define WINE_UNUSED 1
#define BCDEC_STATIC
#define BCDEC_IMPLEMENTATION
#include "bcdec.h"
int main(void) {
    static const unsigned palette[2][6][3] = {
        {{1,0,0},{0,1,0},{0,0,1},{1,1,0},{1,0,1},{0,1,1}},
        {{0,1,0},{0,0,1},{1,1,0},{1,0,1},{0,1,1},{1,0,0}}
    };
    static const uint8_t red[16]={0xe3,0x3d,0,0,0x78,0x0f,0,0,0,0,0,0,0,0,0,0};
    union { uint64_t alignment[2]; uint8_t bytes[16]; } block;
    float rgba[4], rgb[48];
    for (unsigned cube=0;cube<2;cube++) for (unsigned face=0;face<6;face++) for (unsigned mip=0;mip<2;mip++) {
        ref_cube_color(cube,face,mip,rgba);
        for (unsigned c=0;c<3;c++) assert(rgba[c]==(float)(mip?1-palette[cube][face][c]:palette[cube][face][c]));
        assert(rgba[3]==1);
        ref_bc6h_constant(block.bytes,rgba);
        if (!cube && !face && !mip) assert(!memcmp(block.bytes,red,16));
        bcdec_bc6h_float(block.bytes,rgb,12,0);
        for (unsigned px=0;px<16;px++) for (unsigned c=0;c<3;c++)
            assert(rgb[px*3+c]==(float)(mip?1-palette[cube][face][c]:palette[cube][face][c]));
    }
    return 0;
}
'''
    code.write_text(independent)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror',
                    '-Wno-unused-function', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    '-I', str(ROOT / 'tests/dxmt'), '-I', str(bcdec.parent), str(code),
                    '-lm', '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
assert all(name in source for name in ('full_array_checks', 'cube_checks', 'sampler_checks', 'indexed_checks', 'multipass_checks'))
print('PASS actual C BC6H/BC7 vectors, independent Wine BC6H decoding of 24 cube/mip vectors, literal sRGB and indexed spatial references, PE packaging and user-accessible launch; GPU execution not performed by this host check')
