#!/usr/bin/env python3
"""Attribute native BC block capacity without claiming physical residency.

The original census assumed every BC texture expanded on unsupported GPUs.
Native-BC devices retain blocks. Correct requested capacity is useful when
choosing admission budgets, but Metal alignment/residency remain separate.
"""
import argparse
import hashlib
import json
from pathlib import Path

FILES = ('src/dxmt/dxmt_mem_census.hpp', 'src/dxmt/dxmt_texture.cpp')


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise ValueError('DXMT texture accounting input contract changed: ' + repr(before[:80]))
    return source.replace(before, after, 1)

HELPER = r'''// madeira-texture-accounting-v1: tight format capacity, not residency or
// driver heap size. Native BC uses 4x4 blocks even for tiny/odd tail mips.
inline uint32_t
mem_census_bc_block_bytes(enum WMTPixelFormat format) {
  switch (ORIGINAL_FORMAT(format)) {
  case WMTPixelFormatBC1_RGBA: case WMTPixelFormatBC1_RGBA_sRGB:
  case WMTPixelFormatBC4_RUnorm: case WMTPixelFormatBC4_RSnorm:
    return 8;
  case WMTPixelFormatBC2_RGBA: case WMTPixelFormatBC2_RGBA_sRGB:
  case WMTPixelFormatBC3_RGBA: case WMTPixelFormatBC3_RGBA_sRGB:
  case WMTPixelFormatBC5_RGUnorm: case WMTPixelFormatBC5_RGSnorm:
  case WMTPixelFormatBC6H_RGBFloat: case WMTPixelFormatBC6H_RGBUfloat:
  case WMTPixelFormatBC7_RGBAUnorm: case WMTPixelFormatBC7_RGBAUnorm_sRGB:
    return 16;
  default:
    return 0;
  }
}

inline uint64_t
mem_census_capacity_mul(uint64_t left, uint64_t right) {
  return right && left > UINT64_MAX / right ? UINT64_MAX : left * right;
}

inline uint64_t
mem_census_texture_bytes(const WMTTextureInfo &info, bool native_bc = false) {
  const uint32_t block = native_bc ? mem_census_bc_block_bytes(info.pixel_format) : 0;
  const uint32_t bpp = mem_census_texel_bytes((enum WMTPixelFormat)ORIGINAL_FORMAT(info.pixel_format));
  const uint32_t levels = info.mipmap_level_count ? info.mipmap_level_count : 1u;
  const uint32_t arrays = info.array_length ? info.array_length : 1u;
  const uint32_t samples = info.sample_count ? info.sample_count : 1u;
  const uint32_t faces = info.type == WMTTextureTypeCube || info.type == WMTTextureTypeCubeArray ? 6u : 1u;
  // uint32_t dimensions have at most32 valid mip levels. A malformed
  // descriptor must never wrap an admission charge or induce an oversized
  // walk; the actual creation API remains responsible for validation.
  if (levels > 32) return UINT64_MAX;
  uint64_t total = 0;
  for (uint32_t level = 0; level < levels; ++level) {
    const uint64_t w = level < 32 && (info.width >> level) ? info.width >> level : 1u;
    const uint64_t h = level < 32 && (info.height >> level) ? info.height >> level : 1u;
    const uint64_t d = level < 32 && (info.depth >> level) ? info.depth >> level : 1u;
    uint64_t bytes = block ? mem_census_capacity_mul((w + 3) / 4, (h + 3) / 4)
                           : mem_census_capacity_mul(w, h);
    bytes = mem_census_capacity_mul(bytes, d);
    bytes = mem_census_capacity_mul(bytes, block ? block : bpp);
    if (bytes > UINT64_MAX - total) return UINT64_MAX;
    total += bytes;
  }
  return mem_census_capacity_mul(mem_census_capacity_mul(
      mem_census_capacity_mul(total, arrays), faces), samples);
}'''


def stage_file(name, source):
    if 'madeira-texture-accounting-v1' in source:
        raise ValueError('DXMT texture capacity input is already staged')
    if name == FILES[0]:
        # The native bridge's byte layout also distinguishes standalone
        # stencil, RGBA16 signed-normalized and packed depth/stencil storage.
        # These are capacity-only corrections; no resource format changes.
        source = replace_once(source,
            '  case WMTPixelFormatA8Unorm: case WMTPixelFormatR8Uint: case WMTPixelFormatR8Sint:',
            '  case WMTPixelFormatA8Unorm: case WMTPixelFormatR8Uint: case WMTPixelFormatR8Sint:\n'
            '  case WMTPixelFormatStencil8:')
        source = replace_once(source,
            '  case WMTPixelFormatRGBA16Float: case WMTPixelFormatRGBA16Uint:',
            '  case WMTPixelFormatRGBA16Float: case WMTPixelFormatRGBA16Uint:\n'
            '  case WMTPixelFormatRGBA16Snorm:')
        source = replace_once(source,
            '  case WMTPixelFormatRG32Float: case WMTPixelFormatRG32Uint: case WMTPixelFormatRG32Sint:',
            '  case WMTPixelFormatRG32Float: case WMTPixelFormatRG32Uint: case WMTPixelFormatRG32Sint:\n'
            '  case WMTPixelFormatDepth32Float_Stencil8:\n'
            '  case WMTPixelFormatBGRA10_XR: case WMTPixelFormatBGRA10_XR_sRGB:')
        signature = 'inline uint64_t\nmem_census_texture_bytes(const WMTTextureInfo &info) {'
        if source.count(signature) != 1:
            raise ValueError('DXMT texture capacity helper contract changed')
        start = source.index(signature)
        end = source.index('\n}', start) + 2
        source = source[:start] + HELPER + source[end:]
        old_comment = '/* Physical bytes a texture will actually occupy.'
        if source.count(old_comment) != 1:
            raise ValueError('DXMT texture accounting comment contract changed')
        begin = source.index(old_comment)
        finish = source.index('*/', begin) + 2
        source = source[:begin] + '''/* Decoded bytes per texel on devices without native BC support. The
 * capacity helper below separately accounts native BC blocks. Neither value
 * measures residency, driver padding, or per-resource physical footprint. */''' + source[finish:]
        return source
    if name == FILES[1]:
        before = '  ta->census_bytes_ = mem_census_texture_bytes(info);'
        if source.count(before) != 1:
            raise ValueError('DXMT texture capacity producer contract changed')
        return source.replace(before, '''  // madeira-texture-accounting-v1: compressed blocks only when the actual
  // device supports them; fallback devices still count decoded storage.
  const bool native_bc = mem_census_bc_block_bytes(info.pixel_format) && device_.supportsBCTextureCompression();
  ta->census_bytes_ = mem_census_texture_bytes(info, native_bc);''', 1)
    raise ValueError('unowned DXMT texture capacity file: ' + name)


def stage(source_dir, output_dir, overlay_dir=None):
    if source_dir.resolve() == output_dir.resolve():
        raise ValueError('vendor input must remain immutable')
    rows = []
    for name in FILES:
        original = source_dir / name
        candidate = overlay_dir / name if overlay_dir else original
        path = candidate if candidate.is_file() else original
        data = path.read_bytes()
        output = stage_file(name, data.decode()).encode()
        destination = output_dir / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(output)
        rows.append({'path': name, 'input_sha256': hashlib.sha256(data).hexdigest(),
                     'output_sha256': hashlib.sha256(output).hexdigest()})
    return rows


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--overlay-dir', type=Path)
    args = parser.parse_args()
    print(json.dumps({'stage': 'dxmt-texture-accounting-v1',
                      'files': stage(args.source_dir, args.output_dir, args.overlay_dir)}))
