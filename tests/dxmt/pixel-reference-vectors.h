#ifndef MADEIRA_PIXEL_REFERENCE_VECTORS_H
#define MADEIRA_PIXEL_REFERENCE_VECTORS_H

/* Owned, deterministic inputs for the GPU reference test. No graphics backend
 * or decoder supplies the expected pixels. RGB values are exactly zero/one;
 * BC6H's implicit alpha is one. */
#include <assert.h>
#include <stdint.h>
#include <string.h>

static inline void ref_bc6h_put_bits(uint8_t block[16], unsigned *position,
                                    unsigned value, unsigned count)
{
    assert(*position + count <= 128);
    for (unsigned bit = 0; bit < count; ++bit, ++*position)
        block[*position / 8] |= ((value >> bit) & 1u) << (*position & 7u);
}

/* BC6H unsigned mode 11: 00011 prefix, two explicit RGB endpoints with ten
 * bits per component, no partition bits, then 63 index bits (anchor 3, rest 4).
 * Equal endpoints and zero indices make the entire block constant.
 *
 * For unsigned ten-bit endpoint 495, the specified unquantization is
 * ((495 << 16) + 0x8000) >> 10 = 31712. Final magnitude conversion gives
 * (31712 * 31) >> 6 = 15360 = half-float 0x3c00 = exactly 1.0.
 * Endpoint zero is the specification's exact zero special case. */
static inline void ref_bc6h_constant(uint8_t block[16], const float rgba[4])
{
    unsigned position = 0;
    memset(block, 0, 16);
    ref_bc6h_put_bits(block, &position, 3, 5);
    for (unsigned endpoint = 0; endpoint < 2; ++endpoint) {
        for (unsigned channel = 0; channel < 3; ++channel) {
            assert(rgba[channel] == 0.0f || rgba[channel] == 1.0f);
            ref_bc6h_put_bits(block, &position, rgba[channel] == 1.0f ? 495 : 0, 10);
        }
    }
    assert(position == 65); /* Remaining anchor/index bits stay zero. */
}

/* D3D cube face order is +X, -X, +Y, -Y, +Z, -Z. Face-center axis sampling
 * avoids seam/filter ambiguity. Cube one rotates the palette; mip one
 * complements RGB, exposing stale cube/mip selection without rounding. */
static inline void ref_cube_color(unsigned cube, unsigned face, unsigned mip, float rgba[4])
{
    static const unsigned colors[6][3] = {
        {1, 0, 0}, {0, 1, 0}, {0, 0, 1},
        {1, 1, 0}, {1, 0, 1}, {0, 1, 1}
    };
    assert(cube < 2 && face < 6 && mip < 2);
    for (unsigned channel = 0; channel < 3; ++channel) {
        unsigned value = colors[(face + cube) % 6][channel];
        rgba[channel] = (float)(mip ? 1u - value : value);
    }
    rgba[3] = 1.0f;
}

#endif
