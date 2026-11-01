/* SPDX-License-Identifier: LGPL-2.1-or-later
 * A64 scalar unsigned-immediate loads. Excludes SIMD, stores, prefetch and
 * reserved encodings; shared by the PE patcher and its Mach fallback. */
#ifndef MADEIRA_X18_SCALAR_LOAD_H
#define MADEIRA_X18_SCALAR_LOAD_H
#include <stdint.h>
#include <string.h>

struct ios_arm64_scalar_load
{
    unsigned int reg, base, bytes, extend;
    unsigned int offset;
};

static inline int ios_decode_scalar_load( uint32_t insn, struct ios_arm64_scalar_load *load )
{
    unsigned int size = insn >> 30, opc = (insn >> 22) & 3;
    if ((insn & 0x3f000000u) != 0x39000000u || !opc) return 0;
    if ((size == 3 && opc != 1) || (size == 2 && opc == 3)) return 0;
    load->reg = insn & 31;
    load->base = (insn >> 5) & 31;
    load->bytes = 1u << size;
    load->extend = opc == 1 ? 0 : opc == 2 ? 64 : 32;
    load->offset = ((insn >> 10) & 0xfff) << size;
    return 1;
}

static inline int ios_x18_scalar_load_dest( uint32_t insn )
{
    struct ios_arm64_scalar_load load;
    return ios_decode_scalar_load( insn, &load ) && load.base == 18 &&
           load.reg != 18 && load.reg != 31 ? (int)load.reg : -1;
}

static inline uint64_t ios_scalar_load_value( const unsigned char *data,
                                             const struct ios_arm64_scalar_load *load )
{
    uint64_t value = 0;
    memcpy( &value, data, load->bytes );
    if (load->extend)
    {
        int64_t signed_value = load->bytes == 1 ? (int8_t)value :
                               load->bytes == 2 ? (int16_t)value : (int32_t)value;
        value = load->extend == 32 ? (uint32_t)signed_value : (uint64_t)signed_value;
    }
    return value;
}
#endif
