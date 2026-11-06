#ifndef MADEIRA_JIT_STORE_CENSUS_H
#define MADEIRA_JIT_STORE_CENSUS_H
#include <stdint.h>

/* Observation only, after successful production decoding. This classification
 * never authorizes a store or changes its handling. Exact totals supplement
 * the lossy, bounded hot-PC table without VM queries or per-store logging. */
enum madeira_jit_store_family {
    MADEIRA_STORE_OTHER,
    MADEIRA_STORE_LSE,
    MADEIRA_STORE_EXCLUSIVE,
    MADEIRA_STORE_SWAP,
    MADEIRA_STORE_RELEASE,
    MADEIRA_STORE_GPR,
    MADEIRA_STORE_SIMD_PAIR,
    MADEIRA_STORE_FAMILIES
};

static inline enum madeira_jit_store_family madeira_jit_store_family(uint32_t insn)
{
    if ((insn & 0x3f20fc00u) == 0x38208000u) return MADEIRA_STORE_SWAP;
    if ((insn & 0x3f20cc00u) == 0x38200000u ||
        (insn & 0x3fa07c00u) == 0x08a07c00u) return MADEIRA_STORE_LSE;
    if ((insn & 0x3fe07c00u) == 0x08007c00u) return MADEIRA_STORE_EXCLUSIVE;
    if ((insn & 0x3ffffc00u) == 0x089ffc00u ||
        (insn & 0x3fe00c00u) == 0x19000000u) return MADEIRA_STORE_RELEASE;
    if ((insn & 0x3a000000u) == 0x28000000u ||
        (insn & 0x3e000000u) == 0x3c000000u) return MADEIRA_STORE_SIMD_PAIR;
    if ((insn & 0x3fc00000u) == 0x39000000u ||
        (insn & 0x3fe00000u) == 0x38000000u ||
        (insn & 0x3b200c00u) == 0x38200800u) return MADEIRA_STORE_GPR;
    return MADEIRA_STORE_OTHER;
}
#endif
