/* SPDX-License-Identifier: MIT
 * Source-built ntdll's private counter-writer contract. No Windows ABI changes.
 * The exported counter block and the sampler's layout remain unchanged.
 */
#ifndef MADEIRA_NATIVE_COUNTER_ALIAS_ABI_H
#define MADEIRA_NATIVE_COUNTER_ALIAS_ABI_H
#define MADEIRA_NATIVE_COUNTER_ABI_V1 0x315752544e505849ULL
#define MADEIRA_NATIVE_COUNTER_BYTES 24712u
/* uint64 magic; uint32 bytes, reserved; uint64 writer. The writer is NULL in
 * the file, with no DIR64 relocation; only an unpublished owned copy binds it.
 */
#define MADEIRA_NATIVE_COUNTER_CONTRACT_BYTES 24u
#define MADEIRA_NATIVE_COUNTER_WRITER_OFFSET 16u
#endif
