/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Auxiliary-IAT index validation shared by the Wine loader patch and tests.
 * All RVAs refer to one loaded PE image. Never infer a slot by scanning data.
 */
#ifndef MADEIRA_SCM_AUX_SLOT_H
#define MADEIRA_SCM_AUX_SLOT_H
#include <stdint.h>
static int madeira_scm_aux_slot(uint32_t image_size, uint32_t iat_rva,
                               uint32_t iat_size, uint32_t slot_rva,
                               uint32_t aux_rva, uint32_t *result)
{
    uint64_t offset, end;
    if (!iat_rva || !aux_rva || ((iat_rva | aux_rva | slot_rva) & 7)) return 0;
    if ((uint64_t)iat_rva + iat_size > image_size || slot_rva < iat_rva) return 0;
    offset = (uint64_t)slot_rva - iat_rva;
    if (offset + 8 > iat_size) return 0;
    end = (uint64_t)aux_rva + offset + 8;
    if (end > image_size) return 0;
    *result = (uint32_t)(end - 8);
    return 1;
}
#endif
