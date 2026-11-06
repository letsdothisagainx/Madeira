/* Diagnostic publication snapshot, never authorization or a lifetime pin.
 * The cookie points into the fixed native mapping table, whose storage is
 * permanent. Readers must reject generation changes; PE memory is not read.
 */
#ifndef MADEIRA_FAULT_SITE_MAPPING_H
#define MADEIRA_FAULT_SITE_MAPPING_H
#include <stdint.h>
#include <stddef.h>
struct ios_fault_mapping_meta {
    uintptr_t pe_base, rx_base, owner, mapped_by;
    size_t image_size;
    unsigned long long generation;
    const unsigned long long *generation_address;
};
int ios_jit_pool_mapping_snapshot(uintptr_t address, struct ios_fault_mapping_meta *out);
#endif
