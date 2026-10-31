/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef MADEIRA_STIK_BREAKPOINT_H
#define MADEIRA_STIK_BREAKPOINT_H
#include <stdint.h>
#include <string.h>
static int ios_expected_stik_breakpoint( uint32_t insn, uint64_t command, const char *symbol )
{
    if (insn != 0xd43e01a0u || !symbol) return 0;
    return (!command && !strcmp( symbol, "jit26_detach" )) ||
           (command == 1 && !strcmp( symbol, "jit26_prepare_region" ));
}
#endif
