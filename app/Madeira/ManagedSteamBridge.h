/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef MADEIRA_MANAGED_STEAM_BRIDGE_H
#define MADEIRA_MANAGED_STEAM_BRIDGE_H

/* The verified Swift installer owns these prefix entries. Generic runtime
 * farms must not remove or replace them, including during a graphics probe or
 * an unrelated Wine launch. The PE loader uses the regular system32 copy. */
static inline int madeira_managed_bridge_name_equal(const char *name, const char *expected)
{
    unsigned char a, b;
    do
    {
        a = (unsigned char)*name++;
        b = (unsigned char)*expected++;
        if (a >= 'A' && a <= 'Z') a += 'a' - 'A';
        if (b >= 'A' && b <= 'Z') b += 'a' - 'A';
        if (a != b) return 0;
    } while (a);
    return 1;
}

static inline int madeira_generic_runtime_farm_allows(const char *name)
{
    if (!name) return 0;
    return !madeira_managed_bridge_name_equal(name, "madeira-htmlipc-bridge.dll") &&
           !madeira_managed_bridge_name_equal(name, "madeira-htmlipc-bridge.manifest.json") &&
           !madeira_managed_bridge_name_equal(name, "madeira-htmlipc-bridge.madeira-owned-v1.json");
}

#endif
