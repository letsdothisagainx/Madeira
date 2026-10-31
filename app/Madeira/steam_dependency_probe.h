/* SPDX-License-Identifier: GPL-3.0-or-later
 * Read-only, bounded inventory. Never loads, replaces or repairs Steam files. */
#ifndef MADEIRA_STEAM_DEPENDENCY_PROBE_H
#define MADEIRA_STEAM_DEPENDENCY_PROBE_H
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

static inline void madeira_steam_probe_dependencies( const char *root )
{
    static const char *dirs[] = { "", "bin", "bin/x64", "bin/cef/cef.win7", "bin/cef/cef.win7x64" };
    static const char *names[] = { "SDL2.dll", "SDL3.dll", "gldriverquery.exe", "gldriverquery64.exe",
                                  "vulkandriverquery.exe", "vulkandriverquery64.exe", "vulkan-1.dll", "winevulkan.dll" };
    int saved_errno = errno;
    for (unsigned d = 0; d < sizeof(dirs)/sizeof(dirs[0]); d++)
    {
        char path[2048];
        int n = snprintf( path, sizeof(path), "%s/%s", root, dirs[d] );
        if (n < 0 || (size_t)n >= sizeof(path)) continue;
        DIR *folder = opendir( path );
        unsigned found = 0, entries = 0;
        if (!folder)
        {
            dprintf( 2, "[steam-deps] dir=%s scan-error=%d\n", *dirs[d] ? dirs[d] : ".", errno );
            continue;
        }
        struct dirent *entry;
        while (entries++ < 4096 && (entry = readdir( folder )))
            for (unsigned f = 0; f < sizeof(names)/sizeof(names[0]); f++)
                if (!strcasecmp( entry->d_name, names[f] ) && !(found & (1u << f)))
                {
                    unsigned char dos[64], pe[6];
                    unsigned machine = 0;
                    int error = 0, fd = openat( dirfd(folder), entry->d_name, O_RDONLY | O_CLOEXEC );
                    found |= 1u << f;
                    if (fd < 0) error = errno;
                    else
                    {
                        if (pread( fd, dos, sizeof(dos), 0 ) != sizeof(dos) || dos[0] != 'M' || dos[1] != 'Z')
                            error = ENOEXEC;
                        else
                        {
                            uint32_t off = (uint32_t)dos[60] | (uint32_t)dos[61] << 8 |
                                           (uint32_t)dos[62] << 16 | (uint32_t)dos[63] << 24;
                            if (off > 0x1000000 || pread( fd, pe, sizeof(pe), off ) != sizeof(pe) ||
                                memcmp( pe, "PE\0\0", 4 )) error = ENOEXEC;
                            else machine = (unsigned)pe[4] | (unsigned)pe[5] << 8;
                        }
                        close( fd );
                    }
                    dprintf( 2, "[steam-deps] dir=%s file=%s present=1 machine=%04x read-error=%d\n",
                             *dirs[d] ? dirs[d] : ".", names[f], machine, error );
                }
        closedir( folder );
        for (unsigned f = 0; f < sizeof(names)/sizeof(names[0]); f++)
            if (!(found & (1u << f)))
                dprintf( 2, "[steam-deps] dir=%s file=%s present=0 scan-complete=%u\n",
                         *dirs[d] ? dirs[d] : ".", names[f], entries < 4096 );
    }
    errno = saved_errno;
}
#endif
