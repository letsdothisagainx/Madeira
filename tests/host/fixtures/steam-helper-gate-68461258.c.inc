        static const char * const blocked_names[] = { "steamerrorreporter", "gldriverquery", "vulkandriverquery",
                                                      "steamsysinfo", "hardwareupdater",
                                                      "unitycrashhandler64" };
        const WCHAR *ip = params->ImagePathName.Buffer;
        int ip_len = params->ImagePathName.Length / sizeof(WCHAR);
        unsigned b;
        /* ml1357: the full Windows Steam client (steam.exe, started by the in-session
         * launcher or a library entry) runs its own crash reporter, hardware survey and
         * GPU probes. These names were refused because, before ml937, a helper's crash or
         * self-terminate took the whole app down; now each ends only its own
         * pseudo-process. When the PARENT is steam.exe they may start (Dock sessions
         * host Valve's client in dockhost.exe, so their spawns keep the gate).
         * hardwareupdater (pool churn) and the web helper's --type= children (a second
         * CEF instance, see below) stay refused. env.MADEIRA_PROC_GATE_STEAM=0 refuses
         * them all as before. */
        int full_client_parent = 0;
        {
            const char *g = getenv( "MADEIRA_PROC_GATE_STEAM" );
            const RTL_USER_PROCESS_PARAMETERS *cur = NtCurrentTeb()->Peb->ProcessParameters;
            if (!(g && g[0] == '0') && cur && cur->ImagePathName.Buffer &&
                ios_image_name_is( cur->ImagePathName.Buffer, cur->ImagePathName.Length / sizeof(WCHAR),
                                   "steam.exe" ))
                full_client_parent = 1;
        }

        for (b = 0; b < sizeof(blocked_names)/sizeof(blocked_names[0]); b++)
        {
            const char *blocked = blocked_names[b];
            int bl = (int)strlen( blocked ), k, j;

            if (full_client_parent && b < 4)
            {
                /* the first four names: steamerrorreporter, gldriverquery,
                 * vulkandriverquery, steamsysinfo (keep that order above) */
                int hit = 0;
                for (k = 0; k + bl <= ip_len && !hit; k++)
                {
                    for (j = 0; j < bl; j++)
                    {
                        WCHAR c = ip[k + j];
                        if (c >= 'A' && c <= 'Z') c += 32;
                        if (c != (WCHAR)blocked[j]) break;
                    }
                    if (j == bl) hit = 1;
                }
                if (hit)
                    dprintf( 2, "[proc-gate] ml1357 allowing %s: started by the full Steam client "
                             "(steam.exe), whose own helpers run in this session "
                             "(env.MADEIRA_PROC_GATE_STEAM=0 refuses them as before)\n",
                             debugstr_us( &params->ImagePathName ) );
                continue;
            }

            for (k = 0; k + bl <= ip_len; k++)
            {
                for (j = 0; j < bl; j++)
                {
                    WCHAR c = ip[k + j];
                    if (c >= 'A' && c <= 'Z') c += 32;
                    if (c != (WCHAR)blocked[j]) break;
                }
                if (j == bl)
                {
                    dprintf(2, "[proc-gate] REFUSING spawn of %s (%s gate)\n",
                            debugstr_us( &params->ImagePathName ), blocked );
                    return STATUS_ACCESS_DENIED;
                }
            }
        }

        /* madeira-bcd: more optional helpers, named per game. Every x64 pseudo-
         * process copies its own system DLLs into the JIT pool and gets a 16 MB
         * code buffer. GTA V Enhanced build 374 (2026-10-04 09:25): with
         * SocialClubHelper.exe's 240 MB libcef.dll in the big-image slot, the
         * run below the hole was 557 of 560 MB full and its D3DCompiler_47.dll
         * (4.5 MB) failed -- "The CEF browser ... crashed and could not
         * restart" -- while the launcher's crashpad handler,
         * RockstarErrorHandler.exe, held 17 MB of copies and a code buffer.
         * MADEIRA_SPAWN_BLOCK = <name>;<name>;... refuses a spawn whose image
         * path contains one of the names (case-insensitive), like the gate
         * above; empty by default. */
        {
            const char *list = getenv( "MADEIRA_SPAWN_BLOCK" );

            while (list && *list)
            {
                const char *end = strchr( list, ';' );
                int bl = end ? (int)(end - list) : (int)strlen( list ), k, j;

                for (k = 0; bl > 0 && k + bl <= ip_len; k++)
                {
                    for (j = 0; j < bl; j++)
                    {
                        WCHAR c = ip[k + j], w = (WCHAR)(unsigned char)list[j];
                        if (c >= 'A' && c <= 'Z') c += 32;
                        if (w >= 'A' && w <= 'Z') w += 32;
                        if (c != w) break;
                    }
                    if (j == bl)
                    {
                        dprintf(2, "[proc-gate] madeira-bcd REFUSING spawn of %s (MADEIRA_SPAWN_BLOCK %.*s)\n",
                                debugstr_us( &params->ImagePathName ), bl, list );
                        return STATUS_ACCESS_DENIED;
                    }
                }
                list = end ? end + 1 : NULL;
            }
        }
