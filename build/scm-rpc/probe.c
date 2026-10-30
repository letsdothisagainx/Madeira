/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright 2026 125hz
 * Madeira Converter Exception: see LICENSE-EXCEPTION.md */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsvc.h>
#include <stdio.h>
int main(void)
{
    /* Genuine API only: no service installation, registry writes or replies.
     * NULL names and a constant access mask keep this probe free of user data. */
    fprintf(stderr, "[scm-rpc-probe] before machine=null database=null access=%lu\n",
            (unsigned long)SC_MANAGER_CONNECT);
    SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    DWORD error = manager ? 0 : GetLastError();
    fprintf(stderr, "[scm-rpc-probe] after manager-present=%u error=%lu\n",
            manager != NULL, (unsigned long)error);
    if (manager) CloseServiceHandle(manager);
    return manager ? 0 : (int)(error ? error : ERROR_GEN_FAILURE);
}
