/* SPDX-License-Identifier: GPL-3.0-or-later
 * Synthetic loader fixture. Imports Wine's real OpenGL entry; no Valve code. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <GL/gl.h>
static volatile LONG flags;
static void NTAPI tls_callback(void *module,DWORD reason,void *reserved)
{
    (void)module;(void)reserved;
    if (reason==DLL_PROCESS_ATTACH) InterlockedOr(&flags,1);
    if (reason==DLL_THREAD_ATTACH) InterlockedOr(&flags,4);
}
PIMAGE_TLS_CALLBACK madeira_probe_tls __attribute__((section(".CRT$XLB"),used))=tls_callback;
__declspec(dllexport) DWORD WINAPI probe_state(void) { return (DWORD)flags; }
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID reserved)
{
    (void)module;(void)reserved;
    if (reason==DLL_PROCESS_ATTACH) {
        /* NULL is a valid answer with no context. This tests real dependency
         * initialization/call completion, not rendering support. */
        (void)wglGetCurrentContext();
        InterlockedOr(&flags,2);
    }
    if (reason==DLL_THREAD_ATTACH) InterlockedOr(&flags,8);
    return TRUE;
}
