/* SPDX-License-Identifier: GPL-3.0-or-later
 * Real i386 LoadLibrary/TLS/thread-attach probe, independent of Steam/Dock. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
typedef DWORD (WINAPI *state_fn)(void);
static DWORD WINAPI worker(void *p) { (void)p;return 0; }
int main(void)
{
    fprintf(stderr,"[wow64-probe] before-load machine=i386 module=fixture\n");
    HMODULE module=LoadLibraryW(L"madeira-wow64-module-probe.dll");
    DWORD error=module?0:GetLastError();
    fprintf(stderr,"[wow64-probe] load=%lu\n",(unsigned long)error);
    if (!module) return 1;
    state_fn state=(state_fn)(void*)GetProcAddress(module,"probe_state");
    if (!state) { fprintf(stderr,"[wow64-probe] export-error=%lu\n",(unsigned long)GetLastError());FreeLibrary(module);return 2; }
    DWORD before=state();
    HANDLE thread=CreateThread(NULL,0,worker,NULL,0,NULL);
    if (!thread) { fprintf(stderr,"[wow64-probe] thread-error=%lu\n",(unsigned long)GetLastError());FreeLibrary(module);return 3; }
    DWORD wait=WaitForSingleObject(thread,10000);
    CloseHandle(thread);
    if (wait!=WAIT_OBJECT_0) {
        /* Keep the fixture loaded if the new thread might still be using it. */
        fprintf(stderr,"[wow64-probe] wait=%lu\n",(unsigned long)wait);return 4;
    }
    DWORD after=state();
    int ok=(before&3)==3 && (after&15)==15;
    fprintf(stderr,"[wow64-probe] process-tls=%u process-attach=%u thread-tls=%u thread-attach=%u result=%u\n",
            !!(before&1),!!(before&2),!!(after&4),!!(after&8),ok?0u:5u);
    FreeLibrary(module);
    return ok?0:5;
}
