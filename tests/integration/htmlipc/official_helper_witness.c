/* SPDX-License-Identifier: MIT
 * Launch an unmodified official helper and observe its own master section.
 * This peer never creates SteamChrome objects or sends invented readiness. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"[official-browser] line=%u winerror=%lu\n",__LINE__,GetLastError());goto done;}}while(0)
int wmain(int argc,WCHAR **argv)
{
    STARTUPINFOW startup={0};PROCESS_INFORMATION child={0};HANDLE section=NULL,snapshot=INVALID_HANDLE_VALUE;
    void *view=NULL;WCHAR command[32768],name[128];DWORD exit=0;int result=1,sdl=0,cef=0;ULONGLONG started;
    if(argc!=5)return 2;
    CHECK(swprintf(name,128,L"SteamChrome_MasterStream_spid%lu_mem-IPCWrapper",GetCurrentProcessId())>0);
    SetLastError(0);section=OpenFileMappingW(FILE_MAP_READ,FALSE,name);
    CHECK(!section&&GetLastError()==ERROR_FILE_NOT_FOUND);
    CHECK(swprintf(command,32768,
        L"\"%ls\" -nocrashdialog -lang=en_US \"-steampath=%ls\" \"-cachedir=%ls\" \"-logdir=%ls\" -steampid=%lu -buildid=1792618285 -steamid=0 -uimode=7 --single-process --js-flags=--jitless --enable-logging --v=1 --log-severity=verbose --no-proxy-server --winhttp-proxy-resolver",
        argv[1],argv[2],argv[3],argv[4],GetCurrentProcessId())>0);
    startup.cb=sizeof(startup);CHECK(CreateProcessW(argv[1],command,NULL,NULL,FALSE,0,NULL,argv[2],&startup,&child));
    started=GetTickCount64();
    while(GetTickCount64()-started<120000){
        section=OpenFileMappingW(FILE_MAP_READ,FALSE,name);
        if(section)break;
        CHECK(GetLastError()==ERROR_FILE_NOT_FOUND);
        CHECK(GetExitCodeProcess(child.hProcess,&exit));
        if(exit!=STILL_ACTIVE){fprintf(stderr,"[official-browser] early-exit=%08lx elapsed-ms=%llu\n",exit,(unsigned long long)(GetTickCount64()-started));goto done;}
        Sleep(25);
    }
    CHECK(section);view=MapViewOfFile(section,FILE_MAP_READ,0,0,16);CHECK(view);
    {const volatile uint32_t *header=view;uint32_t capacity=header[2],used=header[3];
      CHECK(capacity==8192&&header[0]<capacity&&header[1]<capacity&&used<=capacity);}
    snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,child.dwProcessId);
    if(snapshot!=INVALID_HANDLE_VALUE){
        MODULEENTRY32W module;module.dwSize=sizeof(module);
        if(Module32FirstW(snapshot,&module))do{
            if(!_wcsicmp(module.szModule,L"SDL3.dll"))sdl=1;
            if(!_wcsicmp(module.szModule,L"libcef.dll"))cef=1;
            module.dwSize=sizeof(module);
        }while(Module32NextW(snapshot,&module));
    }
    /* The section witness is the authoritative event. Module enumeration is
     * secondary metadata; cross-architecture Toolhelp support varies in Wine. */
    printf("[official-browser] genuine-master-created=1 helper-alive=1 capacity=8192 elapsed-ms=%llu sdl3-enumerated=%d libcef-enumerated=%d\n",
        (unsigned long long)(GetTickCount64()-started),sdl,cef);result=0;
 done:
    if(snapshot!=INVALID_HANDLE_VALUE)CloseHandle(snapshot);
    if(view)UnmapViewOfFile(view);if(section)CloseHandle(section);
    /* Disposable-prefix cleanup only; the production Steam runtime and user
     * prefixes are never accessed. No retry/restart is performed. */
    if(child.hProcess){if(GetExitCodeProcess(child.hProcess,&exit)&&exit==STILL_ACTIVE){TerminateProcess(child.hProcess,0x54455354);WaitForSingleObject(child.hProcess,5000);}CloseHandle(child.hProcess);}
    if(child.hThread)CloseHandle(child.hThread);
    return result;
}
