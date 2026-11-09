/* SPDX-License-Identifier: GPL-3.0-or-later
 * Isolated SCM integration fixture; never shipped or substituted for Valve. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsvc.h>
#include <stdio.h>
#include <wchar.h>

static const wchar_t service_name[] = L"Steam Client Service";
static const wchar_t service_image[] = L"C:\\Fixture\\Common Files\\Steam\\SteamService.exe";
static const wchar_t updater_image[] = L"C:\\Fixture\\Common Files\\Steam\\SteamServiceTmp.exe";
static const wchar_t marker[] = L"C:\\Fixture\\updated.fixture";
static const wchar_t dispatcher_gate[] = L"Local\\MadeiraServiceIntegrationDispatcherGate";
static SERVICE_STATUS_HANDLE status_handle;
static HANDLE stop_event;
static SERVICE_STATUS status;

static void fail(const char *call) { fprintf(stderr,"[service-fixture] failed=%s error=%lu\n",call,(unsigned long)GetLastError()); ExitProcess(88); }
static void mark(const wchar_t *path) {
    HANDLE file=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(file==INVALID_HANDLE_VALUE)fail("mark");
    const char contents[]="isolated-test-fixture\n";DWORD written;
    if(!WriteFile(file,contents,sizeof(contents)-1,&written,NULL)||written!=sizeof(contents)-1)fail("write-marker");
    CloseHandle(file);
}
static void report_state(DWORD current) {
    status.dwServiceType=SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState=current;status.dwWin32ExitCode=0;status.dwServiceSpecificExitCode=0;
    status.dwControlsAccepted=current==SERVICE_RUNNING?SERVICE_ACCEPT_STOP:0;
    status.dwWaitHint=current==SERVICE_START_PENDING?1000:0;
    status.dwCheckPoint=current==SERVICE_START_PENDING?1:0;
    if(!SetServiceStatus(status_handle,&status))fail("SetServiceStatus");
    fprintf(stderr,"[service-fixture] state=%lu\n",(unsigned long)current);
    HANDLE log=CreateFileW(L"C:\\Fixture\\states.fixture",FILE_APPEND_DATA,FILE_SHARE_READ,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(log==INVALID_HANDLE_VALUE)fail("state-log");
    char line[32];int length=sprintf(line,"%lu\n",(unsigned long)current);DWORD written;
    if(!WriteFile(log,line,(DWORD)length,&written,NULL)||written!=(DWORD)length)fail("state-write");
    CloseHandle(log);
}
static DWORD WINAPI control(DWORD type,DWORD event,void *data,void *context) {
    (void)event;(void)data;(void)context;
    if(type==SERVICE_CONTROL_STOP) {SetEvent(stop_event);return NO_ERROR;}
    return type==SERVICE_CONTROL_INTERROGATE?NO_ERROR:ERROR_CALL_NOT_IMPLEMENTED;
}
static void WINAPI service_main(DWORD argc,wchar_t **argv) {
    (void)argc;(void)argv;
    stop_event=CreateEventW(NULL,TRUE,FALSE,NULL);if(!stop_event)fail("CreateEvent");
    status_handle=RegisterServiceCtrlHandlerExW(service_name,control,NULL);if(!status_handle)fail("RegisterServiceCtrlHandler");
    report_state(SERVICE_START_PENDING);Sleep(150);report_state(SERVICE_RUNNING);
    if(WaitForSingleObject(stop_event,15000)!=WAIT_OBJECT_0)fail("stop-wait");
    report_state(SERVICE_STOP_PENDING);report_state(SERVICE_STOPPED);CloseHandle(stop_event);
}
static SC_HANDLE manager(void) {SC_HANDLE m=OpenSCManagerW(NULL,NULL,SC_MANAGER_ALL_ACCESS);if(!m)fail("OpenSCManager");return m;}
static SC_HANDLE opened(SC_HANDLE m) {SC_HANDLE s=OpenServiceW(m,service_name,SERVICE_ALL_ACCESS);if(!s)fail("OpenService");return s;}
static int setup(const wchar_t *mode) {
    SC_HANDLE m=manager(),s=OpenServiceW(m,service_name,SERVICE_ALL_ACCESS);
    wchar_t command[1024];swprintf(command,1024,L"\"%ls\" /RunAsService %ls",service_image,mode);
    if(s) {
        SERVICE_STATUS current;ControlService(s,SERVICE_CONTROL_STOP,&current);
        for(unsigned i=0;i<100;i++){if(!QueryServiceStatus(s,&current))fail("QueryServiceStatus");if(current.dwCurrentState==SERVICE_STOPPED)break;Sleep(50);}
        if(!ChangeServiceConfigW(s,SERVICE_WIN32_OWN_PROCESS,SERVICE_DEMAND_START,SERVICE_ERROR_IGNORE,command,NULL,NULL,NULL,NULL,NULL,NULL))fail("ChangeServiceConfig");
    } else {
        if(GetLastError()!=ERROR_SERVICE_DOES_NOT_EXIST)fail("OpenService-setup");
        s=CreateServiceW(m,service_name,service_name,SERVICE_ALL_ACCESS,SERVICE_WIN32_OWN_PROCESS,SERVICE_DEMAND_START,SERVICE_ERROR_IGNORE,command,NULL,NULL,NULL,NULL,NULL);
        if(!s)fail("CreateService");
    }
    CloseServiceHandle(s);CloseServiceHandle(m);DeleteFileW(marker);return 0;
}
static int query(void) {
    SC_HANDLE m=manager(),s=opened(m);SERVICE_STATUS_PROCESS p;DWORD n;
    if(!QueryServiceStatusEx(s,SC_STATUS_PROCESS_INFO,(BYTE*)&p,sizeof(p),&n))fail("QueryServiceStatusEx");
    printf("[service-fixture] query-state=%lu pid=%lu exit=%lu\n",(unsigned long)p.dwCurrentState,(unsigned long)p.dwProcessId,(unsigned long)p.dwWin32ExitCode);
    CloseServiceHandle(s);CloseServiceHandle(m);return p.dwCurrentState==SERVICE_RUNNING?0:21;
}
static int query_image(void) {
    SC_HANDLE m=manager(),s=opened(m);SERVICE_STATUS_PROCESS p;DWORD n;
    if(!QueryServiceStatusEx(s,SC_STATUS_PROCESS_INFO,(BYTE*)&p,sizeof(p),&n))fail("QueryServiceStatusEx-image");
    if(p.dwCurrentState!=SERVICE_RUNNING||!p.dwProcessId){CloseServiceHandle(s);CloseServiceHandle(m);return 21;}
    HANDLE process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,p.dwProcessId);
    if(!process)fail("OpenProcess-image");
    wchar_t path[32768];DWORD length=32768;
    if(!QueryFullProcessImageNameW(process,0,path,&length)||!length||length>=32768)fail("QueryFullProcessImageName");
    wprintf(L"[service-fixture] query-image=%ls\n",path);
    CloseHandle(process);CloseServiceHandle(s);CloseServiceHandle(m);return 0;
}
static int stop(void) {
    SC_HANDLE m=manager(),s=opened(m);SERVICE_STATUS p;
    if(!ControlService(s,SERVICE_CONTROL_STOP,&p)&&GetLastError()!=ERROR_SERVICE_NOT_ACTIVE)fail("ControlService");
    for(unsigned i=0;i<100;i++){if(!QueryServiceStatus(s,&p))fail("Query-stop");if(p.dwCurrentState==SERVICE_STOPPED)break;Sleep(50);}
    printf("[service-fixture] stopped=%lu\n",(unsigned long)p.dwCurrentState);
    CloseServiceHandle(s);CloseServiceHandle(m);return p.dwCurrentState==SERVICE_STOPPED?0:22;
}
int wmain(int argc,wchar_t **argv) {
    const wchar_t *base=wcsrchr(argv[0],L'\\');base=base?base+1:argv[0];
    if(!_wcsicmp(base,L"steam.exe")) {
        unsigned plays=0,verifies=0,game_args=0;
        for(int i=1;i<argc;i++) {
            if(!wcscmp(argv[i],L"-applaunch")) {
                if(i+1>=argc||wcscmp(argv[i+1],L"730"))return 91;
                ++plays;
            }
            if(!wcsncmp(argv[i],L"steam://validate/",17)) {
                if(wcscmp(argv[i],L"steam://validate/730"))return 92;
                ++verifies;
            }
            if(!wcscmp(argv[i],L"-condebug")||wcsstr(argv[i],L"cs2.exe"))++game_args;
        }
        if(verifies) {
            if(verifies!=1||plays||game_args)return 93;
            mark(L"C:\\Fixture\\client-verify-requested.fixture");
            puts("[service-fixture] client-action=verify result=unobserved");
        }
        mark(L"C:\\Fixture\\client-started.fixture");puts("[service-fixture] client-entered=1 exit=43");return 43;
    }
    if(argc==2&&!wcscmp(argv[1],L"--anchor")) {
        HANDLE anchor=CreateEventW(NULL,TRUE,FALSE,L"Local\\MadeiraServiceIntegrationAnchor");
        if(!anchor)fail("anchor-create");
        mark(L"C:\\Fixture\\anchor-ready.fixture");
        DWORD wait=WaitForSingleObject(anchor,180000);CloseHandle(anchor);
        return wait==WAIT_OBJECT_0?0:90;
    }
    if(argc==2&&!wcscmp(argv[1],L"--anchor-stop")) {
        HANDLE anchor=OpenEventW(EVENT_MODIFY_STATE,FALSE,L"Local\\MadeiraServiceIntegrationAnchor");
        if(!anchor)fail("anchor-open");
        if(!SetEvent(anchor)){fail("anchor-stop");}CloseHandle(anchor);return 0;
    }
    if(argc==2&&!wcscmp(argv[1],L"--release-dispatcher")) {
        HANDLE gate=OpenEventW(EVENT_MODIFY_STATE,FALSE,dispatcher_gate);
        if(!gate)fail("dispatcher-gate-open");
        if(!SetEvent(gate))fail("dispatcher-gate-release");
        CloseHandle(gate);return 0;
    }
    if(argc>=3&&!wcscmp(argv[1],L"--setup"))return setup(argv[2]);
    if(argc==2&&!wcscmp(argv[1],L"--query"))return query();
    if(argc==2&&!wcscmp(argv[1],L"--query-image"))return query_image();
    if(argc==2&&!wcscmp(argv[1],L"--stop"))return stop();
    if(argc==2&&!wcscmp(argv[1],L"--pipe-enumeration")) {
        WIN32_FIND_DATAW data;HANDLE find=FindFirstFileW(L"\\\\.\\pipe\\*",&data);DWORD error=find==INVALID_HANDLE_VALUE?GetLastError():0;
        if(find!=INVALID_HANDLE_VALUE){FindClose(find);}printf("[service-fixture] pipe-enumeration-error=%lu\n",(unsigned long)error);return 0;
    }
    if(argc==2&&!wcscmp(argv[1],L"--update-child")) {Sleep(1200);mark(marker);return 0;}
    if(argc>=3&&!wcscmp(argv[1],L"/RunAsService")) {
        if(!wcscmp(argv[2],L"early-exit")) {puts("[service-fixture] exit-before-dispatcher=0");return 0;}
        if(!wcscmp(argv[2],L"gate-dispatcher")) {
            /* The captured Valve process stays alive before the SCM control
             * pipe connects. Hold that genuine protocol boundary explicitly:
             * no status or dispatcher result is fabricated by the fixture. */
            HANDLE gate=CreateEventW(NULL,TRUE,FALSE,dispatcher_gate);
            if(!gate)fail("dispatcher-gate-create");
            mark(L"C:\\Fixture\\before-dispatcher.fixture");
            if(WaitForSingleObject(gate,20000)!=WAIT_OBJECT_0)fail("dispatcher-gate-wait");
            CloseHandle(gate);
        }
        if(!wcscmp(argv[2],L"handoff")&&GetFileAttributesW(marker)==INVALID_FILE_ATTRIBUTES) {
            Sleep(700);wchar_t command[1024];swprintf(command,1024,L"\"%ls\" --update-child",updater_image);
            STARTUPINFOW si={0};PROCESS_INFORMATION pi={0};si.cb=sizeof(si);
            if(!CreateProcessW(updater_image,command,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi))fail("CreateUpdater");
            CloseHandle(pi.hThread);CloseHandle(pi.hProcess);Sleep(200);return 0;
        }
        SERVICE_TABLE_ENTRYW table[]={{(wchar_t*)service_name,service_main},{NULL,NULL}};
        if(!StartServiceCtrlDispatcherW(table)){fail("StartServiceCtrlDispatcher");}return 0;
    }
    fprintf(stderr,"[service-fixture] invalid-mode\n");return 89;
}
