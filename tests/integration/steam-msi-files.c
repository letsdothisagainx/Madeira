/* SPDX-License-Identifier: MIT
 * Owned integration fixture. Every NT/MSI result comes from real Windows APIs;
 * no service, installer, file operation or registry response is fabricated. */
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <msi.h>
#include <msiquery.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#define REQUIRE(test) do { if (!(test)) { fprintf(stderr,"[msi-files] failed line=%u winerr=%lu\n",__LINE__,GetLastError()); ExitProcess(90); } } while (0)
#define COUNT(a) (sizeof(a)/sizeof((a)[0]))
typedef NTSTATUS (NTAPI *create_file_fn)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,
                                       PLARGE_INTEGER,ULONG,ULONG,ULONG,ULONG,PVOID,ULONG);

static NTSTATUS native_create(const WCHAR *path,HANDLE *result,IO_STATUS_BLOCK *io)
{
    WCHAR name[32768];
    REQUIRE(swprintf(name,COUNT(name),L"\\??\\%ls",path)>0);
    UNICODE_STRING string={(USHORT)(wcslen(name)*sizeof(WCHAR)),(USHORT)((wcslen(name)+1)*sizeof(WCHAR)),name};
    OBJECT_ATTRIBUTES attributes={sizeof(attributes),NULL,&string,0x40,NULL,NULL};
    create_file_fn create=(create_file_fn)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtCreateFile");
    REQUIRE(create!=NULL);
    *result=NULL;ZeroMemory(io,sizeof(*io));
    return create(result,GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE|FILE_READ_ATTRIBUTES,
                  &attributes,io,NULL,FILE_ATTRIBUTE_NORMAL,0,5,0x60,NULL,0);
}

static void architecture(void)
{
    BOOL wow=FALSE;WCHAR system[MAX_PATH],windows[MAX_PATH];
    REQUIRE(IsWow64Process(GetCurrentProcess(),&wow));
    REQUIRE(GetSystemDirectoryW(system,COUNT(system)) && GetWindowsDirectoryW(windows,COUNT(windows)));
    printf("[msi-files] architecture bits=%u wow64=%u system=%ls windows=%ls\n",
           (unsigned)(sizeof(void *)*8),(unsigned)wow,system,windows);
}

struct rollback_observer { const WCHAR *target,*checkpoint; unsigned seen; };
static UINT CALLBACK observe_install(void *context,UINT message_type,const WCHAR *message)
{
    struct rollback_observer *observer=context;
    if((message_type&0xff000000u)==INSTALLMESSAGE_ACTIONSTART && wcsstr(message,L"FailOwnedFixture")){
        REQUIRE(CopyFileW(observer->target,observer->checkpoint,FALSE));
        ++observer->seen;
    }
    return 0; /* Observational only: normal MSI handling decides every result. */
}

static void build_package(const WCHAR *package,const WCHAR *folder,const WCHAR *platform,const WCHAR *package_id)
{
    static const WCHAR *tables[]={L"Directory",L"Component",L"Feature",L"FeatureComponents",L"File",
        L"Media",L"Property",L"InstallExecuteSequence",L"CustomAction"};
    MSIHANDLE db=0,summary=0,view=0,record=0;WCHAR file[MAX_PATH],cab[MAX_PATH];
    REQUIRE(MsiOpenDatabaseW(package,MSIDBOPEN_CREATE,&db)==ERROR_SUCCESS);
    for(unsigned i=0;i<COUNT(tables);++i){
        REQUIRE(swprintf(file,COUNT(file),L"%ls.idt",tables[i])>0);
        UINT status=MsiDatabaseImportW(db,folder,file);
        if(status)fwprintf(stderr,L"[msi-files] table=%ls status=%u\n",tables[i],status);
        REQUIRE(status==ERROR_SUCCESS);
    }
    REQUIRE(MsiGetSummaryInformationW(db,NULL,6,&summary)==ERROR_SUCCESS);
    REQUIRE(MsiSummaryInfoSetPropertyW(summary,7,VT_LPSTR,0,NULL,platform)==ERROR_SUCCESS);
    REQUIRE(MsiSummaryInfoSetPropertyW(summary,9,VT_LPSTR,0,NULL,package_id)==ERROR_SUCCESS);
    REQUIRE(MsiSummaryInfoSetPropertyW(summary,14,VT_I4,200,NULL,NULL)==ERROR_SUCCESS);
    REQUIRE(MsiSummaryInfoSetPropertyW(summary,15,VT_I4,2,NULL,NULL)==ERROR_SUCCESS);
    REQUIRE(MsiSummaryInfoPersist(summary)==ERROR_SUCCESS);MsiCloseHandle(summary);
    REQUIRE(MsiDatabaseOpenViewW(db,L"INSERT INTO `_Streams` (`Name`, `Data`) VALUES (?, ?)",&view)==ERROR_SUCCESS);
    record=MsiCreateRecord(2);REQUIRE(record!=0);
    REQUIRE(MsiRecordSetStringW(record,1,L"cab1.cab")==ERROR_SUCCESS);
    REQUIRE(swprintf(cab,COUNT(cab),L"%ls\\cab1.cab",folder)>0);
    REQUIRE(MsiRecordSetStreamW(record,2,cab)==ERROR_SUCCESS);
    REQUIRE(MsiViewExecute(view,record)==ERROR_SUCCESS);
    MsiCloseHandle(record);MsiCloseHandle(view);
    REQUIRE(MsiDatabaseCommit(db)==ERROR_SUCCESS);MsiCloseHandle(db);
    puts("[msi-files] genuine-database-and-embedded-mszip-cabinet=created");
}

int wmain(int argc,WCHAR **argv)
{
    architecture();
    REQUIRE(argc>=2);
    if(!wcscmp(argv[1],L"--build")){
        REQUIRE(argc==6);build_package(argv[2],argv[3],argv[4],argv[5]);return 0;
    }
    if(!wcscmp(argv[1],L"--native-create")){
        REQUIRE(argc==4);HANDLE handle;IO_STATUS_BLOCK io;
        NTSTATUS status=native_create(argv[2],&handle,&io);
        unsigned long expected=wcstoul(argv[3],NULL,16);
        printf("[msi-files] native-create disposition=5 access=c0100080 sharing=0 options=60 status=%08lx information=%llu handle=%s\n",
               (unsigned long)status,(unsigned long long)io.Information,handle?"present":"null");
        REQUIRE((ULONG)status==(ULONG)expected);
        if(!status){REQUIRE(handle!=NULL);REQUIRE(CloseHandle(handle));}else REQUIRE(handle==NULL);
        return 0;
    }
    if(!wcscmp(argv[1],L"--sharing")){
        REQUIRE(argc==3);HANDLE held=CreateFileW(argv[2],GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
        REQUIRE(held!=INVALID_HANDLE_VALUE);HANDLE other;IO_STATUS_BLOCK io;
        NTSTATUS status=native_create(argv[2],&other,&io);
        printf("[msi-files] actual-exclusive-share-conflict status=%08lx\n",(unsigned long)status);
        REQUIRE((ULONG)status==0xc0000043u && other==NULL);REQUIRE(CloseHandle(held));return 0;
    }
    if(!wcscmp(argv[1],L"--install")){
        REQUIRE(argc==5 || argc==7);MsiSetInternalUI(INSTALLUILEVEL_NONE,NULL);
        struct rollback_observer observer={argc==7?argv[5]:NULL,argc==7?argv[6]:NULL,0};
        if(argc==7)MsiSetExternalUIW(observe_install,INSTALLLOGMODE_ACTIONSTART,&observer);
        WCHAR logfile[MAX_PATH];REQUIRE(swprintf(logfile,COUNT(logfile),L"%ls.log",argv[2])>0);
        REQUIRE(MsiEnableLogW(INSTALLLOGMODE_VERBOSE|INSTALLLOGMODE_ERROR|INSTALLLOGMODE_ACTIONSTART|INSTALLLOGMODE_ACTIONDATA,logfile,0)==ERROR_SUCCESS);
        UINT result=MsiInstallProductW(argv[2],argv[3]);
        printf("[msi-files] genuine-MsiInstallProduct result=%u\n",result);
        REQUIRE(result==wcstoul(argv[4],NULL,10));
        if(argc==7){REQUIRE(observer.seen==1);puts("[msi-files] rollback-checkpoint actual-installed-bytes-observed-before-error=1");}
        return 0;
    }
    if(!wcscmp(argv[1],L"--state")){
        REQUIRE(argc==4);INSTALLSTATE state=MsiQueryProductStateW(argv[2]);
        printf("[msi-files] genuine-product-state=%d\n",state);
        REQUIRE((int)state==wcstol(argv[3],NULL,10));return 0;
    }
    if(!wcscmp(argv[1],L"--uninstall")){
        REQUIRE(argc==3);MsiSetInternalUI(INSTALLUILEVEL_NONE,NULL);
        UINT result=MsiConfigureProductExW(argv[2],INSTALLLEVEL_DEFAULT,INSTALLSTATE_ABSENT,L"REMOVE=ALL");
        printf("[msi-files] genuine-MsiConfigureProduct-uninstall result=%u\n",result);
        REQUIRE(result==ERROR_SUCCESS);return 0;
    }
    REQUIRE(0);return 1;
}
