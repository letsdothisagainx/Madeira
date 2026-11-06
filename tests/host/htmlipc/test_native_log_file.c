/* SPDX-License-Identifier: MIT
 * Actual staged Wine NtCreateFile with explicitly scoped POSIX file adapters.
 * The fixtures never touch an installed Wine prefix or real Steam files. */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "htmlipc_log_file.h"
#define WINAPI
#define FALSE 0
#define TRUE 1
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
typedef uint16_t WCHAR;typedef uint32_t ULONG,ACCESS_MASK;typedef uintptr_t ULONG_PTR;typedef int32_t NTSTATUS;
typedef int BOOL;typedef void *HANDLE;
typedef struct {uint64_t QuadPart;} LARGE_INTEGER;
typedef struct {uint16_t Length,MaximumLength;WCHAR *Buffer;} UNICODE_STRING;
typedef struct {ULONG Length;HANDLE RootDirectory;UNICODE_STRING *ObjectName;ULONG Attributes;void *SecurityDescriptor,*SecurityQualityOfService;} OBJECT_ATTRIBUTES;
typedef struct {union {NTSTATUS Status;void *Pointer;};ULONG_PTR Information;} IO_STATUS_BLOCK;
/* Native64 field offsets used by the real iOS Unix layer. The distinct
 * guest32 PEB is not read or base-adjusted by this handler. */
typedef struct {unsigned char reserved[0x60];UNICODE_STRING ImagePathName;} RTL_USER_PROCESS_PARAMETERS;
typedef struct {unsigned char reserved[0x20];RTL_USER_PROCESS_PARAMETERS *ProcessParameters;} PEB;
typedef struct {unsigned char reserved[0x60];PEB *Peb;} TEB;
_Static_assert(offsetof(RTL_USER_PROCESS_PARAMETERS,ImagePathName)==0x60,"native params layout");
_Static_assert(offsetof(PEB,ProcessParameters)==0x20,"native PEB layout");
_Static_assert(offsetof(TEB,Peb)==0x60,"native TEB layout");
#define STATUS_SUCCESS 0
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000d)
#define STATUS_NO_SUCH_FILE ((NTSTATUS)0xc000000f)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xc0000022)
#define STATUS_OBJECT_NAME_INVALID ((NTSTATUS)0xc0000033)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xc0000034)
#define STATUS_OBJECT_PATH_NOT_FOUND ((NTSTATUS)0xc000003a)
#define STATUS_OBJECT_NAME_COLLISION ((NTSTATUS)0xc0000035)
#define STATUS_BAD_DEVICE_TYPE ((NTSTATUS)0xc00000cb)
#define STATUS_TOO_MANY_OPENED_FILES ((NTSTATUS)0xc000011f)
#define FILE_SUPERSEDE 0
#define FILE_OPEN 1
#define FILE_CREATE 2
#define FILE_OPEN_IF 3
#define FILE_OVERWRITE 4
#define FILE_OVERWRITE_IF 5
#define FILE_SUPERSEDED 0
#define FILE_OPENED 1
#define FILE_CREATED 2
#define FILE_OVERWRITTEN 3
#define FILE_DIRECTORY_FILE 1
#define FILE_SYNCHRONOUS_IO_NONALERT 0x20
#define FILE_NON_DIRECTORY_FILE 0x40
#define FILE_OPEN_BY_FILE_ID 0x2000
#define FILE_OPEN_REPARSE_POINT 0x200000
#define FILE_READ_DATA 1
#define FILE_WRITE_DATA 2
#define FILE_APPEND_DATA 4
#define GENERIC_WRITE 0x40000000u
#define XATTR_ATTRIBS_MASK 0x27
#define SAMBA_XATTR_DOS_ATTRIB "user.DOSATTRIB"
#define TRACE(...) ((void)0)
#define FIXME(...) ((void)0)
#define WARN(...) ((void)0)
static void ignored_log(const char *format,...){(void)format;}
#define ERR_(channel) ignored_log
static PEB peb;static TEB teb={.Peb=&peb};static RTL_USER_PROCESS_PARAMETERS parameters;
static char drive[4096];static unsigned opens,resolves;static ULONG last_sharing,last_options,last_disposition;
static TEB *NtCurrentTeb(void){return &teb;}
static size_t wide(WCHAR *out,size_t capacity,const char *input)
{size_t n=strlen(input);assert(n<capacity);for(size_t i=0;i<=n;++i)out[i]=(unsigned char)input[i];return n;}
static UNICODE_STRING string(WCHAR *buffer,size_t capacity,const char *input)
{size_t n=wide(buffer,capacity,input);UNICODE_STRING result={(uint16_t)(n*2),(uint16_t)((n+1)*2),buffer};return result;}
static unsigned get_nt_and_unix_names(OBJECT_ATTRIBUTES *attr,UNICODE_STRING *nt_name,char **unix_name,ULONG disposition,BOOL reparse)
{
    static const char prefix[]="\\??\\C:\\";char text[32768];size_t n;
    ++resolves;memset(nt_name,0,sizeof(*nt_name));*unix_name=NULL;
    if(!attr||!attr->ObjectName||!attr->ObjectName->Buffer||(attr->ObjectName->Length&1))return STATUS_OBJECT_NAME_INVALID;
    n=attr->ObjectName->Length/2;if(n>=sizeof(text))return STATUS_OBJECT_NAME_INVALID;
    for(size_t i=0;i<n;++i){WCHAR c=attr->ObjectName->Buffer[i];if(c<32||c>126)return STATUS_OBJECT_NAME_INVALID;text[i]=(char)c;}text[n]=0;
    if(attr->RootDirectory||n<sizeof(prefix)-1||memcmp(text,prefix,sizeof(prefix)-1))return STATUS_BAD_DEVICE_TYPE;
    /* This is only a deterministic C-drive resolver adapter. The real Wine
     * namespace, object manager, case lookup and reparse resolver are not used. */
    for(size_t i=sizeof(prefix)-1;i<n;++i)if(text[i]=='\\')text[i]='/';
    const char *relative=text+sizeof(prefix)-1;
    if(strstr(relative,"../")||strstr(relative,"/..")||strchr(relative,':'))return STATUS_OBJECT_NAME_INVALID;
    size_t bytes=strlen(drive)+1+strlen(relative)+1;*unix_name=malloc(bytes);assert(*unix_name);
    assert(snprintf(*unix_name,bytes,"%s/%s",drive,relative)>0);
    nt_name->Buffer=malloc((n+1)*2);assert(nt_name->Buffer);memcpy(nt_name->Buffer,attr->ObjectName->Buffer,n*2);nt_name->Buffer[n]=0;
    nt_name->Length=n*2;nt_name->MaximumLength=(n+1)*2;
    struct stat st;if(!lstat(*unix_name,&st))return disposition==FILE_CREATE?STATUS_OBJECT_NAME_COLLISION:STATUS_SUCCESS;
    if(errno!=ENOENT)return STATUS_ACCESS_DENIED;
    return disposition==FILE_OPEN||disposition==FILE_OVERWRITE?STATUS_OBJECT_NAME_NOT_FOUND:STATUS_NO_SUCH_FILE;
}
static unsigned file_id_to_unix_file_name(OBJECT_ATTRIBUTES *attr,char **unix_name,UNICODE_STRING *nt_name)
{*unix_name=NULL;memset(nt_name,0,sizeof(*nt_name));return STATUS_INVALID_PARAMETER;}
static unsigned server_open_file_object(HANDLE *handle,ACCESS_MASK access,OBJECT_ATTRIBUTES *attr,ULONG sharing,ULONG options)
{return STATUS_BAD_DEVICE_TYPE;}
static BOOL is_hidden_file(const char *path){const char *p=strrchr(path,'/');return p&&p[1]=='.';}
static unsigned open_unix_file(HANDLE *handle,const char *path,ACCESS_MASK access,OBJECT_ATTRIBUTES *attr,ULONG attributes,
    ULONG sharing,ULONG disposition,ULONG options,void *ea_buffer,ULONG ea_length)
{
    int flags=(access&(GENERIC_WRITE|FILE_WRITE_DATA|FILE_APPEND_DATA))?O_WRONLY:O_RDONLY;
    ++opens;last_sharing=sharing;last_options=options;last_disposition=disposition;
    if(disposition==FILE_CREATE)flags|=O_CREAT|O_EXCL;
    if(disposition==FILE_OPEN_IF)flags|=O_CREAT;
    if(disposition==FILE_OVERWRITE||disposition==FILE_OVERWRITE_IF||disposition==FILE_SUPERSEDE)flags|=O_TRUNC;
    if(disposition==FILE_OVERWRITE_IF||disposition==FILE_SUPERSEDE)flags|=O_CREAT;
    if(options&FILE_DIRECTORY_FILE)flags|=O_DIRECTORY;
    int fd=open(path,flags,0600);
    if(fd<0)return errno==EMFILE?STATUS_TOO_MANY_OPENED_FILES:STATUS_ACCESS_DENIED;
    *handle=(void*)(uintptr_t)(fd+1);return STATUS_SUCCESS;
}
static unsigned server_get_unix_fd(HANDLE handle,unsigned access,int *fd,int *close_fd,void *type,void *options)
{*fd=(int)(uintptr_t)handle-1;*close_fd=0;return 0;}
static int fd_set_dos_attrib(int fd,ULONG attributes,BOOL created){return 0;}
/*production-native-file-bodies*/
static void append(HANDLE handle)
{static const char bytes[]="helper executable log fixture\n";int fd=(int)(uintptr_t)handle-1;assert(lseek(fd,0,SEEK_END)>=0);assert(write(fd,bytes,sizeof(bytes)-1)==sizeof(bytes)-1);assert(!close(fd));}
static void selected(const char *image,const char *cache,const char *helper)
{
    static WCHAR image_buffer[32768];parameters.ImagePathName=string(image_buffer,ARRAY_SIZE(image_buffer),image);
    peb.ProcessParameters=&parameters;assert(!setenv("MADEIRA_HTMLIPC_HELPER",helper,1));assert(!setenv("MADEIRA_HTMLIPC_CACHE_DIR",cache,1));
}
static NTSTATUS create(const char *request,ULONG disposition,int baseline,IO_STATUS_BLOCK *io,HANDLE *handle)
{
    WCHAR buffer[32768];UNICODE_STRING name=string(buffer,ARRAY_SIZE(buffer),request);
    OBJECT_ATTRIBUTES attr={sizeof(attr),NULL,&name,0x40,NULL,NULL};memset(io,0,sizeof(*io));
    if(baseline)return BaselineNtCreateFile(handle,GENERIC_WRITE,&attr,io,NULL,0,3,disposition,FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE,NULL,0);
    return NtCreateFile(handle,GENERIC_WRITE,&attr,io,NULL,0,3,disposition,FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE,NULL,0);
}
static void drive_from_log(const char *log)
{
    static const char suffix[]="/windows/madeira-compat/SteamBrowserLogs/debug.log";size_t n=strlen(log),s=sizeof(suffix)-1;
    assert(n>s&&!strcmp(log+n-s,suffix)&&n-s<sizeof(drive));memcpy(drive,log,n-s);drive[n-s]=0;
}
int main(int argc,char **argv)
{
    if(argc>=5&&argc<=6&&!strcmp(argv[1],"write")){
        const char *log=getenv("MADEIRA_TEST_HOST_LOG");if(!log)return 2;drive_from_log(log);
        selected(argv[3],argv[4],argc==6?argv[5]:argv[3]);IO_STATUS_BLOCK io;HANDLE handle=NULL;
        NTSTATUS status=create(argv[2],FILE_OPEN_IF,0,&io,&handle);
        if(status||io.Status||!handle)return 3;append(handle);return 0;
    }
    assert(argc==1);
    char temporary[]="/tmp/madeira-native-log-XXXXXX";assert(mkdtemp(temporary));
    char cache_host[4096],mutable_host[4096],marker[4096],log[4096],old[4096],sentinel[4096],command[8192];
    assert(snprintf(drive,sizeof(drive),"%s/drive_c",temporary)>0);
    const char *cache="C:\\windows\\madeira-compat\\SteamBrowserRuntime\\fixture-log-v1\\bin\\cef\\cef.win7";
    const char *helper="C:\\windows\\madeira-compat\\SteamBrowserRuntime\\fixture-log-v1\\bin\\cef\\cef.win7\\steamwebhelper.exe";
    const char *request="\\??\\C:\\windows\\madeira-compat\\SteamBrowserRuntime\\fixture-log-v1\\bin\\cef\\cef.win7\\debug.log";
    assert(snprintf(cache_host,sizeof(cache_host),"%s/windows/madeira-compat/SteamBrowserRuntime/fixture-log-v1/bin/cef/cef.win7",drive)>0);
    assert(snprintf(mutable_host,sizeof(mutable_host),"%s/windows/madeira-compat/SteamBrowserLogs",drive)>0);
    assert(snprintf(command,sizeof(command),"mkdir -p '%s' '%s'",cache_host,mutable_host)>0);assert(system(command)==0);
    assert(snprintf(marker,sizeof(marker),"%s/%s",mutable_host,MADEIRA_HTMLIPC_LOG_OWNER)>0);
    assert(snprintf(log,sizeof(log),"%s/debug.log",mutable_host)>0);assert(snprintf(old,sizeof(old),"%s/debug.log",cache_host)>0);
    int fd=open(marker,O_CREAT|O_WRONLY|O_EXCL,0600);assert(fd>=0);assert(write(fd,MADEIRA_HTMLIPC_LOG_OWNER_BYTES,sizeof(MADEIRA_HTMLIPC_LOG_OWNER_BYTES)-1)==sizeof(MADEIRA_HTMLIPC_LOG_OWNER_BYTES)-1);assert(!close(fd));
    selected(helper,cache,helper);IO_STATUS_BLOCK io;HANDLE handle=NULL;
    assert(create(request,FILE_OPEN_IF,1,&io,&handle)==0&&io.Status==0&&io.Information==FILE_CREATED);append(handle);
    assert(!access(old,F_OK)&&access(log,F_OK));assert(!unlink(old));
    for(unsigned i=0;i<2;++i){
        assert(create(request,FILE_OPEN_IF,0,&io,&handle)==0&&io.Status==0&&io.Information==(i?FILE_OPENED:FILE_CREATED));append(handle);
        assert(access(old,F_OK)&&!access(log,F_OK)&&last_sharing==3&&last_options==(FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE)&&last_disposition==FILE_OPEN_IF);
    }
    unsigned previous=opens;assert(!unlink(marker));
    assert(create(request,FILE_OPEN_IF,0,&io,&handle)==STATUS_ACCESS_DENIED&&io.Status==STATUS_ACCESS_DENIED&&!handle&&opens==previous&&access(old,F_OK));
    fd=open(marker,O_CREAT|O_WRONLY|O_EXCL,0600);assert(fd>=0);assert(write(fd,MADEIRA_HTMLIPC_LOG_OWNER_BYTES,sizeof(MADEIRA_HTMLIPC_LOG_OWNER_BYTES)-1)==sizeof(MADEIRA_HTMLIPC_LOG_OWNER_BYTES)-1);close(fd);
    assert(snprintf(sentinel,sizeof(sentinel),"%s/keep",drive)>0);fd=open(sentinel,O_CREAT|O_WRONLY|O_EXCL,0600);assert(fd>=0);assert(write(fd,"keep",4)==4);close(fd);
    assert(!unlink(log)&&!symlink(sentinel,log));
    assert(create(request,FILE_OPEN_IF,0,&io,&handle)==STATUS_ACCESS_DENIED&&!handle&&opens==previous&&access(old,F_OK));assert(!unlink(log));
    assert(!link(sentinel,log));assert(create(request,FILE_OPEN_IF,0,&io,&handle)==STATUS_ACCESS_DENIED&&!handle&&opens==previous);assert(!unlink(log));
    fd=open(sentinel,O_RDONLY);assert(fd>=0);char kept[4];assert(read(fd,kept,4)==4&&!memcmp(kept,"keep",4));close(fd);
    selected("C:\\other\\steamwebhelper.exe",cache,helper);
    assert(create(request,FILE_OPEN,0,&io,&handle)==STATUS_OBJECT_NAME_NOT_FOUND&&!handle&&opens==previous&&access(old,F_OK));
    selected(helper,cache,helper);peb.ProcessParameters=NULL;
    assert(create(request,FILE_OPEN,0,&io,&handle)==STATUS_OBJECT_NAME_NOT_FOUND&&!handle&&opens==previous&&access(old,F_OK));
    assert(resolves>=8);assert(!unlink(sentinel)&&!unlink(marker));
    assert(snprintf(command,sizeof(command),"rm -rf '%s'",temporary)>0);assert(system(command)==0);
    puts("PASS actual staged NtCreateFile: baseline cache contamination, native PEB/env admission, real create/reuse/append, IOSB/disposition/flags, denied unowned/symlink/hardlink output without fallback; POSIX backend adapters only");
}
