/* SPDX-License-Identifier: MIT. Guest AMD64 WINAPI only; no cross-ISA calls. */
#include "fixture_args.h"
using namespace madeira_cef_fixture;
#define IMPORT __declspec(dllimport)
#define EXPORT __declspec(dllexport)
#if !defined(_WIN64) || !(defined(_M_X64) || defined(__x86_64__))
#error "This fixture is only for guest Windows AMD64 under stock Wine"
#endif
struct SecurityAttributes;struct StartupInfoW;struct ProcessInformation;
/* WINAPI on AMD64 is the standard Microsoft x64 ABI (RCX,RDX,R8,R9, then
 * stack arguments + shadow space). BOOL is signed 32-bit; DWORD is U32;
 * handles/environment and all structures remain opaque pointer arguments. */
using CreateProcess= int (*)(const U16 *,U16 *,SecurityAttributes *,SecurityAttributes *,int,U32,
                            void *,const U16 *,StartupInfoW *,ProcessInformation *);
struct Mbi {void *base,*allocation;U32 allocation_protect;U16 partition,pad;Size size;U32 state,protect,type,padding;};
static_assert(sizeof(Mbi)==48&&sizeof(int)==4&&sizeof(void*)==8&&sizeof(U16)==2);
struct UnicodeString {U16 length,maximum;U32 pad;const U16 *buffer;};
struct Notification {U32 flags,pad;const UnicodeString *full,*base;void *module;U32 image_size,padding;};
using Notify=void (*)(U32,const Notification *,void *);
using Register=int (*)(U32,Notify,void *,void **);
extern "C" {
IMPORT void *GetModuleHandleW(const U16 *);
IMPORT int GetModuleHandleExW(U32,const U16 *,void **);
IMPORT void *GetProcAddress(void *,const char *);
IMPORT U32 GetModuleFileNameW(void *,U16 *,U32);
IMPORT U32 GetEnvironmentVariableW(const U16 *,U16 *,U32);
IMPORT U32 GetFullPathNameW(const U16 *,U32,U16 *,U16 **);
IMPORT U32 GetLastError();IMPORT void SetLastError(U32);
IMPORT Size VirtualQuery(const void *,Mbi *,Size);
IMPORT int VirtualProtect(void *,Size,U32,U32 *);
IMPORT int DisableThreadLibraryCalls(void *);
IMPORT void *GetProcessHeap();IMPORT void *HeapAlloc(void *,U32,Size);IMPORT int HeapFree(void *,U32,void *);
IMPORT void *CreateFileW(const U16 *,U32,U32,void *,U32,U32,void *);
IMPORT int GetFileSizeEx(void *,long long *);IMPORT int ReadFile(void *,void *,U32,U32 *,void *);IMPORT int CloseHandle(void *);
IMPORT void OutputDebugStringA(const char *);
}
#if defined(MADEIRA_CEF_ARGS_TEST_ONLY)
#include "fixture_pin.h" /* Generated only from an explicit SHA-verified input. */
namespace {
static Installer state;
static CreateProcess original;
static U16 root[32768],tier0_path[32768];
static Size root_length;
static void *notification_cookie,*pinned_file_handle;
static U32 transformed,forwarded;
static bool jitless=true;
static U32 cdp_port;
static U16 lower(U16 c){if(c>='A'&&c<='Z')return c+32;return c=='/'?'\\':c;}
static Size length(const U16 *s,Size cap){Size n=0;while(s&&n<cap&&s[n])++n;return n;}
static bool same(const U16 *a,const U16 *b,Size n){for(Size i=0;i<n;++i)if(lower(a[i])!=lower(b[i]))return false;return true;}
static bool basename(const U16 *path,Size n,const char *name){Size first=0;for(Size i=0;i<n;++i)if(path[i]=='/'||path[i]=='\\')first=i+1;
    Size j=0;for(;name[j];++j)if(first+j>=n||lower(path[first+j])!=U16(name[j]))return false;return first+j==n;}
static bool query(void *,const void *p,Region *r){Mbi m{};if(VirtualQuery(p,&m,sizeof(m))!=sizeof(m))return false;
    *r={m.base,m.allocation,m.size,m.state,m.protect,m.type};return true;}
static bool protect(void *,void *p,Size n,U32 f,U32 *old){return VirtualProtect(p,n,f,old)!=0;}
static U32 last_error(void *){return GetLastError();}
static bool helper_path(const U16 *app,const U16 *command,U16 *image,Size &n){
    U16 *parsed=image+32768;const U16 *input=app;
    if(!input){
        if(!command)return false;Size at=0,o=0;while(command[at]==' '||command[at]=='\t')++at;
        if(command[at]=='"'){++at;while(command[at]&&command[at]!='"'&&o<32767)parsed[o++]=command[at++];
            if(command[at]!='"'||(command[at+1]&&command[at+1]!=' '&&command[at+1]!='\t'))return false;}
        else while(command[at]&&command[at]!=' '&&command[at]!='\t'&&o<32767){if(command[at]=='"')return false;parsed[o++]=command[at++];}
        if(!o||o==32767)return false;parsed[o]=0;input=parsed;
    }
    Size input_length=length(input,32768);if(input_length==32768||!basename(input,input_length,"steamwebhelper.exe"))return false;
    U32 count=GetFullPathNameW(input,32768,image,nullptr);if(!count||count>=32768)return false;n=count;
    return n>root_length&&same(image,root,root_length)&&basename(image,n,"steamwebhelper.exe");
}
extern "C" int MadeiraCefFixtureCreateProcessW(const U16 *app,U16 *line,SecurityAttributes *process,
    SecurityAttributes *thread,int inherit,U32 flags,void *environment,const U16 *directory,
    StartupInfoW *startup,ProcessInformation *information){
    U32 before=GetLastError();U16 *replacement=nullptr;
    U16 *image=static_cast<U16*>(HeapAlloc(GetProcessHeap(),0,65536*sizeof(U16)));Size image_length=0;
    if(image&&helper_path(app,line,image,image_length)){
        Size n=length(line,32768);
        if(line&&n<32767){replacement=static_cast<U16*>(HeapAlloc(GetProcessHeap(),0,32767*sizeof(U16)));
            if(replacement&&browser_args(image,image_length,line,n,jitless,replacement,32767,cdp_port)<0){HeapFree(GetProcessHeap(),0,replacement);replacement=nullptr;}}
    }
    if(image)HeapFree(GetProcessHeap(),0,image);
    if(replacement){__atomic_fetch_add(&transformed,1u,__ATOMIC_RELAXED);
        OutputDebugStringA("MADEIRA_CEF_ARGS browser-native-flags applied; BRP unchanged");}
    else __atomic_fetch_add(&forwarded,1u,__ATOMIC_RELAXED);
    /* Restore the incoming error BEFORE the genuine call. Its BOOL and outgoing
     * error survive every fixture cleanup call, on success and on failure. */
    SetLastError(before);
    int result=original(app,replacement?replacement:line,process,thread,inherit,flags,environment,directory,startup,information);
    U32 after=GetLastError();if(replacement)HeapFree(GetProcessHeap(),0,replacement);SetLastError(after);return result;
}
static void try_install(){
    if(!state.armed||state.installed)return;
    auto *module=GetModuleHandleW(reinterpret_cast<const U16*>(L"tier0_s64.dll"));if(!module)return;
    static U16 path[32768];U32 n=GetModuleFileNameW(module,path,32768);Size expected=length(tier0_path,32768);
    if(!n||n>=32768||n!=expected||!same(path,tier0_path,n))return;
    /* DLL notifications precede dynamic linking. Wait for an actually resolved
     * ordinary import and retry on later notifications; never replace a thunk. */
    Region slot{};auto *address=static_cast<U8*>(module)+state.slot_rva;
    if(!query(nullptr,address,&slot)||slot.allocation!=module||slot.type!=0x1000000||slot.state!=0x1000||slot.protect!=2||
       *reinterpret_cast<void **>(address)!=reinterpret_cast<void*>(original))return;
    void *caller_owner=nullptr;
    if(!GetModuleHandleExW(5,reinterpret_cast<const U16*>(module),&caller_owner)||caller_owner!=module)return;
    Result result=install(&state,module);
    if(result.error==Error::None)OutputDebugStringA("MADEIRA_CEF_ARGS exact tier0 CreateProcessW IAT installed R-RW-R");
    else OutputDebugStringA("MADEIRA_CEF_ARGS install rejected; inspect MadeiraCefFixtureStatus");
}
static void notification(U32 reason,const Notification *,void *){if(reason==1)try_install();}
static bool prepare(void *self){
    U16 token[128];U32 token_length=GetEnvironmentVariableW(reinterpret_cast<const U16*>(L"MADEIRA_CEF_ARGS_TEST_TOKEN"),token,128);
    if(token_length!=sizeof(fixture_test_token)-1)return false;
    for(Size i=0;i<sizeof(fixture_test_token)-1;++i)if(token[i]!=U16(fixture_test_token[i]))return false;
    U32 n=GetModuleFileNameW(nullptr,root,32768);if(!n||n>=32768||!basename(root,n,"steam.exe"))return false;
    root_length=n;while(root_length&&root[root_length-1]!='/'&&root[root_length-1]!='\\')--root_length;
    if(!root_length||root_length+14>=32768)return false;
    for(Size i=0;i<root_length;++i)tier0_path[i]=root[i];static constexpr char leaf[]="tier0_s64.dll";
    for(Size i=0;i<sizeof(leaf);++i)tier0_path[root_length+i]=U16(leaf[i]);
    void *file=CreateFileW(tier0_path,0x80000000,1,nullptr,3,0x80,nullptr);
    if(file==reinterpret_cast<void*>(~Size(0)))return false;
    long long size=0;U8 *bytes=nullptr;U32 read=0;
    if(GetFileSizeEx(file,&size)&&size==fixture_file_size)bytes=static_cast<U8*>(HeapAlloc(GetProcessHeap(),0,Size(size)));
    if(!bytes||!ReadFile(file,bytes,U32(size),&read,nullptr)||read!=U32(size)){
        if(bytes)HeapFree(GetProcessHeap(),0,bytes);CloseHandle(file);return false;}
    auto *kernel=GetModuleHandleW(reinterpret_cast<const U16*>(L"kernel32.dll"));
    auto *kernelbase=GetModuleHandleW(reinterpret_cast<const U16*>(L"kernelbase.dll"));
    original=kernel?reinterpret_cast<CreateProcess>(GetProcAddress(kernel,"CreateProcessW")):nullptr;
    void *genuine_owner=nullptr,*hook_owner=nullptr;
    if(!original||!GetModuleHandleExW(5,reinterpret_cast<const U16*>(original),&genuine_owner)||
       (genuine_owner!=kernel&&genuine_owner!=kernelbase)||
       !GetModuleHandleExW(5,reinterpret_cast<const U16*>(MadeiraCefFixtureCreateProcessW),&hook_owner)||hook_owner!=self){
        HeapFree(GetProcessHeap(),0,bytes);CloseHandle(file);return false;}
    Config config{};config.file=bytes;config.file_size=Size(size);config.hook_module=self;
    config.hook=reinterpret_cast<void*>(MadeiraCefFixtureCreateProcessW);config.genuine_create_process=reinterpret_cast<void*>(original);
    config.genuine_module=genuine_owner;for(Size i=0;i<32;++i)config.sha256[i]=fixture_sha256[i];
    Api api{nullptr,query,protect,last_error};Result result=arm(&state,config,api);
    if(result.error!=Error::None){HeapFree(GetProcessHeap(),0,bytes);CloseHandle(file);return false;}
    pinned_file_handle=file;static U16 mode[32768];
    U32 count=GetEnvironmentVariableW(reinterpret_cast<const U16*>(L"MADEIRA_JITLESS"),mode,32768);
    jitless=!(count&&count<32768&&mode[0]=='0');
    U16 port[8];U32 port_count=GetEnvironmentVariableW(reinterpret_cast<const U16*>(L"MADEIRA_CEF_FIXTURE_CDP_PORT"),port,8);
    if(port_count&&port_count<8){U32 value=0;bool valid=true;
        for(U32 k=0;k<port_count;++k){if(port[k]<'0'||port[k]>'9'){valid=false;break;}value=value*10+U32(port[k]-'0');}
        if(valid&&value>=1024&&value<=65535)cdp_port=value;
    }
    return true;
}
}
#endif
extern "C" EXPORT U32 MadeiraCefFixtureStatus(){
#if defined(MADEIRA_CEF_ARGS_TEST_ONLY)
    return state.installed?0x10000u:U32(state.result.error);
#else
    return U32(Error::Disarmed);
#endif
}
extern "C" EXPORT U32 MadeiraCefFixtureTransformed(){
#if defined(MADEIRA_CEF_ARGS_TEST_ONLY)
    return __atomic_load_n(&transformed,__ATOMIC_RELAXED);
#else
    return 0;
#endif
}
/* Optional source-provider integration: invoke once from the source loader's
 * PROCESS_ATTACH. Compiling this source alone changes nothing in that loader. */
extern "C" void MadeiraCefFixtureAttach(void *self){
#if defined(MADEIRA_CEF_ARGS_TEST_ONLY)
    U32 before=GetLastError();if(prepare(self)){
        auto *ntdll=GetModuleHandleW(reinterpret_cast<const U16*>(L"ntdll.dll"));
        auto reg=ntdll?reinterpret_cast<Register>(GetProcAddress(ntdll,"LdrRegisterDllNotification")):nullptr;
        if(reg&&reg(0,notification,nullptr,&notification_cookie)>=0){try_install();
            OutputDebugStringA("MADEIRA_CEF_ARGS test-only armed; all child results forwarded");}}
    SetLastError(before);
#else
    (void)self;
#endif
}
#if !defined(MADEIRA_CEF_ARGS_EMBEDDED)
extern "C" int DllMain(void *self,U32 reason,void *){if(reason==1){DisableThreadLibraryCalls(self);MadeiraCefFixtureAttach(self);}return 1;}
#endif
