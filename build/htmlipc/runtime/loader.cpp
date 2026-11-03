/* SPDX-License-Identifier: MIT
 * Optional early-load guest DLL shell. Default build supplies no configuration.
 * Experimental source provider may be compiled explicitly for a fresh prefix.
 * Compile as guest Windows AMD64. Native ARM64 must not invoke these exports.
 */
#include "../stream-install/installer.h"
#if defined(MADEIRA_RUNTIME_PROVIDER)
#include "runtime_provider.h"
#endif
using namespace madeira_stream_install;
#define IMPORT __declspec(dllimport)
#define EXPORT __declspec(dllexport)
using Wide=unsigned short;
struct Mbi {void *base,*allocation;U32 allocation_protect;U16 partition,pad;Size size;U32 state,protect,type,padding;};
static_assert(sizeof(Mbi)==48);
extern "C" {
IMPORT void *GetModuleHandleW(const Wide *);
IMPORT int GetModuleHandleExW(U32,const Wide *,void **);
IMPORT void *GetProcAddress(void *,const char *);
IMPORT Size VirtualQuery(const void *,Mbi *,Size);
IMPORT int VirtualProtect(void *,Size,U32,U32 *);
IMPORT U32 GetLastError();
IMPORT int DisableThreadLibraryCalls(void *);
IMPORT void OutputDebugStringA(const char *);
}
struct UnicodeString {U16 length,maximum;U32 pad;const U16 *buffer;};
struct Notification {U32 flags,pad;const UnicodeString *full,*base;void *module;U32 image_size,padding;};
using Notify=void (*)(U32,const Notification *,void *);
using Register=int (*)(U32,Notify,void *,void **);
using Unregister=int (*)(void *);
static Installer state;
static void *cookie,*seen_module;
static Unregister unregister_notification;
static bool is_chrome(const UnicodeString *s){
    static constexpr char expected[]="chromehtml.dll";
    if(!s||s->length!=(sizeof(expected)-1)*2||!s->buffer)return false;
    for(Size i=0;i<sizeof(expected)-1;++i){U16 c=s->buffer[i];if(c>='A'&&c<='Z')c+=32;if(c!=U16(expected[i]))return false;}return true;
}
static bool query(void *,const void *p,Region *out){Mbi m{};if(VirtualQuery(p,&m,sizeof(m))!=sizeof(m))return false;
    *out={m.base,m.allocation,m.size,m.state,m.protect,m.type};return true;}
static bool protect(void *,void *p,Size n,U32 flags,U32 *old){return VirtualProtect(p,n,flags,old)!=0;}
static U32 last_error(void *){return GetLastError();}
static void notification(U32 reason,const Notification *data,void *){
    if(!data||!is_chrome(data->base))return;
    if(reason==1){seen_module=data->module;if(state.phase==Phase::Armed)
        install_loaded(&state,data->module,data->image_size,data->base->buffer,data->base->length/2);}
    else if(reason==2){note_unloaded(&state,data->module);if(seen_module==data->module)seen_module=nullptr;}
#if defined(MADEIRA_RUNTIME_PROVIDER)
    /* Provider publishes state and at most one fixed install-error line; never
     * a factory or genuine controller call under the loader lock. */
    MadeiraRuntimeNoteInstaller(&state);
#endif
}
extern "C" EXPORT Result MadeiraArmStreamInstaller(const Config *config){
    if(!config)return {Error::InvalidConfig,0,true};
    if(seen_module||GetModuleHandleW(reinterpret_cast<const Wide*>(L"chromehtml.dll"))){
        state.phase=Phase::Failed;return state.result={Error::TooLate,0,true};}
    /* Pins the hook owner before it can be referenced by another DLL's table.
     * The installer DLL and callback registration likewise remain retained. */
    void *hook_owner=nullptr,*self=nullptr;
    if(!GetModuleHandleExW(5,reinterpret_cast<const Wide*>(config->hooks[0]),&hook_owner)||
       hook_owner!=config->hook_module||
       !GetModuleHandleExW(5,reinterpret_cast<const Wide*>(MadeiraArmStreamInstaller),&self))
        return {Error::WrongHook,GetLastError(),true};
    Api api{nullptr,query,protect,last_error};return arm(&state,*config,api);
}
extern "C" EXPORT Result MadeiraStreamInstallerStatus(){return state.result;}
extern "C" EXPORT void *MadeiraResolveCurrentController(){
    /* Explicit post-LoadLibrary call only. DLL notification precedes static
     * constructor registration, so calling CreateInterface there is invalid. */
    if(state.phase!=Phase::Installed||!state.module)return nullptr;
    auto address=GetProcAddress(state.module,"CreateInterface");
    if(address!=static_cast<U8*>(state.module)+create_interface_rva){
        state.phase=Phase::Failed;state.result={Error::WrongFactory,0,true};return nullptr;}
    using Factory=void *(*)(const char *,int *);int status=-1;
    void *object=reinterpret_cast<Factory>(address)("ChromeHTML_Controller_003",&status);
    if(status!=0||!validate_live_controller(&state,object)){
        state.phase=Phase::Failed;state.result={Error::WrongFactory,0,true};return nullptr;}
    return object;
}
extern "C" int DllMain(void *module,U32 reason,void *reserved){
    if(reason==1){
#if defined(MADEIRA_RUNTIME_PROVIDER)
        OutputDebugStringA("MADEIRA_HTMLIPC loader-entry");
#endif
        DisableThreadLibraryCalls(module);
        auto ntdll=GetModuleHandleW(reinterpret_cast<const Wide*>(L"ntdll.dll"));
        if(!ntdll)return 0;
        auto reg=reinterpret_cast<Register>(GetProcAddress(ntdll,"LdrRegisterDllNotification"));
        unregister_notification=reinterpret_cast<Unregister>(GetProcAddress(ntdll,"LdrUnregisterDllNotification"));
        if(!reg||!unregister_notification)return 0;
        if(reg(0,notification,nullptr,&cookie)<0)return 0;
        seen_module=GetModuleHandleW(reinterpret_cast<const Wide*>(L"chromehtml.dll"));
#if defined(MADEIRA_RUNTIME_PROVIDER)
        /* Explicit experimental build only. Its provider requires Steam.exe,
         * exact original file pin, and a separately compiled proven wire map. */
        Config config{};
        if(MadeiraRuntimePrepareConfig(module,&config)){
            Result result=MadeiraArmStreamInstaller(&config);
            if(result.error!=Error::None){state.phase=Phase::Failed;state.result=result;}
        }
        MadeiraRuntimeNoteInstaller(&state);
#else
        /* Remains DISARMED: there is no stub codec, default hook table or
         * environment variable that can enable data changes automatically. */
#endif
    }else if(reason==0 && cookie && unregister_notification){
#if defined(MADEIRA_RUNTIME_PROVIDER)
        MadeiraRuntimeDetach();
#endif
        /* Installed modules are normally pinned until process exit. Retire the
         * owned notification whenever the loader does deliver detach, including
         * that final process/private-NTDLL teardown. No thread-detach cleanup. */
        unregister_notification(cookie);cookie=nullptr;
    }
    (void)reserved;
    return 1;
}
