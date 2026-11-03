/* SPDX-License-Identifier: MIT */
#ifndef MADEIRA_STREAM_INSTALLER_H
#define MADEIRA_STREAM_INSTALLER_H
#if !defined(_WIN64) || !(defined(_M_X64) || defined(__x86_64__))
#error "Build this data-only installer for Windows AMD64"
#endif
namespace madeira_stream_install {
using U8=unsigned char; using U16=unsigned short; using U32=unsigned int;
using U64=unsigned long long; using Size=decltype(sizeof(0));
static_assert(sizeof(void*)==8 && sizeof(U32)==4);
struct Region { void *base,*allocation; Size size; U32 state,protect,type; };
struct Api {
    void *context;
    bool (*query)(void *,const void *,Region *);
    bool (*protect)(void *,void *,Size,U32,U32 *);
    U32 (*last_error)(void *);
};
struct Config {
    /* Exact original PE file bytes, owned, immutable and retained by caller.
     * Full SHA-256 is checked at arm and again before module comparison.
     * No file is opened or modified by this installer. */
    const U8 *pinned_file;
    Size pinned_file_size;
    void *hook_module;
    Size hook_module_size;
    const void *hooks[7];
    U64 generation;
    bool wire_contract_ready;
    bool redirect_helper_win32;
};
enum class Error:U32 {
    None,NotArmed,InvalidConfig,PinMismatch,WrongModule,WrongImage,
    WrongMetadata,WrongProtection,WrongHook,AlreadyInstalled,
    MakeWritableFailed,RestoreFailed,RollbackIncomplete,ModuleUnloaded,
    TooLate,FactoryUnavailable,WrongFactory
};
struct Result { Error error; U32 system_error; bool rollback_complete; };
enum class Phase:U32 { Disarmed,Armed,Installed,Failed };
struct Installer {
    Config config{}; Api api{}; Phase phase=Phase::Disarmed;
    Result result{Error::NotArmed,0,true}; void *module=nullptr;
    U64 original_entries[7]{};
};
/* Call before loading chromehtml. It rejects an absent real wire contract;
 * no placeholder codec, loader, hooks or permissive default is supplied. */
Result arm(Installer *,const Config &,const Api &);
/* Intended for the early DLL notification, before chromehtml DllMain/Init.
 * This only reads/compares image bytes and changes two non-executable DATA
 * pages. It does not call a factory or any current DLL function. */
Result install_loaded(Installer *,void *module,Size image_size,
                      const U16 *base_name,Size base_name_units);
void note_unloaded(Installer *,void *module);
bool validate_live_controller(Installer *,void *controller);
static constexpr U32 stream_vtable_rva=0x132340;
static constexpr U32 controller_object_rva=0x1806b0;
static constexpr U32 controller_vtable_rva=0x123688;
static constexpr U32 create_interface_rva=0xf9660;
}
#endif
