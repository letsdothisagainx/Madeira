/* SPDX-License-Identifier: MIT. Stock-Wine test fixture only. */
#ifndef MADEIRA_CEF_FIXTURE_ARGS_H
#define MADEIRA_CEF_FIXTURE_ARGS_H
namespace madeira_cef_fixture {
using U8=unsigned char;using U16=unsigned short;using U32=unsigned int;
using U64=unsigned long long;using Size=decltype(sizeof(0));
/* Returns output length, or -1 for an unchanged/unsupported call. Never edits
 * input. This mirrors only native Steam browser ARGUMENTS, never child gates. */
int browser_args(const U16 *image,Size image_length,const U16 *line,Size length,
                 bool jitless,U16 *out,Size capacity,U32 cdp_port=0);
struct Region {void *base,*allocation;Size size;U32 state,protect,type;};
struct Api {void *context;bool (*query)(void *,const void *,Region *);
    bool (*protect)(void *,void *,Size,U32,U32 *);U32 (*last_error)(void *);};
enum class Error:U32 {None,Disarmed,InvalidConfig,PinMismatch,WrongImage,WrongImport,
    WrongProtection,WrongHook,NotResolved,MakeWritableFailed,RestoreFailed,RollbackIncomplete};
struct Result {Error error;U32 system_error;bool rollback_complete;};
struct Config {const U8 *file;Size file_size;U8 sha256[32];void *hook_module;
    const void *hook;const void *genuine_create_process;void *genuine_module;};
struct Installer {Config config{};Api api{};Result result{Error::Disarmed,0,true};
    bool armed=false,installed=false;void *module=nullptr;U32 slot_rva=0;};
Result arm(Installer *,const Config &,const Api &);
Result install(Installer *,void *module);
}
#endif
