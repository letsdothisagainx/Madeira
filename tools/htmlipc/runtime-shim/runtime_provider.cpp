/* SPDX-License-Identifier: MIT
 * Experimental source guest AMD64 provider. No production-default activation.
 */
#include "runtime_provider.h"
#include "../stream-codec/stream_codec.h"
namespace install=madeira_stream_install;
namespace codec=madeira_stream_codec;
using namespace madeira_runtime;
using Byte=madeira_wire::Byte;
using Size=madeira_wire::Size;
using Wide=unsigned short;
#define IMPORT __declspec(dllimport)
#define EXPORT __declspec(dllexport)
extern "C" {
IMPORT U32 GetCurrentProcessId();
IMPORT void OutputDebugStringA(const char *);
IMPORT U32 GetCurrentThreadId();
IMPORT U32 GetModuleFileNameW(void *,Wide *,U32);
IMPORT int GetModuleHandleExW(U32,const Wide *,void **);
IMPORT void *GetProcessHeap();
IMPORT void *HeapAlloc(void *,U32,Size);
IMPORT int HeapFree(void *,U32,void *);
IMPORT Byte TryAcquireSRWLockExclusive(void *);
IMPORT void ReleaseSRWLockExclusive(void *);
IMPORT void Sleep(U32);
IMPORT void *CreateFileW(const Wide *,U32,U32,void *,U32,U32,void *);
IMPORT int GetFileSizeEx(void *,long long *);
IMPORT int ReadFile(void *,void *,U32,U32 *,void *);
IMPORT int WriteFile(void *,const void *,U32,U32 *,void *);
IMPORT int CloseHandle(void *);
IMPORT void *GetStdHandle(U32);
int _abnormal_termination();
}
/* Structure copies/zeroing emitted by an actual MSVC-target compiler require
 * these freestanding definitions; no CRT or global constructors are linked. */
extern "C" void *memcpy(void *out,const void *in,Size n) {
    auto *d=static_cast<Byte *>(out);auto *s=static_cast<const Byte *>(in);
    for(Size i=0;i<n;++i)d[i]=s[i];return out;
}
extern "C" void *memset(void *out,int value,Size n) {
    auto *d=static_cast<Byte *>(out);for(Size i=0;i<n;++i)d[i]=Byte(value);return out;
}
inline void *operator new(Size,void *p) noexcept { return p; }

namespace {
constexpr U32 entry_limit=8,wait_thread_limit=16,lock_attempts=128,drain_attempts=128;
constexpr Size pin_size=1668248;
struct LockWord {void *word;};
enum class Life:U32 { Empty,Live,Failed,Closing,Dead };
enum class Operation:U32 { Available,Writable,Put,Get,Clear,Wait };
struct WaitThread {U32 id,count,waits;};
struct Entry {
    Life life;
    codec::Scope scope;
    codec::State *state;
    Byte *input,*output;
    LockWord codec_lock;
    U32 codec_owner;
    U32 active,destroyed,destroying;
    bool reported,quarantined,announced;
    WaitThread wait_threads[wait_thread_limit];
};
using Destroy=void *(*)(void *,U32);
struct Originals {Destroy destroy;codec::Original methods;};
struct Lease {Entry *entry;codec::Scope scope;bool owned,allowed,wait;U32 thread;bool state_locked;};
static LockWord registry_lock;
static Entry entries[entry_limit];
static U32 used,pid,generation_counter;
static U64 current_generation;
static U64 calls,failed_calls;
static U32 failed_generations,first_error,first_command,first_direction,first_wire;
static bool prepared,source_pinned;
static Byte *file_pin;
static madeira_wire::MapView wire_map;
static install::Installer *installer;
static U32 published_phase,published_error;
static void *published_module;
static bool registry_quarantined;
static bool installed_announced;
static bool hook_announced;
static U32 unrelated_probes;
static bool install_error_announced;
static Wide executable_path[32768];
static U32 steam_root_length;
static constexpr char cache_contract[]=
    "MadeiraHtmlIPC-I386-Cache-v2\n"
    "steamwebhelper.exe 014c 8dba99d204779a30a88a794d1a88d7e76355d004d876ed4bb29da7c3d5a4fc70\n"
    "libcef.dll 014c b2dc73b55ca1d6a44a594e97b4ddd57bd19e79b2d09521faf2dfb83f51e2a94e\n"
    "chrome_elf.dll 014c 0c91bfdbb22d20ea153869a3dc7379d54a7380faee300d0fd6809fce491a3677\n"
    "SDL3.dll 014c db01ec466db9c4e19cc5fe8c878ac89bc1b6057136432554842b3cd4dca88669\n";

static void report(Error,U32=0,U32=0,U32=0);
static bool lock_registry(){
    if(__atomic_load_n(&registry_quarantined,__ATOMIC_ACQUIRE))return false;
    for(U32 n=0;n<lock_attempts;++n){if(TryAcquireSRWLockExclusive(&registry_lock))return true;Sleep(1);}
    __atomic_store_n(&registry_quarantined,true,__ATOMIC_RELEASE);report(Error::RegistryLockTimeout);return false;
}
static void unlock_registry(){ReleaseSRWLockExclusive(&registry_lock);}
/* The provider takes a bounded outer state lock. These no-op guards are used
 * only while that lock is owned; void enter callbacks cannot safely indicate
 * a timed-out SRW acquisition to the codec. */
static void codec_enter(void *){}
static void codec_leave(void *){}
static U32 read32(const Byte *p){return U32(p[0])|U32(p[1])<<8|U32(p[2])<<16|U32(p[3])<<24;}
static Size number(char *out,Size at,U64 value){
    char reversed[20];Size n=0;do{reversed[n++]=char('0'+value%10);value/=10;}while(value);
    while(n)out[at++]=reversed[--n];return at;
}
static Size literal(char *out,Size at,const char *s){while(*s)out[at++]=*s++;return at;}
static void report(Error error,U32 direction,U32 command,U32 wire){
    U32 expected=0;
    if(!__atomic_compare_exchange_n(&first_error,&expected,0xffffffffu,false,
                                    __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return;
    first_direction=direction;first_command=command;first_wire=wire;
    /* Publish metadata before the readable error flag. A reader which sees
     * the reserved value returns no record yet, rather than racing these fields. */
    __atomic_store_n(&first_error,U32(error),__ATOMIC_RELEASE);
    char line[192];Size n=literal(line,0,"MADEIRA_HTMLIPC error=");n=number(line,n,U32(error));
    n=literal(line,n," pid=");n=number(line,n,pid);
    n=literal(line,n," generation=");n=number(line,n,__atomic_load_n(&current_generation,__ATOMIC_ACQUIRE));
    n=literal(line,n," direction=");n=number(line,n,direction);
    n=literal(line,n," command=");n=number(line,n,command);
    n=literal(line,n," wire=");n=number(line,n,wire);line[n++]='\n';
    line[n]=0;U32 written=0;WriteFile(GetStdHandle(U32(-12)),line,U32(n),&written,nullptr);OutputDebugStringA(line);
}
static void announce(const char *label,U64 generation=0){
    char line[128];Size n=literal(line,0,"MADEIRA_HTMLIPC ");n=literal(line,n,label);
    n=literal(line,n," pid=");n=number(line,n,pid);
    if(generation){n=literal(line,n," generation=");n=number(line,n,generation);}
    line[n++]='\n';line[n]=0;U32 written=0;WriteFile(GetStdHandle(U32(-12)),line,U32(n),&written,nullptr);OutputDebugStringA(line);
}
static void announce_install_error(U32 code){
    bool expected=false;
    if(!__atomic_compare_exchange_n(&install_error_announced,&expected,true,false,
        __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return;
    char line[100];Size n=literal(line,0,"MADEIRA_HTMLIPC install-error pid=");
    n=number(line,n,pid);n=literal(line,n," code=");n=number(line,n,code);line[n++]='\n';
    line[n]=0;U32 written=0;WriteFile(GetStdHandle(U32(-12)),line,U32(n),&written,nullptr);OutputDebugStringA(line);
}
static void announce_install_diagnostic(const install::Diagnostic &d){
    char line[384];Size n=literal(line,0,"MADEIRA_HTMLIPC image-mismatch stage=");
    n=number(line,n,U32(d.stage));n=literal(line,n," rva=");n=number(line,n,d.rva);
    n=literal(line,n," expected=");n=number(line,n,d.expected_bytes);
    n=literal(line,n," actual=");n=number(line,n,d.actual_bytes);
    n=literal(line,n," bytes=");n=number(line,n,d.byte_count);
    n=literal(line,n," expected-protection=");n=number(line,n,d.expected_protection);
    n=literal(line,n," actual-protection=");n=number(line,n,d.actual_protection);
    n=literal(line,n," image-size=");n=number(line,n,d.actual_image_size);
    n=literal(line,n," query-flags=");n=number(line,n,d.query_flags);
    line[n++]='\n';line[n]=0;U32 written=0;
    WriteFile(GetStdHandle(U32(-12)),line,U32(n),&written,nullptr);OutputDebugStringA(line);
}
static install::Installer *get_installer(){return __atomic_load_n(&installer,__ATOMIC_ACQUIRE);}
static void probe_stream(void *stream,void *to,void *from,U32 operation){
    if(__atomic_fetch_add(&unrelated_probes,1u,__ATOMIC_RELAXED)>=8)return;
    char line[256];Size n=literal(line,0,"MADEIRA_HTMLIPC stream-probe pid=");
    n=number(line,n,pid);n=literal(line,n," operation=");n=number(line,n,operation);
    n=literal(line,n," stream=");n=number(line,n,reinterpret_cast<U64>(stream));
    n=literal(line,n," to=");n=number(line,n,reinterpret_cast<U64>(to));
    n=literal(line,n," from=");n=number(line,n,reinterpret_cast<U64>(from));
    line[n++]='\n';line[n]=0;OutputDebugStringA(line);
}
static bool originals(Originals *out){
    auto *i=get_installer();
    if(!i||__atomic_load_n(&published_phase,__ATOMIC_ACQUIRE)!=U32(install::Phase::Installed)){
        report(Error::InstallerUnavailable);return false;}
    bool expected=false;
    if(__atomic_compare_exchange_n(&installed_announced,&expected,true,false,
        __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))announce("installed");
    expected=false;
    if(__atomic_compare_exchange_n(&hook_announced,&expected,true,false,
        __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))announce("hook-reached");
    out->destroy=reinterpret_cast<Destroy>(i->original_entries[0]);
    out->methods={reinterpret_cast<codec::Original::Count>(i->original_entries[1]),
        reinterpret_cast<codec::Original::Count>(i->original_entries[2]),
        reinterpret_cast<codec::Original::Put>(i->original_entries[3]),
        reinterpret_cast<codec::Original::Get>(i->original_entries[4]),
        reinterpret_cast<codec::Original::Clear>(i->original_entries[5]),
        reinterpret_cast<codec::Original::Wait>(i->original_entries[6])};
    return true;
}
static bool pin_source(){
    if(__atomic_load_n(&source_pinned,__ATOMIC_ACQUIRE))return true;
    auto *i=get_installer();void *owner=nullptr;
    void *expected=__atomic_load_n(&published_module,__ATOMIC_ACQUIRE);
    if(__atomic_load_n(&published_phase,__ATOMIC_ACQUIRE)!=U32(install::Phase::Installed))return false;
    if(!i||!GetModuleHandleExW(5,reinterpret_cast<const Wide *>(i->original_entries[0]),&owner)
       ||owner!=expected||__atomic_load_n(&published_module,__ATOMIC_ACQUIRE)!=expected||
       __atomic_load_n(&published_phase,__ATOMIC_ACQUIRE)!=U32(install::Phase::Installed))return false;
    /* Loader APIs run before either provider lock. Concurrent PIN requests are
     * harmless; release publication makes the immutable original table visible. */
    __atomic_store_n(&source_pinned,true,__ATOMIC_RELEASE);return true;
}
static bool stream_valid(install::Installer *i,void *stream){
    if(!stream)return false;
    auto *table=static_cast<Byte *>(i->module)+install::stream_vtable_rva;
    if(*static_cast<void **>(stream)!=table)return false;
    for(U32 n=0;n<7;++n)
        if(reinterpret_cast<const void *const *>(table)[n]!=i->config.hooks[n])return false;
    return true;
}
static U32 direction(const Entry *e,void *stream){return stream==e->scope.to_helper?1:2;}
static bool waiting(const Entry *e,U32 thread){
    for(auto &w:e->wait_threads)if(w.id==thread&&w.waits)return true;return false;
}
static bool admitted_thread(const Entry *e,U32 thread){
    for(auto &w:e->wait_threads)if(w.id==thread&&w.count)return true;return false;
}
static bool add_thread(Entry *e,U32 thread,bool wait){
    for(auto &w:e->wait_threads)if(w.id==thread&&w.count){++w.count;if(wait)++w.waits;return true;}
    for(auto &w:e->wait_threads)if(!w.count){w.id=thread;w.count=1;w.waits=wait?1:0;return true;}
    return false;
}
static void remove_thread(Entry *e,U32 thread,bool wait){
    for(auto &w:e->wait_threads)if(w.id==thread&&w.count){--w.count;if(wait)--w.waits;return;}
}
static void release_owned(Entry *e){
    /* Called only after both genuine destructors returned, no admitted callback
     * remains, and no admission can reopen this generation. */
    void *heap=GetProcessHeap();
    if(e->state)HeapFree(heap,0,e->state);
    if(e->input)HeapFree(heap,0,e->input);
    if(e->output)HeapFree(heap,0,e->output);
    e->state=nullptr;e->input=nullptr;e->output=nullptr;e->life=Life::Dead;
}
static Entry *make_entry_locked(install::Installer *i,void *controller,void *to,void *from,
                                const Originals &original,Error *failure){
    if(used==entry_limit){*failure=Error::RegistryFull;return nullptr;}
    if(generation_counter==0xffffffffu){*failure=Error::GenerationOverflow;return nullptr;}
    Entry *e=&entries[__atomic_fetch_add(&used,1u,__ATOMIC_RELAXED)];
    e->scope={controller,(U64(pid)<<32)|++generation_counter,to,from};
    __atomic_store_n(&current_generation,e->scope.generation,__ATOMIC_RELEASE);e->life=Life::Failed;
    void *heap=GetProcessHeap();
    void *memory=HeapAlloc(heap,8,sizeof(codec::State));
    if(memory)e->state=new(memory)codec::State{};
    e->input=static_cast<Byte *>(HeapAlloc(heap,0,codec::max_frame));
    e->output=static_cast<Byte *>(HeapAlloc(heap,0,codec::max_frame));
    if(!e->state||!e->input||!e->output){*failure=Error::Allocation;return e;}
    codec::Settings settings{e->scope,original.methods,wire_map,
        {e->input,codec::max_frame,e->output,codec::max_frame},
        {e,codec_enter,codec_leave},64};
    if(!codec::configure(e->state,settings)){*failure=Error::CodecConfiguration;return e;}
    (void)i;e->life=Life::Live;return e;
}
static Lease acquire(void *stream,Operation op,const Originals &original){
    __atomic_fetch_add(&calls,U64(1),__ATOMIC_RELAXED);
    Lease result{};Error error=Error::None;U32 thread=GetCurrentThreadId();
    if(!pin_source()){report(Error::SourcePinFailed);return {nullptr,{},true,false,false,thread,false};}
    if(!lock_registry())return {nullptr,{},true,false,false,thread,false};
    Entry *e=nullptr;
    for(U32 n=0;n<used;++n)if(entries[n].life!=Life::Dead&&
       (entries[n].scope.to_helper==stream||entries[n].scope.from_helper==stream)){e=&entries[n];break;}
    if(!e){
        auto *i=get_installer();
        auto *controller=static_cast<Byte *>(i->module)+install::controller_object_rva;
        /* Read live stream identities, not a pre-Init snapshot of null fields. */
        void *to=*reinterpret_cast<void **>(controller+0x170);
        void *from=*reinterpret_cast<void **>(controller+0x178);
        if(stream!=to&&stream!=from){unlock_registry();probe_stream(stream,to,from,U32(op));return result;}
        result.owned=true;
        if(!install::validate_live_controller(i,controller))error=Error::ControllerInvalid;
        else if(!to||!from||to==from)error=Error::PartialPublication;
        else if(!stream_valid(i,to)||!stream_valid(i,from))error=Error::StreamInvalid;
        else e=make_entry_locked(i,controller,to,from,original,&error);
    }
    if(error!=Error::None){unlock_registry();report(error);return {e,{},true,false,false,thread,false};}
    result.owned=true;result.entry=e;result.scope=e->scope;result.thread=thread;
    bool reentrant_available=op==Operation::Available&&waiting(e,thread);
    if(__atomic_load_n(&e->quarantined,__ATOMIC_ACQUIRE)||
       (e->life!=Life::Live&&!(e->life==Life::Closing&&reentrant_available))){
        unlock_registry();return result;
    }
    if(!add_thread(e,thread,op==Operation::Wait)){
        unlock_registry();report(Error::ThreadSlotsFull,direction(e,stream));return result;
    }
    ++e->active;result.allowed=true;result.wait=op==Operation::Wait;
    bool announce_generation=!e->announced;e->announced=true;
    U64 generation=e->scope.generation;
    unlock_registry();if(announce_generation)announce("connected",generation);return result;
}
static void leave(Lease *lease){
    if(!lease->allowed)return;
    if(!lock_registry()){lease->allowed=false;return;}
    remove_thread(lease->entry,lease->thread,lease->wait);
    --lease->entry->active;unlock_registry();lease->allowed=false;
}
static bool take_state(Lease *lease){
    Entry *e=lease->entry;
    if(__atomic_load_n(&e->quarantined,__ATOMIC_ACQUIRE))return false;
    for(U32 n=0;n<lock_attempts;++n){
        if(TryAcquireSRWLockExclusive(&e->codec_lock)){
            /* Quarantine may have begun while this admitted caller waited.
             * Never resume a partially unwound state after acquiring its lock. */
            if(__atomic_load_n(&e->quarantined,__ATOMIC_ACQUIRE)){
                ReleaseSRWLockExclusive(&e->codec_lock);return false;
            }
            __atomic_store_n(&e->codec_owner,lease->thread,__ATOMIC_RELEASE);
            lease->state_locked=true;return true;
        }
        Sleep(1);
    }
    __atomic_store_n(&e->quarantined,true,__ATOMIC_RELEASE);report(Error::StateLockTimeout);return false;
}
static void release_state(Lease *lease){
    if(!lease->state_locked)return;
    __atomic_store_n(&lease->entry->codec_owner,0u,__ATOMIC_RELEASE);
    ReleaseSRWLockExclusive(&lease->entry->codec_lock);lease->state_locked=false;
}
static void finish_lease(Lease *lease,bool abnormal){
    if(!lease->allowed)return;
    if(abnormal){
        Entry *e=lease->entry;
        /* The freestanding codec has no C++ runtime. A genuine exception may
         * leave its injected lock held; the Windows finally releases only a
         * lock proven owned by this exact thread, then closes the generation.
         * The original exception continues unchanged. */
        __atomic_store_n(&e->quarantined,true,__ATOMIC_RELEASE);
        report(Error::OriginalUnwind);
    }
    release_state(lease);
    leave(lease);
}
static bool failed(const Lease &lease,void *stream,U32 fallback_command=0){
    Entry *e=lease.entry;codec::Failure failure;
    U32 command=fallback_command,dir=direction(e,stream);
    failure=e->state->failure;
    if(dir==1&&e->state->tx_used>=8)command=read32(e->input+4);
    if(dir==2&&e->state->rx_collected>=8)command=read32(e->state->rx_header+4);
    if(__atomic_load_n(&e->quarantined,__ATOMIC_ACQUIRE)||
       __atomic_load_n(&registry_quarantined,__ATOMIC_ACQUIRE))return true;
    if(failure.error==codec::Error::None)return false;
    if(!e->reported){e->reported=true;__atomic_fetch_add(&failed_generations,1u,__ATOMIC_RELAXED);}
    report(Error::CodecFailure,dir,command,U32(failure.wire));return true;
}
static U32 failed_count(){__atomic_fetch_add(&failed_calls,U64(1),__ATOMIC_RELAXED);return 0;}

extern "C" void *runtime_destroy(void *stream,U32 flags){
    Originals original{};if(!originals(&original)){failed_count();return nullptr;}
    if(!pin_source()){report(Error::SourcePinFailed);failed_count();return nullptr;}
    if(!lock_registry()){failed_count();return nullptr;}
    Entry *e=nullptr;
    for(U32 n=0;n<used;++n)if(entries[n].life!=Life::Dead&&
       (entries[n].scope.to_helper==stream||entries[n].scope.from_helper==stream)){e=&entries[n];break;}
    if(!e){unlock_registry();return original.destroy(stream,flags);}
    U32 bit=stream==e->scope.to_helper?1:2;
    if(__atomic_load_n(&e->quarantined,__ATOMIC_ACQUIRE)){unlock_registry();report(Error::Quarantined);
        failed_count();return nullptr;}
    if(admitted_thread(e,GetCurrentThreadId())){
        __atomic_store_n(&e->quarantined,true,__ATOMIC_RELEASE);unlock_registry();
        report(Error::ReentrantDestroy);failed_count();return nullptr;
    }
    if((e->destroying|e->destroyed)&bit){unlock_registry();report(Error::DuplicateDestroy);
        failed_count();return nullptr;}
    e->life=Life::Closing;e->destroying|=bit;unlock_registry();
    /* Genuine Shutdown sets abort and signals incoming Wait before these dtors.
     * No registry or codec lock spans this wait or the genuine destructor. */
    bool drained=false;
    for(U32 n=0;n<drain_attempts;++n){
        if(!lock_registry()){failed_count();return nullptr;}
        drained=e->active==0;
        bool quarantined=__atomic_load_n(&e->quarantined,__ATOMIC_ACQUIRE);
        unlock_registry();
        if(quarantined){report(Error::Quarantined);failed_count();return nullptr;}
        if(drained)break;Sleep(1);
    }
    if(!drained){__atomic_store_n(&e->quarantined,true,__ATOMIC_RELEASE);
        report(Error::DrainTimeout);failed_count();return nullptr;}
    if(__atomic_load_n(&e->quarantined,__ATOMIC_ACQUIRE)){
        report(Error::Quarantined);failed_count();return nullptr;}
    void *result=nullptr;bool completed=false;
    __try {result=original.destroy(stream,flags);completed=true;}
    __finally {
        if(lock_registry()){
            e->destroying&=~bit;
            if(completed){e->destroyed|=bit;
                if(e->destroyed==3&&!e->active&&!e->destroying)release_owned(e);}
            else __atomic_store_n(&e->quarantined,true,__ATOMIC_RELEASE);
            unlock_registry();
        }
        if(!completed)report(Error::OriginalUnwind);
    }
    return result;
}
extern "C" U32 runtime_available(void *stream){
    Originals o{};if(!originals(&o))return failed_count();auto l=acquire(stream,Operation::Available,o);
    if(!l.owned)return o.methods.available(stream);if(!l.allowed)return failed_count();
    U32 result=0;bool bad=false;
    __try {if(take_state(&l)){result=codec::available(l.entry->state,l.scope,stream);bad=failed(l,stream);}else bad=true;}
    __finally {finish_lease(&l,_abnormal_termination()!=0);}
    return bad?failed_count():result;
}
extern "C" U32 runtime_writable(void *stream){
    Originals o{};if(!originals(&o))return failed_count();auto l=acquire(stream,Operation::Writable,o);
    if(!l.owned)return o.methods.writable(stream);if(!l.allowed)return failed_count();
    U32 result=0;bool bad=false;
    __try {if(take_state(&l)){result=codec::writable(l.entry->state,l.scope,stream);bad=failed(l,stream);}else bad=true;}
    __finally {finish_lease(&l,_abnormal_termination()!=0);}
    return bad?failed_count():result;
}
extern "C" U32 runtime_put(void *stream,const void *data,U32 count){
    Originals o{};if(!originals(&o))return failed_count();auto l=acquire(stream,Operation::Put,o);
    if(!l.owned)return o.methods.put(stream,data,count);if(!l.allowed)return failed_count();
    U32 command=data&&count>=8?read32(static_cast<const Byte *>(data)+4):0;
    U32 result=0;bool bad=false;
    __try {if(take_state(&l)){result=codec::put(l.entry->state,l.scope,stream,data,count);bad=failed(l,stream,command);}else bad=true;}
    __finally {finish_lease(&l,_abnormal_termination()!=0);}
    return bad?failed_count():result;
}
extern "C" U32 runtime_get(void *stream,void *data,U32 count){
    Originals o{};if(!originals(&o))return failed_count();auto l=acquire(stream,Operation::Get,o);
    if(!l.owned)return o.methods.get(stream,data,count);if(!l.allowed)return failed_count();
    U32 result=0;bool bad=false;
    __try {if(take_state(&l)){result=codec::get(l.entry->state,l.scope,stream,data,count);bad=failed(l,stream);}else bad=true;}
    __finally {finish_lease(&l,_abnormal_termination()!=0);}
    return bad?failed_count():result;
}
extern "C" bool runtime_clear(void *stream,U32 count){
    Originals o{};if(!originals(&o)){failed_count();return false;}auto l=acquire(stream,Operation::Clear,o);
    if(!l.owned)return o.methods.clear(stream,count);if(!l.allowed){failed_count();return false;}
    bool result=false,bad=false;
    __try {if(take_state(&l)){result=codec::clear(l.entry->state,l.scope,stream,count);bad=failed(l,stream);}else bad=true;}
    __finally {finish_lease(&l,_abnormal_termination()!=0);}
    if(bad){failed_count();return false;}return result;
}
extern "C" bool runtime_wait(void *stream,bool infinite,U32 timeout){
    Originals o{};if(!originals(&o)){failed_count();return false;}auto l=acquire(stream,Operation::Wait,o);
    if(!l.owned)return o.methods.wait(stream,infinite,timeout);if(!l.allowed){failed_count();return false;}
    bool result=false,bad=false;
    __try {
        if(take_state(&l)){
            bad=failed(l,stream);release_state(&l);
            /* Equivalent to codec::wait's two health checks, with bounded
             * outer synchronization and genuine Wait entirely unlocked. */
            if(!bad){result=o.methods.wait(stream,infinite,timeout);
                if(take_state(&l))bad=failed(l,stream);else bad=true;}
        }else bad=true;
    }
    __finally {finish_lease(&l,_abnormal_termination()!=0);}
    if(bad){failed_count();return false;}return result;
}
static bool own_image_size(void *module,Size *size){
    if(!module)return false;auto *p=static_cast<Byte *>(module);
    if(p[0]!='M'||p[1]!='Z')return false;U32 off=read32(p+0x3c);
    if(off>0x1000||read32(p+off)!=0x4550||p[off+24]!=0x0b||p[off+25]!=2)return false;
    *size=read32(p+off+24+56);return *size>=0x1000;
}
static bool identify_process(){
    U32 n=GetModuleFileNameW(nullptr,executable_path,32768);
    if(!n||n>=32767){report(Error::WrongProcess);return false;}
    U32 start=n;while(start&&executable_path[start-1]!='\\'&&executable_path[start-1]!='/')--start;
    static constexpr char steam[]="steam.exe";
    if(n-start!=sizeof(steam)-1){report(Error::WrongProcess);return false;}
    for(U32 k=0;k<sizeof(steam)-1;++k){Wide c=executable_path[start+k];if(c>='A'&&c<='Z')c+=32;
        if(c!=Wide(steam[k])){report(Error::WrongProcess);return false;}}
    steam_root_length=start;return true;
}
static bool prepare_cache_gate(){
    static constexpr char suffix[]="bin\\cef\\cef.win7\\.madeira-cache-verified-v1";
    if(steam_root_length+sizeof(suffix)>32768){report(Error::CacheNotVerified);return false;}
    for(U32 k=0;k<sizeof(suffix);++k)executable_path[steam_root_length+k]=Wide(suffix[k]);
    void *file=CreateFileW(executable_path,0x80000000u,5,nullptr,3,0x80,nullptr);
    if(file==reinterpret_cast<void *>(~Size(0))){report(Error::CacheNotVerified);return false;}
    char bytes[sizeof(cache_contract)];long long length=0;U32 got=0;
    bool ok=GetFileSizeEx(file,&length)&&length==sizeof(cache_contract)-1&&
        ReadFile(file,bytes,sizeof(cache_contract)-1,&got,nullptr)&&got==sizeof(cache_contract)-1;
    CloseHandle(file);
    if(ok)for(U32 k=0;k<sizeof(cache_contract)-1;++k)if(bytes[k]!=cache_contract[k]){ok=false;break;}
    if(!ok)report(Error::CacheNotVerified);return ok;
}
static bool prepare_pin(){
    static constexpr char suffix[]="bin\\chromehtml.dll";
    if(steam_root_length+sizeof(suffix)>32768){report(Error::PinOpen);return false;}
    for(U32 k=0;k<sizeof(suffix);++k)executable_path[steam_root_length+k]=Wide(suffix[k]);
    void *file=CreateFileW(executable_path,0x80000000u,5,nullptr,3,0x80,nullptr);
    if(file==reinterpret_cast<void *>(~Size(0))){report(Error::PinOpen);return false;}
    long long length=0;
    if(!GetFileSizeEx(file,&length)||length!=static_cast<long long>(pin_size)){
        CloseHandle(file);report(Error::PinSize);return false;}
    file_pin=static_cast<Byte *>(HeapAlloc(GetProcessHeap(),0,pin_size));
    if(!file_pin){CloseHandle(file);report(Error::Allocation);return false;}
    U32 total=0;
    while(total<pin_size){U32 got=0;
        if(!ReadFile(file,file_pin+total,U32(pin_size-total),&got,nullptr)||!got){
            CloseHandle(file);HeapFree(GetProcessHeap(),0,file_pin);file_pin=nullptr;report(Error::PinRead);return false;}
        total+=got;
    }
    CloseHandle(file);return true;
}
}

extern "C" bool MadeiraRuntimePrepareConfig(void *module,install::Config *out){
    if(!out||__atomic_load_n(&prepared,__ATOMIC_ACQUIRE))return false;
    pid=GetCurrentProcessId();generation_counter=1;
    __atomic_store_n(&current_generation,(U64(pid)<<32)|1,__ATOMIC_RELEASE);
    if(!identify_process())return false;
#if defined(MADEIRA_RUNTIME_HAS_PROVEN_MAP)
    if(!MadeiraRuntimeGetWireMap(&wire_map)||!wire_map.entries||!wire_map.count){report(Error::MissingProvenMap);return false;}
#else
    (void)module;report(Error::MissingProvenMap);return false;
#endif
    Size image_size=0;if(!own_image_size(module,&image_size)){report(Error::ModuleMetadata);return false;}
    if(!prepare_cache_gate())return false;
    if(!prepare_pin())return false;
    install::Config config{};config.pinned_file=file_pin;config.pinned_file_size=pin_size;
    config.hook_module=module;config.hook_module_size=image_size;
    config.hooks[0]=reinterpret_cast<const void *>(runtime_destroy);
    config.hooks[1]=reinterpret_cast<const void *>(runtime_available);
    config.hooks[2]=reinterpret_cast<const void *>(runtime_writable);
    config.hooks[3]=reinterpret_cast<const void *>(runtime_put);
    config.hooks[4]=reinterpret_cast<const void *>(runtime_get);
    config.hooks[5]=reinterpret_cast<const void *>(runtime_clear);
    config.hooks[6]=reinterpret_cast<const void *>(runtime_wait);
    config.generation=__atomic_load_n(&current_generation,__ATOMIC_ACQUIRE);
    config.wire_contract_ready=true;config.redirect_helper_win32=true;
    *out=config;__atomic_store_n(&prepared,true,__ATOMIC_RELEASE);return true;
}
extern "C" void MadeiraRuntimeNoteInstaller(install::Installer *state){
    /* No factory, heap or DLL loading under the notification loader lock.
     * A failed install emits one explicitly permitted fixed numeric diagnostic. */
    __atomic_store_n(&installer,state,__ATOMIC_RELEASE);
    __atomic_store_n(&published_module,state?state->module:nullptr,__ATOMIC_RELAXED);
    __atomic_store_n(&published_error,state?U32(state->result.error):0u,__ATOMIC_RELAXED);
    __atomic_store_n(&published_phase,state?U32(state->phase):0u,__ATOMIC_RELEASE);
    if(state&&state->phase==install::Phase::Installed){
        bool expected=false;
        if(__atomic_compare_exchange_n(&installed_announced,&expected,true,false,
            __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))announce("installed");
    }else if(state&&state->phase==install::Phase::Failed){
        announce_install_diagnostic(state->diagnostic);
        announce_install_error(U32(state->result.error));
    }
}
extern "C" EXPORT bool MadeiraRuntimeGetStatus(Status *out,U32 bytes){
    if(!out||bytes<sizeof(Status))return false;
    Status s{};s.size=sizeof(Status);s.version=1;s.pid=pid;
    s.prepared=__atomic_load_n(&prepared,__ATOMIC_ACQUIRE);
    s.installer_phase=__atomic_load_n(&published_phase,__ATOMIC_ACQUIRE);
    s.installer_error=__atomic_load_n(&published_error,__ATOMIC_ACQUIRE);
    s.installed_module=reinterpret_cast<U64>(__atomic_load_n(&published_module,__ATOMIC_ACQUIRE));
    U32 error=__atomic_load_n(&first_error,__ATOMIC_ACQUIRE);
    if(error&&error!=0xffffffffu){s.provider_error=error;s.wire_error=first_wire;
        s.first_command=first_command;s.first_direction=first_direction;}
    s.entry_count=__atomic_load_n(&used,__ATOMIC_ACQUIRE);
    s.failed_generations=__atomic_load_n(&failed_generations,__ATOMIC_ACQUIRE);
    s.generation=__atomic_load_n(&current_generation,__ATOMIC_ACQUIRE);
    s.calls=__atomic_load_n(&calls,__ATOMIC_RELAXED);s.failed_calls=__atomic_load_n(&failed_calls,__ATOMIC_RELAXED);
    *out=s;return true;
}
