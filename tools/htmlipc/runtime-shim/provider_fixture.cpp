/* SPDX-License-Identifier: MIT. Provider ABI/lifetime fixture, not Steam API. */
#include "runtime_provider.h"
using namespace madeira_runtime;
namespace si=madeira_stream_install;
using Size=si::Size;using Byte=si::U8;
extern "C" {
void *runtime_destroy(void *,U32);
U32 runtime_available(void *);U32 runtime_writable(void *);
U32 runtime_put(void *,const void *,U32);U32 runtime_get(void *,void *,U32);
bool runtime_clear(void *,U32);bool runtime_wait(void *,bool,U32);
__declspec(dllimport) Size VirtualQuery(const void *,void *,Size);
__declspec(dllimport) int VirtualProtect(void *,Size,U32,U32 *);
U64 fixture_module=0,fixture_own_module=0;
U32 fixture_mode=0,fixture_thread=111,fixture_poison=0;
U32 fixture_original_dtors=0,fixture_original_puts=0,fixture_original_waits=0;
U32 fixture_errors=0;
U32 fixture_closing_reentries=0;
}
struct Mbi {void *base,*allocation;U32 ap;unsigned short partition,pad;Size size;U32 state,protect,type,padding;};
static bool query(void *,const void *address,si::Region *out){
    Mbi r{};if(VirtualQuery(address,&r,sizeof(r))!=sizeof(r))return false;
    *out={r.base,r.allocation,r.size,r.state,r.protect,r.type};return true;
}
static bool protect(void *,void *p,Size n,U32 value,U32 *old){return VirtualProtect(p,n,value,old)!=0;}
static U32 last_error(void *){return 0;}
struct FakeStream {void *vtable;Byte bytes[8192];U32 used,read,id;};
static FakeStream to,from,control;
static si::Installer installed;
static U32 rd(const Byte *p){return U32(p[0])|U32(p[1])<<8|U32(p[2])<<16|U32(p[3])<<24;}
static void wr(Byte *p,U32 n){for(U32 k=0;k<4;++k)p[k]=Byte(n>>(8*k));}
extern "C" void *fixture_original_destroy(void *s,U32 flags){
    ++fixture_original_dtors;if(flags!=1&&flags!=3)++fixture_errors;
    if(fixture_mode==6&&s==&to){if(runtime_destroy(s,flags)!=nullptr)++fixture_errors;}
    return s;
}
extern "C" U32 fixture_original_available(void *s){auto *q=static_cast<FakeStream *>(s);return q->id==3?73:q->used-q->read;}
extern "C" U32 fixture_original_writable(void *){return 8192;}
extern "C" U32 fixture_original_put(void *s,const void *p,U32 n){
    ++fixture_original_puts;auto *q=static_cast<FakeStream *>(s);
    if(fixture_mode==7&&s==&to){if(runtime_destroy(s,1)!=nullptr)++fixture_errors;}
    U32 count=n>3?3:n;if(q->used+count>sizeof(q->bytes))return 0;
    for(U32 k=0;k<count;++k)q->bytes[q->used++]=static_cast<const Byte *>(p)[k];return count;
}
extern "C" U32 fixture_original_get(void *s,void *p,U32 n){
    auto *q=static_cast<FakeStream *>(s);U32 count=q->used-q->read;if(count>n)count=n;
    for(U32 k=0;k<count;++k)static_cast<Byte *>(p)[k]=q->bytes[q->read++];return count;
}
extern "C" bool fixture_original_clear(void *s,U32 n){auto *q=static_cast<FakeStream *>(s);
    if(n&&q->used-q->read!=n)return false;q->used=q->read=0;return true;}
extern "C" bool fixture_original_wait(void *s,bool infinite,U32 timeout){
    ++fixture_original_waits;if(infinite||timeout!=123)++fixture_errors;
    if(fixture_mode==3&&s==&from){fixture_thread=222;
        if(runtime_destroy(&to,1)!=nullptr)++fixture_errors;
        fixture_thread=111;return false;}
    return runtime_available(s)>0;
}
extern "C" void fixture_sleep(U32){
    if(fixture_mode==3){fixture_thread=111;
        if(runtime_available(&from)!=14)++fixture_errors;else ++fixture_closing_reentries;
        fixture_thread=222;
    }
}
static bool setup(){
    si::Config c{};
    if(!MadeiraRuntimePrepareConfig(reinterpret_cast<void *>(fixture_own_module),&c))return false;
    installed.config=c;installed.api={nullptr,query,protect,last_error};
    installed.phase=si::Phase::Installed;installed.result={si::Error::None,0,true};
    installed.module=reinterpret_cast<void *>(fixture_module);
    const U32 methods[]={0x58bf0,0x59100,0x590e0,0x593f0,0x58fa0,0x58e60,0x58dc0};
    for(U32 k=0;k<7;++k)installed.original_entries[k]=fixture_module+methods[k];
    auto *table=reinterpret_cast<void **>(fixture_module+si::stream_vtable_rva);
    U32 old=0;if(!VirtualProtect(table,56,4,&old))return false;
    for(U32 k=0;k<7;++k)table[k]=const_cast<void *>(c.hooks[k]);
    if(!VirtualProtect(table,56,old,&old))return false;
    to.vtable=from.vtable=control.vtable=table;to.id=1;from.id=2;control.id=3;
    auto **controller=reinterpret_cast<void **>(fixture_module+si::controller_object_rva);
    *controller=reinterpret_cast<void *>(fixture_module+si::controller_vtable_rva);
    MadeiraRuntimeNoteInstaller(&installed);
    return true;
}
static void publish(){
    *reinterpret_cast<void **>(fixture_module+si::controller_object_rva+0x170)=&to;
    *reinterpret_cast<void **>(fixture_module+si::controller_object_rva+0x178)=&from;
}
static U32 send(U32 command){Byte bytes[14]{};wr(bytes,2);wr(bytes+4,command);wr(bytes+8,17);bytes[12]=8;bytes[13]=17;
    return runtime_put(&to,bytes,sizeof(bytes));}
extern "C" U64 run_tests(){
    if(!setup()){
        Status s{};if(!MadeiraRuntimeGetStatus(&s,sizeof(s)))return 1;
        if(fixture_mode==8||fixture_mode==10)return s.provider_error==U32(Error::CacheNotVerified)?0:2;
        if(fixture_mode==9)return s.provider_error==U32(Error::WrongProcess)?0:3;
        return 4;
    }
    if(fixture_mode==12){
        installed.phase=si::Phase::Failed;installed.result={si::Error::WrongImage,0,true};
        MadeiraRuntimeNoteInstaller(&installed);MadeiraRuntimeNoteInstaller(&installed);
        Status s{};MadeiraRuntimeGetStatus(&s,sizeof(s));
        return s.installer_phase==U32(si::Phase::Failed)&&s.installer_error==U32(si::Error::WrongImage)?0:44;
    }
    // Null pre-Init fields do not capture a stale scope or wrap bootstrap I/O.
    if(runtime_available(&control)!=73)return 5;
    if(!runtime_wait(&control,false,123))return 6;
    Byte raw[5]={1,2,3,4,5},readback[2]{};
    if(runtime_put(&control,raw,5)!=3||runtime_get(&control,readback,2)!=2||readback[1]!=2)return 38;
    if(runtime_clear(&control,7)||!runtime_clear(&control,1)||runtime_writable(&control)!=8192)return 39;
    if(runtime_destroy(&control,1)!=&control)return 40;
    fixture_original_dtors=fixture_original_puts=0; // Reset only fixture observations between phases.
    Status s{};MadeiraRuntimeGetStatus(&s,sizeof(s));if(s.entry_count)return 7;
    if(fixture_mode==11){
        *reinterpret_cast<void **>(fixture_module+si::controller_object_rva+0x170)=&to;
        if(runtime_available(&to))return 8;MadeiraRuntimeGetStatus(&s,sizeof(s));
        return s.provider_error==U32(Error::PartialPublication)?0:9;
    }
    publish();
    if(fixture_mode==4){fixture_poison=1;if(send(4))return 10;
        MadeiraRuntimeGetStatus(&s,sizeof(s));return s.provider_error==U32(Error::RegistryLockTimeout)?0:11;}
    if(fixture_mode==2){if(send(4))return 12;MadeiraRuntimeGetStatus(&s,sizeof(s));
        if(s.provider_error!=U32(Error::Allocation))return 13;
        if(runtime_destroy(&to,1)!=&to||runtime_destroy(&from,1)!=&from)return 14;return 0;}
    if(fixture_mode==1){if(send(53))return 15;MadeiraRuntimeGetStatus(&s,sizeof(s));
        if(s.provider_error!=U32(Error::CodecFailure)||s.first_command!=53||s.first_direction!=1)return 16;
        if(fixture_original_puts||to.used)return 41;
        if(runtime_available(&from)||runtime_wait(&from,false,123))return 17;
        if(runtime_destroy(&to,1)!=&to||runtime_destroy(&from,1)!=&from)return 18;return 0;}
    if(fixture_mode==7){if(send(4))return 42;MadeiraRuntimeGetStatus(&s,sizeof(s));
        return s.provider_error==U32(Error::ReentrantDestroy)&&!fixture_original_dtors?0:43;}
    if(send(4)!=14||to.used!=14||rd(to.bytes+4)!=12)return 19;
    if(fixture_mode==5){fixture_poison=2;if(runtime_available(&from))return 20;
        if(runtime_destroy(&to,1)!=nullptr)return 21;MadeiraRuntimeGetStatus(&s,sizeof(s));
        return s.provider_error==U32(Error::StateLockTimeout)&&!fixture_original_dtors?0:22;}
    wr(from.bytes,2);wr(from.bytes+4,69);wr(from.bytes+8,17);from.bytes[12]=8;from.bytes[13]=17;from.used=14;
    if(fixture_mode==3){if(runtime_wait(&from,false,123))return 23;
        if(runtime_destroy(&from,1)!=nullptr)return 24;MadeiraRuntimeGetStatus(&s,sizeof(s));
        return s.provider_error==U32(Error::DrainTimeout)&&!fixture_original_dtors&&!fixture_errors?0:25;}
    if(!runtime_wait(&from,false,123))return 26;
    if(runtime_available(&from)!=14)return 27;
    Byte output[14]{};if(runtime_get(&from,output,4)!=4||rd(output)!=2)return 28;
    if(runtime_get(&from,output+4,10)!=10||rd(output+4)!=90||output[13]!=17)return 29;
    if(runtime_available(&from)!=0)return 30;
    if(runtime_destroy(&to,3)!=&to||runtime_destroy(&from,1)!=&from)return 31;
    if(fixture_original_dtors!=2)return 32;
    if(fixture_mode==6){MadeiraRuntimeGetStatus(&s,sizeof(s));
        return s.provider_error==U32(Error::DuplicateDestroy)&&!fixture_errors?0:33;}
    MadeiraRuntimeGetStatus(&s,sizeof(s));U64 old=s.generation;
    to.used=to.read=from.used=from.read=0;
    if(send(4)!=14)return 34;MadeiraRuntimeGetStatus(&s,sizeof(s));
    if(s.entry_count!=2||s.generation==old||s.provider_error)return 35;
    if(runtime_destroy(&to,1)!=&to||runtime_destroy(&from,1)!=&from)return 36;
    return fixture_errors?37:0;
}
