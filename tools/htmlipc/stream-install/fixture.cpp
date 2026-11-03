/* SPDX-License-Identifier: MIT. Import-free MSVC-target installer fixture. */
#include "installer.h"
using namespace madeira_stream_install;
static constexpr U64 module_base=0x280000000ULL,pin_base=0x900000000ULL;
extern "C" U32 test_mode=0,protect_calls=0,api_error=0;
extern "C" Diagnostic last_diagnostic{};
extern "C" U32 page_protections[0x19c]{};
extern "C" void *memset(void *p,int c,Size n){auto b=static_cast<volatile U8*>(p);for(Size i=0;i<n;++i)b[i]=U8(c);return p;}
extern "C" void *memcpy(void *p,const void *q,Size n){auto a=static_cast<volatile U8*>(p);auto b=static_cast<const volatile U8*>(q);for(Size i=0;i<n;++i)a[i]=b[i];return p;}
extern "C" __declspec(noinline) void hook(){__builtin_trap();}
static bool query(void *,const void *ptr,Region *r){U64 p=reinterpret_cast<U64>(ptr);
    if(p>=module_base&&p<module_base+0x19c000){U32 page=U32((p-module_base)>>12);
        *r={reinterpret_cast<void*>(p&~4095ULL),reinterpret_cast<void*>(module_base),4096,0x1000,page_protections[page],0x1000000};return true;}
    if(p>=0x180000000ULL&&p<0x180100000ULL){*r={reinterpret_cast<void*>(0x180000000ULL),reinterpret_cast<void*>(0x180000000ULL),0x100000,0x1000,test_mode==6?0x40U:0x20U,0x1000000};return true;}
    return false;
}
extern "C" __declspec(noinline) bool fake_protect(void *,void *ptr,Size n,U32 value,U32 *old){
    ++protect_calls;U64 p=reinterpret_cast<U64>(ptr);
    if(n!=4096||p%4096||p<module_base||p>=module_base+0x19c000||(value!=2&&value!=4)){api_error=87;return false;}
    if((test_mode==1&&protect_calls==1)||(test_mode==2&&protect_calls==3)||(test_mode==3&&value==2)){api_error=57;return false;}
    U32 page=U32((p-module_base)>>12);*old=page_protections[page];page_protections[page]=value;return true;
}
static U32 error(void *){return api_error;}
extern "C" U64 run_tests(){
    for(U32 i=0;i<0x19c;++i)page_protections[i]=2;
    for(U32 i=1;i<0x120;++i)page_protections[i]=0x20;
    for(U32 i=0x177;i<0x185;++i)page_protections[i]=4;
    page_protections[0x197]=4;
    if(test_mode==12)page_protections[0]=4;
    if(test_mode==13)page_protections[1]=2;
    Installer state;Config c{};c.pinned_file=reinterpret_cast<const U8*>(pin_base);c.pinned_file_size=1668248;
    c.hook_module=reinterpret_cast<void*>(0x180000000ULL);c.hook_module_size=0x100000;
    for(U32 i=0;i<7;++i)c.hooks[i]=reinterpret_cast<const void*>(hook);
    c.generation=3;c.wire_contract_ready=test_mode!=8;c.redirect_helper_win32=test_mode!=9;
    Api a{nullptr,query,fake_protect,error};Result armed=arm(&state,c,a);
    if(test_mode==4)return armed.error==Error::PinMismatch?0:1;
    if(test_mode==6)return armed.error==Error::WrongHook?0:2;
    if(test_mode==8)return armed.error==Error::InvalidConfig?0:3;
    if(armed.error!=Error::None)return 4;
    const U16 name[]={'c','h','r','o','m','e','h','t','m','l','.','d','l','l'};
    Result result=install_loaded(&state,reinterpret_cast<void*>(module_base),test_mode==14?0x19c001:0x19c000,name,14);
    last_diagnostic=state.diagnostic;
    if(test_mode==1)return result.error==Error::MakeWritableFailed&&result.system_error==57&&result.rollback_complete?0:5;
    if(test_mode==2)return result.error==Error::RestoreFailed&&result.system_error==57&&result.rollback_complete?0:6;
    if(test_mode==3)return result.error==Error::RollbackIncomplete&&result.system_error==57&&!result.rollback_complete?0:7;
    if(test_mode==5)return result.error==Error::WrongMetadata&&state.diagnostic.stage==Stage::Metadata&&state.diagnostic.rva==0x17f428?0:8;
    if(test_mode==7)return result.error==Error::WrongImage&&state.diagnostic.stage==Stage::Relocation&&state.diagnostic.rva==0x132340?0:9;
    if(test_mode==10)return result.error==Error::WrongImage&&state.diagnostic.stage==Stage::SectionBytes&&state.diagnostic.rva==0x1000?0:42;
    if(test_mode==16||test_mode==17||test_mode==19)return result.error==Error::WrongImage&&state.diagnostic.stage==Stage::HeaderBytes?0:43;
    if(test_mode==18)return result.error==Error::WrongImage&&state.diagnostic.stage==Stage::SectionBytes&&state.diagnostic.rva==0x1000?0:49;
    if(test_mode==12)return result.error==Error::WrongImage&&state.diagnostic.stage==Stage::HeaderProtection&&state.diagnostic.rva==0?0:44;
    if(test_mode==13)return result.error==Error::WrongImage&&state.diagnostic.stage==Stage::SectionProtection&&state.diagnostic.rva==0x1000?0:45;
    if(test_mode==14)return result.error==Error::WrongImage&&state.diagnostic.stage==Stage::ModuleSize&&state.diagnostic.actual_image_size==0x19c001?0:46;
    if(test_mode==15)return result.error==Error::WrongImage&&state.diagnostic.stage==Stage::SectionBytes&&state.diagnostic.rva==0x121ce0?0:47;
    if(result.error!=Error::None||state.phase!=Phase::Installed)return 10+U64(result.error);
    if(state.diagnostic.stage!=Stage::None)return 48;
    if(page_protections[0x132]!=2||page_protections[0x121]!=2)return 40;
    auto object=reinterpret_cast<U64*>(module_base+controller_object_rva);
    *object=module_base+controller_vtable_rva;
    if(!validate_live_controller(&state,object))return 41;
    return 0;
}
