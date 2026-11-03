/* SPDX-License-Identifier: MIT. Installed-state validation fixture, not a Steam image. */
#include "installer.h"
#include <cstdio>
#include <vector>
#include <cstdint>
namespace si=madeira_stream_install;
using si::U8;using si::U32;using si::U64;
static void w16(U8 *p,unsigned n){p[0]=U8(n);p[1]=U8(n>>8);}
static void w32(U8 *p,U32 n){for(unsigned i=0;i<4;++i)p[i]=U8(n>>(8*i));}
static void w64(U8 *p,U64 n){for(unsigned i=0;i<8;++i)p[i]=U8(n>>(8*i));}
struct Mapping {U8 *base;U32 protect=4,state=0x1000,type=0x1000000;bool owner=true,range=true,query_ok=true;unsigned writes=0;};
static bool query(void *ctx,const void *address,si::Region *out){
    auto &m=*static_cast<Mapping *>(ctx);if(!m.query_ok)return false;
    U64 a=reinterpret_cast<U64>(address),base=reinterpret_cast<U64>(m.base);
    if(a<base||a-base>=0x19c000)return false;
    *out={m.range?const_cast<void *>(address):m.base+0x19c000,m.owner?m.base:m.base+8,4096,m.state,m.protect,m.type};return true;
}
static bool protect(void *ctx,void *,si::Size,U32,U32 *){++static_cast<Mapping *>(ctx)->writes;return false;}
static U32 last_error(void *){return 5;}
int main(){
    std::vector<U8> file(1668248),image(0x19c000);U8 *f=file.data(),*b=image.data();
    w16(f,0x5a4d);w32(f+0x3c,0x80);w32(f+0x80,0x4550);w16(f+0x84,0x8664);w16(f+0x86,6);
    w32(f+0x88,0x6ad92a63);w16(f+0x94,240);w16(f+0x98,0x20b);w64(f+0xb0,0x180000000ULL);
    w32(f+0xd0,0x19c000);w32(f+0xd4,0x400);
    w32(f+0x188+12,0x120000);w32(f+0x188+16,0x50000);w32(f+0x188+20,0x1000);
    const U64 base=reinterpret_cast<U64>(b);
    for(U32 i=0;i<42;++i){w64(f+0x1000+(si::controller_vtable_rva-0x120000)+i*8,0x180001000ULL+i*16);w64(b+si::controller_vtable_rva+i*8,base+0x1000+i*16);}
    w64(b+si::controller_object_rva,base+si::controller_vtable_rva);
    Mapping m{b};si::Installer s{};s.module=b;s.phase=si::Phase::Installed;s.api={&m,query,protect,last_error};
    s.config.pinned_file=f;s.config.pinned_file_size=file.size();
    unsigned cases=0;
    auto expect=[&](const char *name,bool wanted){++cases;s.diagnostic={};bool actual=si::validate_live_controller(&s,b+si::controller_object_rva);
        if(actual!=wanted){std::fprintf(stderr,"FAIL %s expected=%u actual=%u protect=%x\n",name,unsigned(wanted),unsigned(actual),m.protect);return false;}return true;};
    if(!expect("owned committed MEM_IMAGE PAGE_READWRITE",true))return 1;
    m.protect=8;if(!expect("owned committed MEM_IMAGE PAGE_WRITECOPY",true))return 1;
    for(U32 p:{0u,1u,2u,0x10u,0x20u,0x40u,0x80u,0x104u,0x108u,0x204u}){m.protect=p;if(!expect("unexpected data page protection",false))return 1;}
    m.protect=8;m.owner=false;if(!expect("wrong image allocation owner",false))return 1;m.owner=true;
    m.type=0x20000;if(!expect("private allocation in place of image",false))return 1;m.type=0x1000000;
    m.state=0x2000;if(!expect("uncommitted reservation",false))return 1;m.state=0x1000;
    m.range=false;if(!expect("bad region range",false))return 1;m.range=true;
    m.query_ok=false;if(!expect("VirtualQuery failure",false))return 1;m.query_ok=true;
    w64(b+si::controller_object_rva,base+si::controller_vtable_rva+8);if(!expect("changed object vtable",false))return 1;
    w64(b+si::controller_object_rva,base+si::controller_vtable_rva);
    for(U32 slot:{0u,20u,41u}){w64(b+si::controller_vtable_rva+slot*8,base+0x1001+slot*16);if(!expect("changed pinned vtable entry",false))return 1;w64(b+si::controller_vtable_rva+slot*8,base+0x1000+slot*16);}
    s.config.pinned_file_size=0;if(!expect("missing original file metadata",false))return 1;s.config.pinned_file_size=file.size();
    s.phase=si::Phase::Failed;if(!expect("retired or failed module",false))return 1;s.phase=si::Phase::Installed;
    if(si::validate_live_controller(&s,b+si::controller_object_rva+8))return 1;++cases;
    if(!expect("restored owned copy-on-write image",true)||m.writes)return 1;
    // Synthetic installed-state metadata cannot arm the real hash-pinned installer.
    si::Installer untrusted{};auto config=s.config;config.generation=1;config.wire_contract_ready=true;config.hook_module=b;config.hook_module_size=image.size();
    if(si::arm(&untrusted,config,s.api).error!=si::Error::PinMismatch)return 1;++cases;
    std::printf("PASS %u controller image-protection/ownership cases; no protect calls; synthetic fixture cannot arm production installer\n",cases);
}
