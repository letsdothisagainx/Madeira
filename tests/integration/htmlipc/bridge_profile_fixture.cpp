/* SPDX-License-Identifier: MIT.
 * Real production installer against original Valve PE bytes, never executed.
 * Linux adapts owned mmap/mprotect ranges to the Windows SEC_IMAGE API shape.
 * This does not run Valve DllMain, CEF, Steam, or an authenticated session. */
#include "installer.h"
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>
#include <sys/mman.h>
#include <unistd.h>
namespace si=madeira_stream_install;
using si::U8;using si::U16;using si::U32;using si::U64;
#define CHECK(x) do{if(!(x)){std::fprintf(stderr,"FAIL line %u: %s\n",__LINE__,#x);std::exit(1);}}while(0)
static U16 r16(const U8 *p){return U16(p[0])|U16(p[1])<<8;}
static U32 r32(const U8 *p){return U32(r16(p))|U32(r16(p+2))<<16;}
static U64 r64(const U8 *p){return U64(r32(p))|U64(r32(p+4))<<32;}
static void w64(U8 *p,U64 value){for(unsigned i=0;i<8;i++)p[i]=U8(value>>(8*i));}
static std::vector<U8> read_file(const char *name){
    std::ifstream input(name,std::ios::binary);CHECK(input.good());
    std::vector<U8> bytes{std::istreambuf_iterator<char>(input),{}};
    CHECK(bytes.size()>4096&&bytes.size()<(4u<<20));return bytes;
}
static int posix_protect(U32 value){
    switch(value){case 1:return PROT_NONE;case 2:return PROT_READ;case 4:case 8:return PROT_READ|PROT_WRITE;
    case 0x20:return PROT_READ|PROT_EXEC;default:CHECK(false);return 0;}
}
struct Owned {
    U8 *base;size_t bytes;std::vector<U32> protections;bool alive=true;
    explicit Owned(size_t size):bytes((size+4095)&~size_t(4095)),protections(bytes/4096,4){
        base=static_cast<U8*>(mmap(nullptr,bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0));
        CHECK(base!=MAP_FAILED);
    }
    Owned(const Owned &)=delete;Owned &operator=(const Owned &)=delete;
    ~Owned(){CHECK(munmap(base,bytes)==0);}
    bool contains(const void *address)const{
        auto a=reinterpret_cast<uintptr_t>(address),b=reinterpret_cast<uintptr_t>(base);
        return a>=b&&a-b<bytes;
    }
    bool set(void *address,size_t length,U32 value,U32 *old=nullptr){
        CHECK(contains(address));auto offset=static_cast<U8*>(address)-base;
        CHECK(offset%4096==0&&length%4096==0&&length<=bytes-size_t(offset));
        if(old)*old=protections[size_t(offset)/4096];
        if(mprotect(address,length,posix_protect(value)))return false;
        for(size_t i=size_t(offset)/4096;i<(size_t(offset)+length)/4096;i++)protections[i]=value;
        return true;
    }
    /* Read the actual kernel VM permissions; the test cannot authorize writes
     * merely by changing its Windows protection bookkeeping. */
    bool native_permissions(const void *address,U32 wanted)const{
        FILE *maps=std::fopen("/proc/self/maps","r");CHECK(maps);char row[1024];bool found=false;
        uintptr_t a=reinterpret_cast<uintptr_t>(address),start,end;char permissions[5];
        while(std::fgets(row,sizeof(row),maps))if(std::sscanf(row,"%lx-%lx %4s",&start,&end,permissions)==3&&a>=start&&a<end){
            int actual=(permissions[0]=='r'?PROT_READ:0)|(permissions[1]=='w'?PROT_WRITE:0)|(permissions[2]=='x'?PROT_EXEC:0);
            found=actual==posix_protect(wanted);break;
        }
        CHECK(std::fclose(maps)==0);return found;
    }
};
struct Context {
    Owned hooks{4096};Owned *image=nullptr;unsigned protects=0,fail_at=0;U32 error=0;
    Context(){
        for(unsigned i=0;i<7;i++){
            // Owned AMD64 function: mov eax,slot; ret. No Valve instruction runs.
            U8 *code=hooks.base+i*16;code[0]=0xb8;code[1]=U8(i);code[2]=code[3]=code[4]=0;code[5]=0xc3;
        }
        CHECK(hooks.set(hooks.base,hooks.bytes,0x20));
        for(unsigned i=0;i<7;i++)CHECK(reinterpret_cast<unsigned(*)()>(hooks.base+i*16)()==i);
    }
};
static bool query(void *context,const void *address,si::Region *region){
    auto &c=*static_cast<Context*>(context);Owned *mapping=c.hooks.contains(address)?&c.hooks:c.image;
    if(!mapping||!mapping->alive||!mapping->contains(address))return false;
    size_t page=(static_cast<const U8*>(address)-mapping->base)/4096;U32 protect=mapping->protections[page];
    CHECK(mapping->native_permissions(address,protect));size_t end=page+1;
    while(end<mapping->protections.size()&&mapping->protections[end]==protect)++end;
    // MEM_IMAGE denotes this fixture's explicitly mapped PE/allocation identity.
    *region={mapping->base+page*4096,mapping->base,(end-page)*4096,0x1000,protect,0x1000000};return true;
}
static bool protect(void *context,void *address,si::Size bytes,U32 value,U32 *old){
    auto &c=*static_cast<Context*>(context);++c.protects;
    if(c.fail_at==c.protects){c.error=5;return false;}
    if(!c.image||!c.image->alive||!c.image->contains(address)){c.error=487;return false;}
    if(!c.image->set(address,bytes,value,old)){c.error=U32(errno);return false;}return true;
}
static U32 last_error(void *context){return static_cast<Context*>(context)->error;}
static si::Config config(std::vector<U8> &bytes,Context &c){
    si::Config cfg{};cfg.pinned_file=bytes.data();cfg.pinned_file_size=bytes.size();
    cfg.hook_module=c.hooks.base;cfg.hook_module_size=c.hooks.bytes;
    for(unsigned i=0;i<7;i++)cfg.hooks[i]=c.hooks.base+i*16;
    cfg.generation=1;cfg.wire_contract_ready=true;cfg.redirect_helper_win32=false;return cfg;
}
static si::Api api(Context &c){return {&c,query,protect,last_error};}
#ifndef MADEIRA_BASELINE_PROFILE
struct Image:Owned {
    const si::Profile *profile;U32 sections,count,headers;std::vector<U8> text_before;
    Image(const std::vector<U8> &file,const si::Profile *selected):Owned(selected->image_size),profile(selected){
        U32 nt=r32(file.data()+60),opt=nt+24;count=r16(file.data()+nt+6);sections=opt+r16(file.data()+nt+20);headers=r32(file.data()+opt+60);
        std::memcpy(base,file.data(),headers);
        for(U32 i=0;i<count;i++){
            const U8 *row=file.data()+sections+i*40;U32 rva=r32(row+12),length=r32(row+16),offset=r32(row+20);
            CHECK(rva+length<=bytes&&offset+length<=file.size());std::memcpy(base+rva,file.data()+offset,length);
        }
        U32 reloc=r32(file.data()+opt+112+5*8),reloc_size=r32(file.data()+opt+116+5*8),at=0;
        while(at<reloc_size){
            U32 page=r32(base+reloc+at),block=r32(base+reloc+at+4);CHECK(block>=8&&block%2==0&&block<=reloc_size-at);
            for(U32 n=8;n<block;n+=2){U16 entry=r16(base+reloc+at+n);if(!(entry>>12))continue;
                CHECK(entry>>12==10);U32 target=page+(entry&4095);CHECK(target+8<=bytes);
                w64(base+target,r64(base+target)+reinterpret_cast<U64>(base)-profile->image_base);
            }
            at+=block;
        }
        CHECK(at==reloc_size);
        // The controller object's BSS vptr is normally initialized by DllMain.
        // Seed only that ordinary object state; never execute Valve startup.
        w64(base+profile->controller_object_rva,reinterpret_cast<U64>(base)+profile->controller_vtable_rva);
        CHECK(set(base,bytes,1));CHECK(set(base,(headers+4095)&~U32(4095),2));
        for(U32 i=0;i<count;i++){
            const U8 *row=file.data()+sections+i*40;U32 rva=r32(row+12),length=std::max(r32(row+8),r32(row+16)),flags=r32(row+36);
            if(!length)continue;CHECK(rva%4096==0);
            U32 mode=flags&0x20000000?0x20:flags&0x80000000?4:2;
            CHECK(!(flags&0x20000000)||!(flags&0x80000000));CHECK(set(base+rva,(length+4095)&~U32(4095),mode));
            if(std::memcmp(row,".text",5)==0)text_before.assign(base+rva,base+rva+length);
        }
    }
    void unchanged_text(const std::vector<U8> &file){
        for(U32 i=0;i<count;i++)if(std::memcmp(file.data()+sections+i*40,".text",5)==0){
            const U8 *row=file.data()+sections+i*40;U32 rva=r32(row+12),length=std::max(r32(row+8),r32(row+16));
            CHECK(text_before.size()==length&&!std::memcmp(text_before.data(),base+rva,length));
            CHECK(native_permissions(base+rva,0x20));
        }
    }
    void flip(U32 rva){
        U32 old;U8 *page=base+(rva&~U32(4095));CHECK(set(page,4096,4,&old));base[rva]^=1;CHECK(set(page,4096,old));
    }
};
static const U16 module_name[]={'c','h','r','o','m','e','h','t','m','l','.','d','l','l',0};
static si::Result install(si::Installer &s,Image &image){return si::install_loaded(&s,image.base,image.bytes,module_name,14);}
static void check_original(const si::Profile &p,const Image &image){
    for(unsigned i=0;i<7;i++)CHECK(r64(image.base+p.stream_vtable_rva+i*8)==reinterpret_cast<U64>(image.base)+p.original_rvas[i]);
}
static void exercise(std::vector<U8> bytes,const char *label){
    auto selected=si::profile_for_file(bytes.data(),bytes.size());CHECK(selected);Context c;Image image(bytes,selected);c.image=&image;
    si::Installer s{};CHECK(si::arm(&s,config(bytes,c),api(c)).error==si::Error::None&&s.profile==selected);
    auto installed=install(s,image);
    if(installed.error!=si::Error::None)std::fprintf(stderr,
        "install %s error=%u system=%u stage=%u rva=%x expected=%llx actual=%llx query=%x expected-protect=%x actual-protect=%x\n",
        label,unsigned(installed.error),installed.system_error,unsigned(s.diagnostic.stage),s.diagnostic.rva,
        s.diagnostic.expected_bytes,s.diagnostic.actual_bytes,s.diagnostic.query_flags,
        s.diagnostic.expected_protection,s.diagnostic.actual_protection);
    CHECK(installed.error==si::Error::None&&s.phase==si::Phase::Installed);
    CHECK(c.protects==2);CHECK(image.native_permissions(image.base+selected->stream_vtable_rva,2));
    for(unsigned i=0;i<7;i++)CHECK(r64(image.base+selected->stream_vtable_rva+i*8)==reinterpret_cast<U64>(c.hooks.base+i*16));
    CHECK(std::strcmp(reinterpret_cast<char*>(image.base+selected->helper_path_rva),"bin/cef/cef.win64/steamwebhelper.exe")==0);
    CHECK(si::validate_live_controller(&s,image.base+selected->controller_object_rva));
    U8 *controller=image.base+selected->controller_object_rva;U64 vptr=r64(controller);
    w64(controller,vptr+8);CHECK(!si::validate_live_controller(&s,controller));
    w64(controller,vptr);CHECK(si::validate_live_controller(&s,controller));
    image.unchanged_text(bytes);
    CHECK(install(s,image).error==si::Error::AlreadyInstalled);
    si::note_unloaded(&s,image.base);image.alive=false;
    CHECK(!si::validate_live_controller(&s,image.base+selected->controller_object_rva));
    CHECK(s.result.error==si::Error::ModuleUnloaded);
    for(unsigned failure:{1u,2u}){
        Context fault;Image original(bytes,selected);fault.image=&original;fault.fail_at=failure;si::Installer attempt{};
        CHECK(si::arm(&attempt,config(bytes,fault),api(fault)).error==si::Error::None);
        auto result=install(attempt,original);CHECK(result.error==(failure==1?si::Error::MakeWritableFailed:si::Error::RestoreFailed));
        CHECK(result.rollback_complete&&result.system_error==5);check_original(*selected,original);
        CHECK(original.native_permissions(original.base+selected->stream_vtable_rva,2));original.unchanged_text(bytes);
    }
    {
        auto changed=bytes;changed.back()^=1;Context fault;si::Installer attempt{};
        CHECK(si::arm(&attempt,config(changed,fault),api(fault)).error==si::Error::PinMismatch);
    }
    {
        Context fault;si::Installer attempt{};CHECK(fault.hooks.set(fault.hooks.base,fault.hooks.bytes,4));
        CHECK(si::arm(&attempt,config(bytes,fault),api(fault)).error==si::Error::WrongHook);
    }
    {
        Context fault;Image original(bytes,selected);fault.image=&original;si::Installer attempt{};
        CHECK(si::arm(&attempt,config(bytes,fault),api(fault)).error==si::Error::None);
        bytes.back()^=1;CHECK(install(attempt,original).error==si::Error::PinMismatch);bytes.back()^=1;
        CHECK(!fault.protects);check_original(*selected,original);
    }
    {
        Context fault;Image original(bytes,selected);fault.image=&original;si::Installer attempt{};
        CHECK(si::arm(&attempt,config(bytes,fault),api(fault)).error==si::Error::None);
        original.flip(selected->original_rvas[0]);CHECK(install(attempt,original).error==si::Error::WrongImage);
        CHECK(!fault.protects);check_original(*selected,original);
    }
    std::printf("PASS %s actual-file=%zu mapped=%x selected-controller=%x/%x slots=%u production arm/install/controller; native W^X, hash/section tamper refusal, rollback, unload, unchanged code/helper path\n",
        label,bytes.size(),selected->image_size,selected->controller_object_rva,selected->controller_vtable_rva,selected->controller_slots);
}
#endif
int main(int argc,char **argv){
    CHECK(argc==3&&sysconf(_SC_PAGESIZE)==4096);auto old=read_file(argv[1]),updated=read_file(argv[2]);
#ifdef MADEIRA_BASELINE_PROFILE
    Context c;si::Installer old_s{},updated_s{};
    CHECK(si::arm(&old_s,config(old,c),api(c)).error==si::Error::None);
    CHECK(si::arm(&updated_s,config(updated,c),api(c)).error==si::Error::PinMismatch);
    std::puts("PASS baseline production installer: original official core arms; updated official core reproduces genuine PinMismatch");
#else
    exercise(old,"legacy");exercise(updated,"updated");
    std::puts("NOTE: mapped-file installer proof only; controller BSS seeded without Valve DllMain. No real helper, Steam IPC, iOS session or CS2 launch claimed.");
#endif
}
