/* SPDX-License-Identifier: MIT */
#include "installer.h"
#include "sha256.h"
namespace madeira_stream_install {
static constexpr U32 original_rvas[7]={0x58bf0,0x59100,0x590e0,0x593f0,0x58fa0,0x58e60,0x58dc0};
static constexpr U8 digest[32]={0x37,0xf5,0xdd,0xbe,0x87,0x43,0x62,0xd7,0x29,0xb7,0xcd,0x33,0x50,0x49,0x43,0xa9,0xd6,0x49,0xd8,0x45,0x52,0x5a,0xfa,0xe4,0xbc,0xc2,0xaf,0x36,0xab,0x97,0x1f,0x4b};
static constexpr char old_path[]="bin/cef/cef.win64/steamwebhelper.exe";
static constexpr char new_path[]="bin/cef/cef.win32/steamwebhelper.exe";
static_assert(sizeof(old_path)==37 && sizeof(old_path)==sizeof(new_path));
static U16 u16(const U8 *p){return U16(p[0])|U16(p[1])<<8;}
static U32 u32(const U8 *p){return U32(u16(p))|U32(u16(p+2))<<16;}
static U64 u64(const U8 *p){return U64(u32(p))|U64(u32(p+4))<<32;}
static bool equal(const void *aa,const void *bb,Size n){auto a=static_cast<const U8*>(aa);auto b=static_cast<const U8*>(bb);for(Size i=0;i<n;++i)if(a[i]!=b[i])return false;return true;}
static bool span(Size at,Size n,Size total){return at<=total && n<=total-at;}
static Result fail(Installer *s,Error error,U32 system=0,bool rolled_back=true){
    if(s){s->phase=Phase::Failed;s->result={error,system,rolled_back};return s->result;}
    return {error,system,rolled_back};
}
static void diagnose(Installer *s,Stage stage,U32 rva,U64 expected=0,U64 actual=0,
                     U32 count=0,U32 expected_protect=0,U32 actual_protect=0,U32 flags=0){
    if(!s||stage==Stage::None||s->diagnostic.stage!=Stage::None)return;
    auto &d=s->diagnostic;d.stage=stage;d.rva=rva;d.expected_bytes=expected;
    d.actual_bytes=actual;d.byte_count=count;d.expected_protection=expected_protect;
    d.actual_protection=actual_protect;d.query_flags=flags;
}
struct PE {const U8 *f;Size n;U32 nt,optional,sections,count,image_size,headers,iat,iat_size,reloc,reloc_size;U64 base;};
static bool parse(const Config &c,PE &p){
    p={};p.f=c.pinned_file;p.n=c.pinned_file_size;
    if(!p.f || p.n!=1668248 || u16(p.f)!=0x5a4d)return false;
    p.nt=u32(p.f+0x3c);
    if(!span(p.nt,264,p.n)||u32(p.f+p.nt)!=0x4550||u16(p.f+p.nt+4)!=0x8664)return false;
    p.count=u16(p.f+p.nt+6);p.optional=p.nt+24;p.sections=p.optional+u16(p.f+p.nt+20);
    if(p.count!=6||!span(p.sections,p.count*40,p.n)||u16(p.f+p.optional)!=0x20b)return false;
    p.base=u64(p.f+p.optional+24);p.image_size=u32(p.f+p.optional+56);p.headers=u32(p.f+p.optional+60);
    p.iat=u32(p.f+p.optional+112+12*8);p.iat_size=u32(p.f+p.optional+116+12*8);
    p.reloc=u32(p.f+p.optional+112+5*8);p.reloc_size=u32(p.f+p.optional+116+5*8);
    return p.base==0x180000000ULL && p.image_size==0x19c000 &&
      u32(p.f+p.nt+8)==0x6ad92a63 && span(p.headers,0,p.n) &&
      span(p.iat,p.iat_size,p.image_size)&&span(p.reloc,p.reloc_size,p.image_size);
}
static const U8 *at(const PE &p,U32 rva,Size n){
    if(rva<p.headers && span(rva,n,p.headers)&&span(rva,n,p.n))return p.f+rva;
    for(U32 i=0;i<p.count;++i){const U8 *s=p.f+p.sections+i*40;U32 v=u32(s+12),raw=u32(s+16),off=u32(s+20);
        if(rva>=v && span(rva-v,n,raw)&&span(off+(rva-v),n,p.n))return p.f+off+(rva-v);
    }return nullptr;
}
static bool pin(const Config &c,PE &p){
    if(!parse(c,p))return false;U8 actual[32];sha256(c.pinned_file,c.pinned_file_size,actual);return equal(actual,digest,32);
}
static bool query_span(Installer *s,const void *address,Size bytes,U32 expected,void *allocation,Stage stage=Stage::None){
    U64 cursor=reinterpret_cast<U64>(address),end=cursor+bytes;
    if(end<cursor){diagnose(s,stage,U32(cursor-reinterpret_cast<U64>(s->module)),0,0,0,expected,0,2);return false;}
    while(cursor<end){Region r{};U32 rva=U32(cursor-reinterpret_cast<U64>(s->module));
        if(!s->api.query(s->api.context,reinterpret_cast<void*>(cursor),&r)){
            diagnose(s,stage,rva,0,0,0,expected,0,1);return false;}
        U64 b=reinterpret_cast<U64>(r.base),z=b+r.size;
        U32 flags=0;if(b>cursor||z<=cursor||z<b)flags|=2;if(r.state!=0x1000)flags|=4;
        if(r.type!=0x1000000)flags|=8;if(r.allocation!=allocation)flags|=16;if(r.protect!=expected)flags|=32;
        if(flags){diagnose(s,stage,rva,0,0,0,expected,r.protect,flags);return false;}
        cursor=z<end?z:end;
    }return true;
}
struct Relocations {const PE *p;U32 block=0,entry=0,block_size=0,page=0;};
static bool next_reloc(Relocations &r,U32 &target){
    while(r.block<r.p->reloc_size){
        if(!r.block_size){const U8 *b=at(*r.p,r.p->reloc+r.block,8);if(!b)return false;
            r.page=u32(b);r.block_size=u32(b+4);r.entry=8;
            if(r.block_size<8||r.block_size%2||r.block_size>r.p->reloc_size-r.block)return false;}
        while(r.entry<r.block_size){const U8 *e=at(*r.p,r.p->reloc+r.block+r.entry,2);if(!e)return false;r.entry+=2;U16 item=u16(e);
            if(item>>12==0)continue;if(item>>12!=10)return false;target=r.page+(item&0xfff);return true;}
        r.block+=r.block_size;r.block_size=0;
    }target=0xffffffff;return true;
}
/* Snapshot at most eight bytes already identified as a first mismatch.
 * Query each byte before reading; no attempt is made to relax validation.
 * Section snapshots normalize the same DIR64 entries as comparison. */
static void snapshot(Installer *s,const PE &p,bool header=false){
    auto &d=s->diagnostic;if(d.stage==Stage::None||d.byte_count)return;
    U32 start=d.rva;U8 *base=static_cast<U8*>(s->module);
    Relocations it{&p};U32 relocation=0xffffffff;
    if(!header&&!next_reloc(it,relocation))return;
    for(U32 i=0;i<8&&start+i<p.image_size;++i){U32 rva=start+i;Region q{};
        if(!s->api.query(s->api.context,base+rva,&q)||q.state!=0x1000||q.type!=0x1000000||q.allocation!=s->module||
           (q.protect&0x100)||!(q.protect==2||q.protect==4||q.protect==8||q.protect==0x20||q.protect==0x40||q.protect==0x80))break;
        U64 b=reinterpret_cast<U64>(q.base),a=reinterpret_cast<U64>(base+rva);
        if(a<b||a-b>=q.size)break;
        const U8 *raw=at(p,rva,1);if(!raw)break;
        U8 expected=*raw;
        if(!header){
            if(rva>=p.iat&&rva-p.iat<p.iat_size)break;
            while(relocation!=0xffffffff&&U64(relocation)+8<=rva)if(!next_reloc(it,relocation))return;
            if(relocation<=rva&&rva-relocation<8){const U8 *v=at(p,relocation,8);if(!v)break;
                U64 relocated=u64(v)+reinterpret_cast<U64>(base)-p.base;expected=U8(relocated>>((rva-relocation)*8));}
        }
        d.expected_bytes|=U64(expected)<<(i*8);d.actual_bytes|=U64(base[rva])<<(i*8);++d.byte_count;
    }
}
static bool compare_section(Installer *s,const PE &p,U32 section){
    const U8 *h=p.f+p.sections+section*40;U32 start=u32(h+12),length=u32(h+8),raw=u32(h+16),off=u32(h+20),flags=u32(h+36);
    if(!span(start,length,p.image_size)||!span(off,raw,p.n)){
        diagnose(s,Stage::SectionBounds,start,p.image_size,U64(start)+length);return false;}
    U8 *base=static_cast<U8*>(s->module);U32 protect=(flags&0x20000000)?0x20:2;
    if(!query_span(s,base+start,length,protect,s->module,Stage::SectionProtection)){snapshot(s,p);return false;}
    Relocations it{&p};U32 relocation;if(!next_reloc(it,relocation)){diagnose(s,Stage::Relocation,p.reloc);return false;}
    while(relocation<start)if(!next_reloc(it,relocation)){diagnose(s,Stage::Relocation,p.reloc+it.block);return false;}
    for(U32 i=0;i<length;){U32 rva=start+i;
        if(rva>=p.iat && rva-p.iat<p.iat_size){++i;continue;}
        if(relocation==rva){const U8 *original=at(p,rva,8);if(!original||length-i<8){diagnose(s,Stage::Relocation,rva);return false;}
            U64 wanted=u64(original)+reinterpret_cast<U64>(base)-p.base,actual=u64(base+rva);
            if(actual!=wanted){diagnose(s,Stage::Relocation,rva,wanted,actual,8,protect,protect);return false;}
            i+=8;if(!next_reloc(it,relocation)){diagnose(s,Stage::Relocation,p.reloc+it.block);return false;}continue;}
        U8 expected=i<raw?p.f[off+i]:0;
        if(base[rva]!=expected){diagnose(s,Stage::SectionBytes,rva,0,0,0,protect,protect);snapshot(s,p);return false;}++i;
    }return true;
}
static bool name_is_current(const U16 *name,Size units){
    static constexpr char expected[]="chromehtml.dll";
    if(!name||units!=sizeof(expected)-1)return false;
    for(Size i=0;i<units;++i){U16 v=name[i];if(v>='A'&&v<='Z')v+=32;if(v!=U16(expected[i]))return false;}return true;
}
Result arm(Installer *s,const Config &c,const Api &a){
    if(!s||s->phase!=Phase::Disarmed)return fail(s,Error::InvalidConfig);
    if(!a.query||!a.protect||!a.last_error||!c.generation||!c.wire_contract_ready||!c.hook_module||!c.hook_module_size)
        return fail(s,Error::InvalidConfig);
    PE p;if(!pin(c,p))return fail(s,Error::PinMismatch);
    U64 lo=reinterpret_cast<U64>(c.hook_module),hi=lo+c.hook_module_size;
    if(hi<lo)return fail(s,Error::InvalidConfig);
    for(auto hook:c.hooks){U64 address=reinterpret_cast<U64>(hook);Region r{};
        if(address<lo||address>=hi||!a.query(a.context,hook,&r)||r.allocation!=c.hook_module||r.state!=0x1000||
            r.type!=0x1000000||r.protect!=0x20)return fail(s,Error::WrongHook);}
    s->config=c;s->api=a;s->phase=Phase::Armed;s->result={Error::None,0,true};return s->result;
}
static bool restore_pages(Installer *s,void *const pages[2],U32 count,const U32 old[2],U32 *first_error=nullptr){
    bool ok=true;for(U32 i=count;i>0;--i){U32 ignored;if(!s->api.protect(s->api.context,pages[i-1],4096,old[i-1],&ignored)){
            if(first_error&&!*first_error)*first_error=s->api.last_error(s->api.context);ok=false;}
        Region r{};if(!s->api.query(s->api.context,pages[i-1],&r)||r.protect!=old[i-1]){
            if(first_error&&!*first_error)*first_error=s->api.last_error(s->api.context);ok=false;}}return ok;
}
Result install_loaded(Installer *s,void *module,Size image_size,const U16 *name,Size units){
    if(!s||s->phase!=Phase::Armed)return s?fail(s,s->phase==Phase::Installed?Error::AlreadyInstalled:Error::NotArmed):Result{Error::NotArmed,0,true};
    s->diagnostic.actual_image_size=image_size;
    if(!name_is_current(name,units))return fail(s,Error::WrongModule);
    if(!module||image_size!=0x19c000){diagnose(s,Stage::ModuleSize,0,0x19c000,image_size);return fail(s,Error::WrongImage);}
    s->module=module;PE p;if(!pin(s->config,p))return fail(s,Error::PinMismatch);
    if(!query_span(s,module,p.headers,2,module,Stage::HeaderProtection)){snapshot(s,p,true);return fail(s,Error::WrongImage);}
    /* Wine's SEC_IMAGE mapper rewrites OptionalHeader.ImageBase to map_addr
     * while applying dynamic-base relocations (ntdll/unix/virtual.c). Windows
     * may retain the preferred base. Accept exactly those two representations,
     * never an arbitrary changed header or a base supplied by the image itself.
     * The original SHA-pinned file still supplies all relocation expectations. */
    U32 image_base_rva=p.optional+24;U64 mapped_base=reinterpret_cast<U64>(module);
    bool header_rebased=u64(static_cast<U8*>(module)+image_base_rva)==mapped_base;
    for(U32 i=0;i<p.headers;++i){
        U8 expected=(header_rebased&&i>=image_base_rva&&i-image_base_rva<8)?
            U8(mapped_base>>((i-image_base_rva)*8)):p.f[i];
        if(static_cast<U8*>(module)[i]!=expected){
            diagnose(s,Stage::HeaderBytes,i,0,0,0,2,2);snapshot(s,p,true);return fail(s,Error::WrongImage);}}
    /* Verify the complete mapped .text/.rdata/.pdata against the original
     * SHA-pinned file. Normalize only PE DIR64 relocations and loader IAT.
     * Mutable .data is checked separately for the exact RTTI type names. */
    for(U32 i=0;i<p.count;++i){const U8 *h=p.f+p.sections+i*40;
        if((equal(h,".text",5)||equal(h,".rdata",6)||equal(h,".pdata",6))&&!compare_section(s,p,i))return fail(s,Error::WrongImage);}
    U8 *base=static_cast<U8*>(module);auto table=reinterpret_cast<volatile U64*>(base+stream_vtable_rva);
    if(u64(base+0x132338)!=reinterpret_cast<U64>(base)+0x15c550){
        diagnose(s,Stage::Metadata,0x132338,reinterpret_cast<U64>(base)+0x15c550,u64(base+0x132338),8);return fail(s,Error::WrongMetadata);}
    const U32 metadata_rvas[3]={0x15c550,0x17f428,0x17f400};
    const U8 *metadata_expected[3]={at(p,0x15c550,24),reinterpret_cast<const U8*>(".?AVCSharedMemStream@@"),reinterpret_cast<const U8*>(".?AVIMemStream@@")};
    const U32 metadata_lengths[3]={24,22,16};
    for(U32 m=0;m<3;++m)for(U32 i=0;i<metadata_lengths[m];++i)if(base[metadata_rvas[m]+i]!=metadata_expected[m][i]){
        diagnose(s,Stage::Metadata,metadata_rvas[m]+i);snapshot(s,p);return fail(s,Error::WrongMetadata);}
    for(U32 i=0;i<7;++i){s->original_entries[i]=reinterpret_cast<U64>(base)+original_rvas[i];if(table[i]!=s->original_entries[i]){
        diagnose(s,Stage::Metadata,stream_vtable_rva+i*8,s->original_entries[i],table[i],8);return fail(s,Error::WrongMetadata);}}
    for(U32 i=0;i<sizeof(old_path);++i)if(base[0x121ce0+i]!=U8(old_path[i])){
        diagnose(s,Stage::Metadata,0x121ce0+i);snapshot(s,p);return fail(s,Error::WrongMetadata);}
    if(u64(base+0x121cd8)!=reinterpret_cast<U64>(base)+0x121ce0){
        diagnose(s,Stage::Metadata,0x121cd8,reinterpret_cast<U64>(base)+0x121ce0,u64(base+0x121cd8),8);return fail(s,Error::WrongMetadata);}
    void *pages[2]={base+0x132000,base+0x121000};U32 old[2]{};U32 count=s->config.redirect_helper_win32?2:1;
    for(U32 i=0;i<count;++i){if(!query_span(s,pages[i],4096,2,module))return fail(s,Error::WrongProtection);
        if(!s->api.protect(s->api.context,pages[i],4096,4,&old[i])){U32 error=s->api.last_error(s->api.context);bool restored=restore_pages(s,pages,i,old);return fail(s,restored?Error::MakeWritableFailed:Error::RollbackIncomplete,error,restored);}
        if(old[i]!=2){bool restored=restore_pages(s,pages,i+1,old);return fail(s,Error::WrongProtection,0,restored);}}
    for(U32 i=0;i<7;++i)table[i]=reinterpret_cast<U64>(s->config.hooks[i]);
    if(s->config.redirect_helper_win32)for(U32 i=0;i<sizeof(new_path);++i)base[0x121ce0+i]=U8(new_path[i]);
    U32 first_restore_error=0;
    if(!restore_pages(s,pages,count,old,&first_restore_error)){
        U32 first=first_restore_error;bool writable=true;
        for(U32 i=0;i<count;++i){Region q{};if(!s->api.query(s->api.context,pages[i],&q)){writable=false;continue;}
            if(q.protect!=4){U32 ignored;if(!s->api.protect(s->api.context,pages[i],4096,4,&ignored))writable=false;}}
        if(writable){for(U32 i=0;i<7;++i)table[i]=s->original_entries[i];
            if(s->config.redirect_helper_win32)for(U32 i=0;i<sizeof(old_path);++i)base[0x121ce0+i]=U8(old_path[i]);}
        bool restored=restore_pages(s,pages,count,old);
        return fail(s,writable&&restored?Error::RestoreFailed:Error::RollbackIncomplete,first,writable&&restored);
    }
    s->phase=Phase::Installed;s->result={Error::None,0,true};return s->result;
}
void note_unloaded(Installer *s,void *module){if(s&&s->module==module)fail(s,Error::ModuleUnloaded,0,false);}
bool validate_live_controller(Installer *s,void *controller){
    if(!s||s->phase!=Phase::Installed||!s->module||controller!=static_cast<U8*>(s->module)+controller_object_rva)return false;
    if(!query_span(s,controller,8,4,s->module))return false;
    U8 *base=static_cast<U8*>(s->module);if(u64(static_cast<U8*>(controller))!=reinterpret_cast<U64>(base)+controller_vtable_rva)return false;
    PE p;if(!parse(s->config,p))return false;
    for(U32 i=0;i<42;++i){const U8 *original=at(p,controller_vtable_rva+i*8,8);if(!original||u64(base+controller_vtable_rva+i*8)!=u64(original)+reinterpret_cast<U64>(base)-p.base)return false;}
    return true;
}
}
