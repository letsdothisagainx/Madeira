/* SPDX-License-Identifier: MIT. No instructions or executable pages are edited. */
#include "fixture_args.h"
#include "sha256.h"
namespace madeira_cef_fixture {
static U16 u16(const U8 *p){return U16(p[0])|U16(p[1])<<8;}
static U32 u32(const U8 *p){return U32(u16(p))|U32(u16(p+2))<<16;}
static U64 u64(const U8 *p){return U64(u32(p))|U64(u32(p+4))<<32;}
static bool span(Size a,Size n,Size total){return a<=total&&n<=total-a;}
static bool equal(const U8 *a,const U8 *b,Size n){for(Size i=0;i<n;++i)if(a[i]!=b[i])return false;return true;}
struct PE {const U8 *f;Size n;U32 nt,opt,sections,count,image,headers,imports,imports_size,iat,iat_size,reloc,reloc_size;U64 base;};
static bool parse(const Config &c,PE &p){
    p={};p.f=c.file;p.n=c.file_size;
    if(!p.f||p.n<64||p.n>64*1024*1024||u16(p.f)!=0x5a4d)return false;
    p.nt=u32(p.f+0x3c);if(!span(p.nt,264,p.n)||u32(p.f+p.nt)!=0x4550||u16(p.f+p.nt+4)!=0x8664)return false;
    p.opt=p.nt+24;p.count=u16(p.f+p.nt+6);U32 optional_size=u16(p.f+p.nt+20);
    if(optional_size<240||!p.count||p.count>64||u16(p.f+p.opt)!=0x20b||u32(p.f+p.opt+108)<16)return false;
    p.sections=p.opt+optional_size;if(!span(p.sections,p.count*40,p.n))return false;
    p.image=u32(p.f+p.opt+56);p.headers=u32(p.f+p.opt+60);p.base=u64(p.f+p.opt+24);
    p.imports=u32(p.f+p.opt+120);p.imports_size=u32(p.f+p.opt+124);
    p.iat=u32(p.f+p.opt+208);p.iat_size=u32(p.f+p.opt+212);
    p.reloc=u32(p.f+p.opt+152);p.reloc_size=u32(p.f+p.opt+156);
    if(!p.image||p.image>512*1024*1024||p.headers<p.sections+p.count*40||!span(0,p.headers,p.n)||p.headers>p.image||
       !p.imports||!p.imports_size||!span(p.imports,p.imports_size,p.image)||
       !span(p.iat,p.iat_size,p.image)||!span(p.reloc,p.reloc_size,p.image))return false;
    for(U32 i=0;i<p.count;++i){const U8 *s=p.f+p.sections+i*40;
        if(!span(u32(s+12),u32(s+8),p.image)||!span(u32(s+20),u32(s+16),p.n))return false;}
    return true;
}
static const U8 *at(const PE &p,U32 rva,Size n){
    if(rva<p.headers&&span(rva,n,p.headers))return p.f+rva;
    for(U32 i=0;i<p.count;++i){const U8 *s=p.f+p.sections+i*40;U32 start=u32(s+12),raw=u32(s+16),off=u32(s+20);
        if(rva>=start&&span(rva-start,n,raw)&&span(off+(rva-start),n,p.n))return p.f+off+(rva-start);}
    return nullptr;
}
static bool string_is(const PE &p,U32 rva,const char *expected,bool ignore_case=false){
    for(Size i=0;;++i){if(i>255||U64(rva)+i>0xffffffff)return false;const U8 *c=at(p,rva+U32(i),1);if(!c)return false;
        U8 a=*c,b=U8(expected[i]);if(ignore_case){if(a>='A'&&a<='Z')a+=32;if(b>='A'&&b<='Z')b+=32;}
        if(a!=b)return false;if(!b)return true;}
}
static bool import_slot(const PE &p,U32 &slot){
    U32 matches=0;bool terminated=false;
    for(U32 n=0;n+20<=p.imports_size;n+=20){const U8 *d=at(p,p.imports+n,20);if(!d)return false;
        if(!u32(d)&&!u32(d+4)&&!u32(d+8)&&!u32(d+12)&&!u32(d+16)){terminated=true;break;}
        if(!string_is(p,u32(d+12),"KERNEL32.dll",true))continue;
        U32 lookup=u32(d),iat=u32(d+16);if(!lookup||!iat)return false;
        bool end=false;for(U32 k=0;k<32768;++k){U64 look=U64(lookup)+k*8,entry=U64(iat)+k*8;
            if(look>0xffffffff||entry>0xffffffff)return false;const U8 *t=at(p,U32(look),8);
            if(!t||!at(p,U32(entry),8))return false;U64 name=u64(t);if(!name){end=true;break;}
            if(name>>63)continue;if(name>0xfffffffd)return false;
            if(string_is(p,U32(name)+2,"CreateProcessW")){slot=U32(entry);++matches;}
        }if(!end)return false;
    }
    return terminated&&matches==1&&!(slot&7)&&p.iat_size&&slot>=p.iat&&span(slot-p.iat,8,p.iat_size);
}
static bool query(Installer *s,const void *address,Size length,U32 protection,void *owner){
    U64 current=reinterpret_cast<U64>(address),end=current+length;if(end<current)return false;
    while(current<end){Region r{};if(!s->api.query(s->api.context,reinterpret_cast<void*>(current),&r))return false;
        U64 start=reinterpret_cast<U64>(r.base),limit=start+r.size;
        if(start>current||limit<=current||limit<start||r.state!=0x1000||r.type!=0x1000000||
           r.allocation!=owner||r.protect!=protection)return false;
        current=limit<end?limit:end;}
    return true;
}
struct Relocations {const PE *p;U32 block=0,entry=0,size=0,page=0,previous=0;bool seen=false;};
static bool next(Relocations &r,U32 &target){
    while(r.block<r.p->reloc_size){
        if(!r.size){const U8 *b=at(*r.p,r.p->reloc+r.block,8);if(!b)return false;
            r.page=u32(b);r.size=u32(b+4);r.entry=8;
            if(r.size<8||r.size%2||r.size>r.p->reloc_size-r.block)return false;}
        while(r.entry<r.size){const U8 *v=at(*r.p,r.p->reloc+r.block+r.entry,2);if(!v)return false;r.entry+=2;
            U16 item=u16(v);if(!(item>>12))continue;if(item>>12!=10)return false;
            U64 t=U64(r.page)+(item&4095);if(t>0xffffffff||!span(Size(t),8,r.p->image)||(r.seen&&t<U64(r.previous)+8))return false;
            target=U32(t);r.previous=target;r.seen=true;return true;}
        r.block+=r.size;r.size=0;
    }target=0xffffffff;return true;
}
static bool section(Installer *s,const PE &p,U32 index){
    const U8 *h=p.f+p.sections+index*40;U32 start=u32(h+12),length=u32(h+8),raw=u32(h+16),off=u32(h+20),flags=u32(h+36);
    bool executable=flags&0x20000000,writable=flags&0x80000000;
    if(executable&&writable)return false;if(writable)return true;
    /* Discardable relocation sections can legitimately have been decommitted. */
    if(flags&0x02000000)return true;
    auto *base=static_cast<const U8*>(s->module);
    if(!query(s,base+start,length,executable?0x20:2,s->module))return false;
    Relocations reloc{&p};U32 target;if(!next(reloc,target))return false;
    while(target<start)if(!next(reloc,target))return false;
    for(U32 i=0;i<length;){U32 rva=start+i;
        if(rva>=p.iat&&rva-p.iat<p.iat_size){++i;continue;}
        if(target==rva){const U8 *original=at(p,rva,8);if(!original||length-i<8||
            u64(base+rva)!=u64(original)+reinterpret_cast<U64>(base)-p.base)return false;
            i+=8;if(!next(reloc,target))return false;continue;}
        if(base[rva]!=(i<raw?p.f[off+i]:0))return false;++i;
    }return true;
}
static Result fail(Installer *s,Error error,U32 system=0,bool rollback=true){return s->result={error,system,rollback};}
Result arm(Installer *s,const Config &c,const Api &api){
    if(!s||s->armed||!api.query||!api.protect||!api.last_error||!c.hook||!c.hook_module||
       !c.genuine_create_process||!c.genuine_module)return s?fail(s,Error::InvalidConfig):Result{Error::InvalidConfig,0,true};
    PE p;U8 actual[32];if(!parse(c,p))return fail(s,Error::PinMismatch);
    sha256(c.file,c.file_size,actual);if(!equal(actual,c.sha256,32))return fail(s,Error::PinMismatch);
    U32 slot=0;if(!import_slot(p,slot))return fail(s,Error::WrongImport);
    s->config=c;s->api=api;s->slot_rva=slot;
    if(!query(s,c.hook,1,0x20,c.hook_module)||!query(s,c.genuine_create_process,1,0x20,c.genuine_module))return fail(s,Error::WrongHook);
    s->armed=true;return s->result={Error::None,0,true};
}
Result install(Installer *s,void *module){
    if(!s||!s->armed)return s?fail(s,Error::Disarmed):Result{Error::Disarmed,0,true};
    if(s->installed)return s->result;if(!module)return fail(s,Error::WrongImage);
    s->module=module;PE p;U8 actual[32];if(!parse(s->config,p))return fail(s,Error::PinMismatch);
    sha256(s->config.file,s->config.file_size,actual);if(!equal(actual,s->config.sha256,32))return fail(s,Error::PinMismatch);
    auto *base=static_cast<U8*>(module);if(!query(s,base,p.headers,2,module))return fail(s,Error::WrongImage);
    U64 mapped=reinterpret_cast<U64>(module);U32 image_base=p.opt+24;
    bool wine_rebased=u64(base+image_base)==mapped;
    for(U32 i=0;i<p.headers;++i){U8 expected=wine_rebased&&i>=image_base&&i-image_base<8?U8(mapped>>((i-image_base)*8)):p.f[i];
        if(base[i]!=expected)return fail(s,Error::WrongImage);}
    for(U32 i=0;i<p.count;++i)if(!section(s,p,i))return fail(s,Error::WrongImage);
    U32 page=s->slot_rva&~4095u;bool data_section=false;
    for(U32 i=0;i<p.count;++i){const U8 *h=p.f+p.sections+i*40;U32 start=u32(h+12),length=u32(h+8),flags=u32(h+36);
        if(start<U64(page)+4096&&U64(start)+length>page&&(flags&0x20000000))return fail(s,Error::WrongProtection);
        if(s->slot_rva>=start&&span(s->slot_rva-start,8,length)&&!(flags&(0x20000000u|0x80000000u)))data_section=true;}
    if(!data_section||!query(s,base+page,4096,2,module))return fail(s,Error::WrongProtection);
    auto *slot=reinterpret_cast<U64*>(base+s->slot_rva);U64 genuine=reinterpret_cast<U64>(s->config.genuine_create_process);
    if(__atomic_load_n(slot,__ATOMIC_ACQUIRE)!=genuine)return fail(s,Error::NotResolved);
    U32 old=0;if(!s->api.protect(s->api.context,base+page,4096,4,&old))return fail(s,Error::MakeWritableFailed,s->api.last_error(s->api.context));
    if(old!=2){U32 ignored=0;
        /* Never turn an unexpected/raced protection value into an executable
         * request. The only restoration target is the validated original R. */
        bool restored=s->api.protect(s->api.context,base+page,4096,2,&ignored)&&query(s,base+page,4096,2,module);
        return fail(s,restored?Error::WrongProtection:Error::RollbackIncomplete,0,restored);}
    U64 expected=genuine;bool replaced=__atomic_compare_exchange_n(slot,&expected,reinterpret_cast<U64>(s->config.hook),false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);
    U32 ignored=0;bool restored=s->api.protect(s->api.context,base+page,4096,2,&ignored)&&query(s,base+page,4096,2,module);
    if(!restored){U32 first=s->api.last_error(s->api.context);bool writable=query(s,base+page,4096,4,module);
        if(!writable){U32 previous=0;writable=s->api.protect(s->api.context,base+page,4096,4,&previous);}
        bool undone=!replaced;if(writable&&replaced){U64 hook=reinterpret_cast<U64>(s->config.hook);
            undone=__atomic_compare_exchange_n(slot,&hook,genuine,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);}
        bool final=s->api.protect(s->api.context,base+page,4096,2,&ignored)&&query(s,base+page,4096,2,module);
        return fail(s,undone&&final?Error::RestoreFailed:Error::RollbackIncomplete,first,undone&&final);}
    if(!replaced)return fail(s,Error::NotResolved);
    s->installed=true;return s->result={Error::None,0,true};
}
}
