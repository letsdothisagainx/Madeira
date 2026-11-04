/* SPDX-License-Identifier: MIT. Protocol/registry tests; no simulated Steam success. */
#include "domain_registry.h"
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <map>
#include <string>
#include <vector>
namespace d=madeira_domain;
using B=std::vector<d::Byte>;
struct Heap {std::map<void *,d::Size> live;bool fail=false;};
static void *allocate(void *p,d::Size n){auto &h=*static_cast<Heap *>(p);if(h.fail)return nullptr;void *a=std::malloc(n);assert(a);h.live[a]=n;return a;}
static void release(void *p,void *a){auto &h=*static_cast<Heap *>(p);assert(h.live.erase(a)==1);std::free(a);}
static d::Bytes view(const std::string &s){return {reinterpret_cast<const d::Byte *>(s.data()),s.size()};}
static void varint(B &b,d::U64 n){while(n>=128){b.push_back(d::Byte(n)|128);n>>=7;}b.push_back(d::Byte(n));}
static void field(B &b,unsigned id,const std::string &s){varint(b,id*8+2);varint(b,s.size());b.insert(b.end(),s.begin(),s.end());}
static d::Error message(d::Registry &r,d::Owner owner,const B &b){d::Registration v{};auto e=d::parse_registration({b.data(),b.size()},&v);return e==d::Error::Ok?d::update(&r,owner,v):e;}
int main(){
    Heap heap;d::Registry r{};d::Owner owner{0x600310000,18},foreign{owner.process,19};
    assert(d::open(&r,owner,{&heap,allocate,release})==d::Error::Ok);
    B b;field(b,1,"steamloopback.host");field(b,2,"C:\\Steam\\steamui");
    assert(message(r,owner,b)==d::Error::Ok&&r.records==1);
    d::Byte output[256];std::memset(output,0xa5,sizeof(output));
    auto lookup=[&](const char *name){return d::lookup(&r,owner,view(name),output,sizeof(output));};
    assert(lookup("steamloopback.host").error==d::Error::Ok);
    assert(!std::strcmp(reinterpret_cast<char *>(output),"C:\\Steam\\steamui"));
    assert(lookup("STEAMLOOPBACK.HOST").error==d::Error::NotFound);
    assert(lookup("sub.steamloopback.host").error==d::Error::NotFound);
    assert(lookup("steamloopback.host.attacker").error==d::Error::NotFound);
    assert(lookup("https://steamloopback.host").error==d::Error::NotFound);
    assert(d::lookup(&r,foreign,view("steamloopback.host"),output,sizeof(output)).error==d::Error::WrongOwner);
    std::memset(output,0xa5,sizeof(output));
    auto small=d::lookup(&r,owner,view("steamloopback.host"),output,1);assert(small.error==d::Error::Capacity&&small.required>1);
    for(auto n:output)assert(n==0xa5);
    B replacement;field(replacement,1,"steamloopback.host");field(replacement,2,"D:\\Library\\steamui");
    heap.fail=true;auto before=r.reserved;
    assert(message(r,owner,replacement)==d::Error::NoMemory&&r.records==1&&r.reserved==before);
    assert(lookup("steamloopback.host").error==d::Error::Ok&&!std::strcmp(reinterpret_cast<char *>(output),"C:\\Steam\\steamui"));
    heap.fail=false;assert(message(r,owner,replacement)==d::Error::Ok&&heap.live.size()==1);
    assert(lookup("steamloopback.host").error==d::Error::Ok&&!std::strcmp(reinterpret_cast<char *>(output),"D:\\Library\\steamui"));
    // Last optional-field value wins; missing/empty path removes exactly one key.
    B dup;field(dup,1,"wrong.host");field(dup,2,"wrong");field(dup,1,"steamloopback.host");field(dup,2,"right");
    assert(message(r,owner,dup)==d::Error::Ok&&r.records==1);
    assert(lookup("steamloopback.host").error==d::Error::Ok&&!std::strcmp(reinterpret_cast<char *>(output),"right"));
    B empty;field(empty,2,"ignored");assert(message(r,owner,empty)==d::Error::Ok&&r.records==1);
    B remove;field(remove,1,"steamloopback.host");assert(message(r,owner,remove)==d::Error::Ok&&r.records==0&&heap.live.empty());
    assert(message(r,owner,remove)==d::Error::Ok);
    for(const B &bad:std::vector<B>{{0},{8,1},{0x0a,3,'x'},{0x80},{0x0a,0x80},{0x12,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,1}}){
        const std::string keepDomain="keep-domain",keepPath="keep-path";
        d::Registration sentinel{view(keepDomain),view(keepPath)},copy=sentinel;
        assert(d::parse_registration({bad.data(),bad.size()},&sentinel)==d::Error::Malformed);
        assert(sentinel.domain.data==copy.domain.data&&sentinel.path.data==copy.path.data);
    }
    B unknown;field(unknown,3,"new-feature");assert(message(r,owner,unknown)==d::Error::UnsupportedField);
    B nul;field(nul,1,std::string("nul.host\0suffix",15));field(nul,2,std::string("safe\0suffix",11));
    assert(message(r,owner,nul)==d::Error::Ok);
    assert(lookup("nul.host").error==d::Error::Ok&&!std::strcmp(reinterpret_cast<char *>(output),"safe"));
    B nulRemove;field(nulRemove,1,"nul.host");field(nulRemove,2,std::string("\0ignored",8));
    assert(message(r,owner,nulRemove)==d::Error::Ok&&r.records==0);
    std::map<std::string,std::string> model;
    for(unsigned i=0;i<5000;++i){std::string key="host"+std::to_string(i%73),path=i%5?"path"+std::to_string(i):"";B edit;field(edit,1,key);field(edit,2,path);
        assert(message(r,owner,edit)==d::Error::Ok);if(path.empty())model.erase(key);else model[key]=path;
        assert(r.records==model.size()&&heap.live.size()==model.size());
        for(const auto &[name,want]:model){assert(d::lookup(&r,owner,view(name),output,sizeof(output)).error==d::Error::Ok);assert(!std::strcmp(reinterpret_cast<char *>(output),want.c_str()));}
    }
    assert(d::close(&r,foreign)==d::Error::WrongOwner&&!heap.live.empty());
    assert(d::close(&r,owner)==d::Error::Ok&&heap.live.empty()&&r.reserved==0);
    assert(d::open(&r,foreign,{&heap,allocate,release})==d::Error::Ok);
    assert(message(r,owner,b)==d::Error::WrongOwner);
    assert(message(r,foreign,b)==d::Error::Ok);
    assert(d::close(&r,foreign)==d::Error::Ok&&heap.live.empty());
    std::puts("PASS command54 protobuf, exact domain registry, transactional OOM, 5000 replacement/removal cycles and owner-generation lifetime; helper routing integration not claimed");
}
