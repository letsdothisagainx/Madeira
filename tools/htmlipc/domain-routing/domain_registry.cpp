/* SPDX-License-Identifier: MIT */
#include "domain_registry.h"
namespace madeira_domain {
struct Node {Node *next;Size domain,path,bytes;};
namespace {
static bool owner_valid(Owner a){return a.process&&a.generation;}
static bool same(Owner a,Owner b){return a.process==b.process&&a.generation==b.generation;}
static bool valid(Bytes a){return a.data||!a.size;}
static bool varint(Bytes b,Size *at,U64 *out){U64 n=0;for(unsigned i=0;i<10;++i){if(*at==b.size)return false;Byte c=b.data[(*at)++];if(i==9&&c>1)return false;n|=U64(c&127)<<(i*7);if(!(c&128)){*out=n;return true;}}return false;}
static Bytes cstring(Bytes b){for(Size i=0;i<b.size;++i)if(!b.data[i])return {b.data,i};return b;}
static Byte *key(Node *n){return reinterpret_cast<Byte *>(n+1);}
static const Byte *key(const Node *n){return reinterpret_cast<const Byte *>(n+1);}
static bool equal(const Node *n,Bytes b){if(n->domain!=b.size)return false;for(Size i=0;i<b.size;++i)if(key(n)[i]!=b.data[i])return false;return true;}
static void copy(Byte *to,Bytes b){for(Size i=0;i<b.size;++i)to[i]=b.data[i];}
static bool current(const Registry *r,Owner o){return r&&r->live&&owner_valid(o)&&same(r->owner,o);}
}
Error parse_registration(Bytes b,Registration *out){
    if(!out||!valid(b))return Error::InvalidArgument;
    if(b.size>max_registration_bytes)return Error::TooLarge;
    Registration result{};Size at=0;
    while(at<b.size){U64 tag,length;if(!varint(b,&at,&tag)||tag>0xffffffffu||!(tag>>3))return Error::Malformed;
        U32 field=U32(tag>>3);if(field!=1&&field!=2)return Error::UnsupportedField;
        if((tag&7)!=2||!varint(b,&at,&length)||length>b.size-at)return Error::Malformed;
        Bytes value{b.data+at,Size(length)};at+=Size(length);
        if(field==1)result.domain=value;else result.path=value;
    }
    *out=result;return Error::Ok;
}
Error open(Registry *r,Owner o,Memory memory){
    if(!r||r->live||r->head||!owner_valid(o)||!memory.allocate||!memory.release)return Error::InvalidArgument;
    r->owner=o;r->memory=memory;r->records=r->reserved=0;r->live=true;return Error::Ok;
}
Error update(Registry *r,Owner o,Registration message){
    if(!current(r,o))return Error::WrongOwner;
    if(!valid(message.domain)||!valid(message.path))return Error::InvalidArgument;
    if(message.domain.size>max_registration_bytes||message.path.size>max_registration_bytes-message.domain.size)return Error::TooLarge;
    // Genuine handlers consume protobuf strings through const-char pointers.
    Bytes domain=cstring(message.domain),path=cstring(message.path);
    if(!domain.size)return Error::Ok;
    Node **link=&r->head;while(*link&&!equal(*link,domain))link=&(*link)->next;
    Node *old=*link;
    if(!path.size){if(old){*link=old->next;--r->records;r->reserved-=old->bytes;r->memory.release(r->memory.context,old);}return Error::Ok;}
    constexpr Size limit=~Size(0);
    if(domain.size>limit-sizeof(Node)-2||path.size>limit-sizeof(Node)-2-domain.size)return Error::TooLarge;
    Size bytes=sizeof(Node)+domain.size+1+path.size+1;
    Size previous=old?old->bytes:0;if(bytes>limit-(r->reserved-previous)||(!old&&r->records==limit))return Error::TooLarge;
    auto *next=static_cast<Node *>(r->memory.allocate(r->memory.context,bytes));if(!next)return Error::NoMemory;
    next->next=old?old->next:nullptr;next->domain=domain.size;next->path=path.size;next->bytes=bytes;
    Byte *data=key(next);copy(data,domain);data[domain.size]=0;copy(data+domain.size+1,path);data[domain.size+1+path.size]=0;
    *link=next;r->reserved=r->reserved-previous+bytes;if(old)r->memory.release(r->memory.context,old);else ++r->records;
    return Error::Ok;
}
Result lookup(const Registry *r,Owner o,Bytes host,Byte *output,Size capacity){
    if(!current(r,o))return {Error::WrongOwner,0};
    if(!valid(host)||(!output&&capacity))return {Error::InvalidArgument,0};
    host=cstring(host);
    for(const Node *n=r->head;n;n=n->next)if(equal(n,host)){
        Size required=n->path+1;if(!output||capacity<required)return {Error::Capacity,required};
        const Byte *path=key(n)+n->domain+1;for(Size i=0;i<required;++i)output[i]=path[i];return {Error::Ok,required};}
    return {Error::NotFound,0};
}
Error close(Registry *r,Owner o){
    if(!current(r,o))return Error::WrongOwner;
    while(r->head){Node *n=r->head;r->head=n->next;r->memory.release(r->memory.context,n);}
    r->records=r->reserved=0;r->live=false;r->owner={};return Error::Ok;
}
}
