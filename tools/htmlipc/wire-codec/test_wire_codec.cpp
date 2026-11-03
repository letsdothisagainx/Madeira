/* SPDX-License-Identifier: MIT
 * These command numbers are deliberately fixture-only, not Steam evidence.
 */
#include "wire_codec.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

using namespace madeira_wire;
using Bytes = std::vector<Byte>;
static unsigned assertions;
[[noreturn]] static void die(const char *expression,int line) {
    std::fprintf(stderr,"FAIL line %d: %s\n",line,expression);std::exit(1);
}
#define CHECK(x) do { ++assertions;if (!(x)) die(#x,__LINE__); } while (0)

static constexpr MapEntry fixture_entries[] = {
    {100,200,MessageKind::OpaqueCommon},
    {101,201,MessageKind::BrowserCreate},
    {102,202,MessageKind::OpaqueCommon},
};
static constexpr MapView fixture_map{fixture_entries,3};
static constexpr U32 fixture_browser=0x89abcdefu;
static void put32(Bytes &b,U32 n) {
    for(unsigned i=0;i<4;++i) b.push_back(Byte(n>>(i*8)));
}
static U32 get32(const Byte *p) {
    return U32(p[0])|(U32(p[1])<<8)|(U32(p[2])<<16)|(U32(p[3])<<24);
}
static void varint(Bytes &b,U64 v) {
    do {Byte c=Byte(v&127);v>>=7;b.push_back(c|Byte(v?128:0));} while(v);
}
static void key(Bytes &b,U32 n,unsigned wire) { varint(b,(U64(n)<<3)|wire); }
static void scalar(Bytes &b,U32 n,U64 v) { key(b,n,0);varint(b,v); }
static void bytes(Bytes &b,U32 n,const Bytes &v) {
    key(b,n,2);varint(b,v.size());b.insert(b.end(),v.begin(),v.end());
}
static void fixed(Bytes &b,U32 n,U64 v,unsigned width) {
    key(b,n,width==4?5:1);
    for(unsigned i=0;i<width;++i) b.push_back(Byte(v>>(i*8)));
}
static Bytes frame(U32 command,const Bytes &body,U32 browser=fixture_browser) {
    CHECK(body.size()<=0xffffffffu);
    Bytes out;out.reserve(body.size()+12);put32(out,U32(body.size()));
    put32(out,command);put32(out,browser);out.insert(out.end(),body.begin(),body.end());return out;
}
static U64 read_varint(const Bytes &b,Size &pos) {
    U64 v=0;unsigned shift=0;
    while(pos<b.size() && shift<70) {
        Byte c=b[pos++];v|=U64(c&127)<<shift;
        if(!(c&128)) return v;
        shift+=7;
    }
    die("independent fixture decoder received bad varint",__LINE__);
}
struct Field { U32 n;unsigned wire;U64 value;Bytes data; };
static std::vector<Field> decode(const Bytes &b) {
    std::vector<Field> result;
    for(Size p=0;p<b.size();) {
        U64 k=read_varint(b,p);Field f{U32(k>>3),unsigned(k&7),0,{}};
        if(f.wire==0) f.value=read_varint(b,p);
        else if(f.wire==2) {
            U64 n=read_varint(b,p);CHECK(n<=b.size()-p);
            f.data.assign(b.begin()+p,b.begin()+p+Size(n));p+=Size(n);
        } else if(f.wire==1 || f.wire==5) {
            Size n=f.wire==1?8:4;CHECK(n<=b.size()-p);
            for(Size i=0;i<n;++i) f.value|=U64(b[p++])<<(8*i);
        } else die("independent fixture decoder wire",__LINE__);
        result.push_back(f);
    }
    return result;
}
static Bytes convert(Direction direction,const Bytes &input,MapView map=fixture_map) {
    Result query=convert_frame(direction,map,input.data(),input.size(),nullptr,0);
    CHECK(query.error==Error::Capacity);CHECK(query.written==0);CHECK(query.required>=12);
    Bytes output(query.required+17,0xa5);
    Result r=convert_frame(direction,map,input.data(),input.size(),output.data(),query.required);
    CHECK(r.error==Error::Ok);CHECK(r.written==query.required);CHECK(r.required==query.required);
    for(Size i=r.written;i<output.size();++i) CHECK(output[i]==0xa5);
    output.resize(r.written);return output;
}
static void rejected(Direction direction,const Bytes &input,Error expected,
                     MapView map=fixture_map) {
    Bytes output(512,0xa5),before=output;
    const Byte empty_sentinel=0;
    const Byte *start=input.empty()?&empty_sentinel:input.data();
    Result r=convert_frame(direction,map,start,input.size(),output.data(),output.size());
    if(r.error!=expected) {
        std::fprintf(stderr,"rejected: direction=%u size=%zu expected=%u actual=%u bytes=",
                     unsigned(direction),input.size(),unsigned(expected),unsigned(r.error));
        for(Byte c:input) std::fprintf(stderr,"%02x",unsigned(c));
        std::fputc('\n',stderr);
    }
    CHECK(r.error==expected);CHECK(r.written==0);CHECK(output==before);
}
static Bytes body(const Bytes &frame_bytes) {
    CHECK(frame_bytes.size()>=12);CHECK(get32(frame_bytes.data())==frame_bytes.size()-12);
    return Bytes(frame_bytes.begin()+12,frame_bytes.end());
}
static void common_roundtrips() {
    for(const Bytes &b:std::vector<Bytes>{{},{0},{0xff},{0x08,0x80,0},{0x0b,0x0c},
        {0,0xff,0x80,0x80,0x80,0,0x04,0xde,0xad,0xbe,0xef}}) {
        Bytes input=frame(100,b),legacy=convert(Direction::CurrentToLegacy,input);
        CHECK(get32(legacy.data()+4)==200);CHECK(get32(legacy.data()+8)==fixture_browser);
        CHECK(body(legacy)==b);CHECK(convert(Direction::LegacyToCurrent,legacy)==input);
    }
    U32 state=0x719a38d2u;
    for(unsigned trial=0;trial<128;++trial) {
        Bytes raw(trial*13);
        for(Byte &b:raw) {state^=state<<13;state^=state>>17;state^=state<<5;b=Byte(state);}
        Bytes input=frame(102,raw,state);
        Bytes legacy=convert(Direction::CurrentToLegacy,input);
        CHECK(get32(legacy.data()+4)==202);CHECK(get32(legacy.data()+8)==state);
        CHECK(body(legacy)==raw);CHECK(convert(Direction::LegacyToCurrent,legacy)==input);
    }
}
static void create_fields() {
    Bytes b;scalar(b,1,0xfedcba98u);bytes(b,2,{0,'u','a',0xff});bytes(b,3,{});
    scalar(b,4,1);fixed(b,5,0x3fa00000u,4);scalar(b,6,640);scalar(b,7,480);
    bytes(b,8,{'a','b'});bytes(b,9,{0,1,2,0});scalar(b,10,4);
    scalar(b,11,0xffffffffu);scalar(b,12,123);scalar(b,13,0xabcdu);
    bytes(b,14,{'x'});fixed(b,15,0x1122334455667788ull,8);scalar(b,16,1);
    Bytes out=convert(Direction::CurrentToLegacy,frame(101,b));
    CHECK(get32(out.data()+4)==201);CHECK(get32(out.data()+8)==fixture_browser);
    auto fields=decode(body(out));CHECK(fields.size()==18);
    const U32 expected_n[]={1,3,5,6,7,9,10,11,13,14,15,16,17,18,19,20,8,12};
    const unsigned expected_wire[]={0,2,2,0,5,0,0,2,2,0,0,0,0,2,1,0,0,0};
    auto original=decode(b);
    for(Size i=0;i<16;++i) {
        CHECK(fields[i].n==expected_n[i]);CHECK(fields[i].wire==expected_wire[i]);
        CHECK(fields[i].value==original[i].value);CHECK(fields[i].data==original[i].data);
    }
    CHECK(fields[16].n==8);CHECK(fields[16].wire==0);CHECK(fields[16].value==0);
    CHECK(fields[17].n==12);CHECK(fields[17].wire==0);CHECK(fields[17].value==1);
    rejected(Direction::LegacyToCurrent,out,Error::WrongDirection);
}
static void create_types_and_duplicates() {
    for(U32 type:{0u,1u,2u,3u,4u,12u,13u}) {
        Bytes b;scalar(b,10,type);auto fields=decode(body(convert(Direction::CurrentToLegacy,frame(101,b))));
        CHECK(fields.size()==3);CHECK(fields[0].n==14);CHECK(fields[0].value==type);
        CHECK(fields[1].n==8);CHECK(fields[1].value==(type<=2 || type==12 || type==13));
        CHECK(fields[2].n==12);CHECK(fields[2].value==(type==4));
    }
    auto defaults=decode(body(convert(Direction::CurrentToLegacy,frame(101,{}))));
    CHECK(defaults.size()==2);CHECK(defaults[0].n==8);CHECK(defaults[0].value==1);
    CHECK(defaults[1].n==12);CHECK(defaults[1].value==0);
    for(U64 type:{5ull,11ull,14ull,0xffffffffull,0x100000000ull,~0ull}) {
        Bytes b;scalar(b,10,type);rejected(Direction::CurrentToLegacy,frame(101,b),Error::UnsupportedBrowserType);
    }
    Bytes b;scalar(b,10,999);scalar(b,10,4);scalar(b,1,11);scalar(b,1,22);
    auto fields=decode(body(convert(Direction::CurrentToLegacy,frame(101,b))));
    CHECK(fields.size()==6);CHECK(fields[0].n==14);CHECK(fields[0].value==999);
    CHECK(fields[1].n==14);CHECK(fields[1].value==4);
    CHECK(fields[2].n==1);CHECK(fields[2].value==11);CHECK(fields[3].value==22);
    CHECK(fields[4].value==0);CHECK(fields[5].value==1);
    scalar(b,10,5);rejected(Direction::CurrentToLegacy,frame(101,b),Error::UnsupportedBrowserType);
    Bytes noncanonical{0x50,0x84,0x00};
    fields=decode(body(convert(Direction::CurrentToLegacy,frame(101,noncanonical))));
    CHECK(fields[0].value==4);CHECK(fields.back().value==1);
    Bytes many;many.reserve(2*600000);
    for(unsigned i=0;i<600000;++i) {many.push_back(8);many.push_back(Byte(i&127));}
    Bytes out=convert(Direction::CurrentToLegacy,frame(101,many));
    CHECK(out.size()==many.size()+16);
}
static void malformed_create() {
    std::vector<Bytes> bad={
        {0}, {0x0b}, {0x0c}, {0x0e}, {0x0f}, {0x80}, {0x08,0x80},
        {0x08,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x02},
        {0x08,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0},
        {0x12,5,'a'}, {0x12,0x80}, {0x12,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,1},
        {0x2d,0,0,0}, {0x79,0,0,0,0,0,0,0}, {0x0d,0,0,0,0},
        {0x88,1,0}, // Unknown field17 must not be silently discarded.
    };
    Bytes overlarge_key;varint(overlarge_key,(U64(0x20000000u)<<3));varint(overlarge_key,0);bad.push_back(overlarge_key);
    Bytes overlong_key(10,0x80);overlong_key.push_back(0);bad.push_back(overlong_key);
    for(const Bytes &suffix:bad) {
        Bytes b;bytes(b,2,{'v','a','l','i','d'});scalar(b,10,4);
        b.insert(b.end(),suffix.begin(),suffix.end());
        rejected(Direction::CurrentToLegacy,frame(101,b),Error::MalformedProtobuf);
    }
}
static void frame_and_map_errors() {
    Bytes valid=frame(100,{1,2,3});
    for(Size n=0;n<12;++n) rejected(Direction::CurrentToLegacy,Bytes(valid.begin(),valid.begin()+n),Error::MalformedFrame);
    Bytes wrong=valid;wrong[0]=4;rejected(Direction::CurrentToLegacy,wrong,Error::MalformedFrame);
    wrong=valid;wrong.push_back(0);rejected(Direction::CurrentToLegacy,wrong,Error::MalformedFrame);
    rejected(Direction::CurrentToLegacy,frame(103,{}),Error::UnsupportedCommand);
    rejected(Direction::LegacyToCurrent,frame(203,{}),Error::UnsupportedCommand);
    const MapEntry same_current[]={{100,200,MessageKind::OpaqueCommon},{100,201,MessageKind::OpaqueCommon}};
    rejected(Direction::CurrentToLegacy,valid,Error::InvalidMap,{same_current,2});
    const MapEntry same_legacy[]={{100,200,MessageKind::OpaqueCommon},{101,200,MessageKind::OpaqueCommon}};
    rejected(Direction::CurrentToLegacy,valid,Error::InvalidMap,{same_legacy,2});
    rejected(Direction::CurrentToLegacy,valid,Error::InvalidMap,{nullptr,1});
    const MapEntry bad_kind[]={{100,200,static_cast<MessageKind>(99)}};
    rejected(Direction::CurrentToLegacy,valid,Error::InvalidMap,{bad_kind,1});
    rejected(Direction::CurrentToLegacy,valid,Error::UnsupportedCommand,{nullptr,0});
    Bytes output(32,0xa5),saved=output;
    Result r=convert_frame(Direction::CurrentToLegacy,fixture_map,nullptr,12,output.data(),output.size());
    CHECK(r.error==Error::InvalidArgument);CHECK(output==saved);
    r=convert_frame(Direction::CurrentToLegacy,fixture_map,valid.data(),valid.size(),nullptr,32);
    CHECK(r.error==Error::InvalidArgument);
    r=convert_frame(static_cast<Direction>(99),fixture_map,valid.data(),valid.size(),output.data(),output.size());
    CHECK(r.error==Error::InvalidArgument);CHECK(output==saved);
}
static void output_atomicity() {
    Bytes b;bytes(b,2,{'l','o','n','g','e','r'});scalar(b,10,4);
    Bytes input=frame(101,b);Bytes expected=convert(Direction::CurrentToLegacy,input);
    Bytes output(expected.size()+32,0xa5),saved=output;
    for(Size cap=0;cap<expected.size();++cap) {
        Result r=convert_frame(Direction::CurrentToLegacy,fixture_map,input.data(),input.size(),output.data(),cap);
        CHECK(r.error==Error::Capacity);CHECK(r.written==0);CHECK(r.required==expected.size());CHECK(output==saved);
    }
    Bytes overlap(input.size()+expected.size()+4,0xa5);
    std::copy(input.begin(),input.end(),overlap.begin()+1);Bytes before=overlap;
    for(Size offset:{0u,1u,2u}) {
        Result r=convert_frame(Direction::CurrentToLegacy,fixture_map,overlap.data()+1,input.size(),overlap.data()+offset,expected.size());
        CHECK(r.error==Error::Overlap);CHECK(r.written==0);CHECK(overlap==before);
    }
    // Only the actual output extent matters; unused advertised capacity may
    // extend across the input if the bytes actually written are disjoint.
    Bytes adjacent(expected.size()+input.size()+4,0xa5);
    std::copy(input.begin(),input.end(),adjacent.begin()+expected.size());
    Result r=convert_frame(Direction::CurrentToLegacy,fixture_map,
        adjacent.data()+expected.size(),input.size(),adjacent.data(),adjacent.size());
    CHECK(r.error==Error::Ok);CHECK(r.written==expected.size());
    CHECK(std::equal(expected.begin(),expected.end(),adjacent.begin()));
    CHECK(std::equal(input.begin(),input.end(),adjacent.begin()+expected.size()));
}
static void payload_limits() {
    CHECK(max_outgoing_payload==32u*1024u*1024u);
    CHECK(max_incoming_payload==128u*1024u*1024u);
    {
        Bytes b(max_outgoing_payload,0xe7);Bytes input=frame(100,b);b.clear();b.shrink_to_fit();
        Bytes out=convert(Direction::CurrentToLegacy,input);
        CHECK(out.size()==max_outgoing_payload+12);CHECK(out[12]==0xe7);CHECK(out.back()==0xe7);
        input.push_back(0);U32 size=U32(max_outgoing_payload+1);
        for(unsigned i=0;i<4;++i) input[i]=Byte(size>>(i*8));
        rejected(Direction::CurrentToLegacy,input,Error::FrameTooLarge);
    }
    {
        // A valid 32 MiB Create body is too large after explicit derived fields
        // are appended. Error detection must finish before touching output.
        Bytes b(max_outgoing_payload,0);
        for(Size i=0;i<b.size();i+=2) b[i]=8;
        Bytes input=frame(101,b);b.clear();b.shrink_to_fit();
        rejected(Direction::CurrentToLegacy,input,Error::FrameTooLarge);
    }
    {
        Bytes b(max_incoming_payload,0x91);Bytes input=frame(200,b);b.clear();b.shrink_to_fit();
        Bytes out=convert(Direction::LegacyToCurrent,input);
        CHECK(out.size()==max_incoming_payload+12);CHECK(out[12]==0x91);CHECK(out.back()==0x91);
        input.push_back(0);U32 size=U32(max_incoming_payload+1);
        for(unsigned i=0;i<4;++i) input[i]=Byte(size>>(i*8));
        rejected(Direction::LegacyToCurrent,input,Error::FrameTooLarge);
    }
}
int main() {
    common_roundtrips();create_fields();create_types_and_duplicates();malformed_create();
    frame_and_map_errors();output_atomicity();payload_limits();
    std::printf("PASS wire codec: %u assertions, exact frame/header mapping, opaque roundtrips, Create fields/types/duplicates, malformed inputs, atomic errors, and 32/128 MiB boundaries\n",assertions);
}
