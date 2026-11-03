#!/usr/bin/env python3
"""Map official PE bytes as inert data and exercise the real IAT installer.

No Windows/PE instructions run. Host C++ code simulates MEM_IMAGE page metadata
and applies the official DIR64 relocations to a page-aligned byte buffer.
"""
from pathlib import Path
import argparse
import hashlib
import os
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
EXPECTED = '8559e6bd32eb3fddd95079633272866deb292211ec4f7e69aeb0ec48fdafef72'
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('file', nargs='?', type=Path, default=HERE / 'tier0_s64.dll')
a = p.parse_args()
a.file = a.file.resolve()
before = a.file.read_bytes()
assert len(before) == 887960, 'Unexpected official file size'
assert hashlib.sha256(before).hexdigest() == EXPECTED, 'Official full-file SHA-256 mismatch'

source = r'''
#include "fixture_args.h"
#include "sha256.h"
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>
using namespace madeira_cef_fixture;
#define CHECK(x) do{if(!(x)){std::fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);std::abort();}}while(0)
static U16 r16(const U8*p){return U16(p[0])|(U16(p[1])<<8);}
static U32 r32(const U8*p){return U32(r16(p))|(U32(r16(p+2))<<16);}
static U64 r64(const U8*p){return U64(r32(p))|(U64(r32(p+4))<<32);}
static void w64(U8*p,U64 v){for(unsigned i=0;i<8;++i)p[i]=U8(v>>(8*i));}
struct Page {U32 protection;};
struct Call {void*address;Size size;U32 flags,old;};
struct Map {
    std::vector<U8> raw;U8*memory,*hook,*genuine;U32 image_size,headers,nt,opt,sections,count;
    std::vector<Page> pages;std::vector<Call> calls;unsigned relocations=0;
    explicit Map(const char*path) {
        std::ifstream in(path,std::ios::binary);CHECK(in.good());raw.assign(std::istreambuf_iterator<char>(in),{});
        CHECK(raw.size()==887960);nt=r32(raw.data()+0x3c);opt=nt+24;
        CHECK(r16(raw.data())==0x5a4d&&r32(raw.data()+nt)==0x4550&&r16(raw.data()+nt+4)==0x8664);
        count=r16(raw.data()+nt+6);sections=opt+r16(raw.data()+nt+20);
        image_size=r32(raw.data()+opt+56);headers=r32(raw.data()+opt+60);
        CHECK(image_size==0x30b000&&headers==0x400&&count==7);
        memory=static_cast<U8*>(std::aligned_alloc(4096,image_size));
        hook=static_cast<U8*>(std::aligned_alloc(4096,4096));
        genuine=static_cast<U8*>(std::aligned_alloc(4096,4096));CHECK(memory&&hook&&genuine);
        pages.assign(image_size/4096,{2});std::memset(memory,0,image_size);
        std::memcpy(memory,raw.data(),headers);
        for(U32 n=0;n<count;++n){const U8*s=raw.data()+sections+n*40;
            U32 va=r32(s+12),length=r32(s+8),size=r32(s+16),offset=r32(s+20),flags=r32(s+36);
            CHECK(U64(va)+std::max(length,size)<=image_size&&U64(offset)+size<=raw.size());
            std::memcpy(memory+va,raw.data()+offset,size);
            U32 protection=flags&0x20000000?0x20:flags&0x80000000?4:2;
            CHECK(!(flags&0x20000000)||!(flags&0x80000000));
            for(U32 page=va/4096;page<(U64(va)+std::max(length,size)+4095)/4096;++page)pages[page].protection=protection;
        }
        U64 delta=reinterpret_cast<U64>(memory)-r64(raw.data()+opt+24);
        U32 reloc=r32(raw.data()+opt+152),size=r32(raw.data()+opt+156);
        for(U32 offset=0;offset<size;){CHECK(offset+8<=size);U32 page=r32(memory+reloc+offset),block=r32(memory+reloc+offset+4);
            CHECK(block>=8&&!(block%2)&&offset+block<=size);
            for(U32 at=8;at<block;at+=2){U16 item=r16(memory+reloc+offset+at);if(!(item>>12))continue;
                CHECK(item>>12==10);U32 target=page+(item&4095);CHECK(U64(target)+8<=image_size);
                w64(memory+target,r64(memory+target)+delta);++relocations;
            }offset+=block;
        }
        // Wine can publish the relocated ImageBase in the mapped PE headers.
        w64(memory+opt+24,reinterpret_cast<U64>(memory));
        w64(memory+0xa5358,reinterpret_cast<U64>(genuine+0x180));
    }
    ~Map(){std::free(memory);std::free(hook);std::free(genuine);}
    static bool query(void*context,const void*address,Region*r) {
        auto&m=*static_cast<Map*>(context);U64 a=reinterpret_cast<U64>(address),start=reinterpret_cast<U64>(m.memory);
        if(a>=start&&a-start<m.image_size){Size index=Size(a-start)/4096;
            *r={m.memory+index*4096,m.memory,4096,0x1000,m.pages[index].protection,0x1000000};return true;}
        for(U8*owner:{m.hook,m.genuine}){start=reinterpret_cast<U64>(owner);if(a>=start&&a-start<4096){*r={owner,owner,4096,0x1000,0x20,0x1000000};return true;}}
        return false;
    }
    static bool protect(void*context,void*address,Size size,U32 flags,U32*old) {
        auto&m=*static_cast<Map*>(context);CHECK(address==m.memory+0xa5000&&size==4096&&(flags==2||flags==4));
        auto&current=m.pages[0xa5].protection;*old=current;m.calls.push_back({address,size,flags,current});current=flags;return true;
    }
    static U32 error(void*){return 0x1234;}
};
int main(int argc,char**argv){CHECK(argc==2);Map m(argv[1]);auto pristine=m.raw;
    U8 hash[32];sha256(m.raw.data(),m.raw.size(),hash);char hex[65];for(unsigned i=0;i<32;++i)std::sprintf(hex+i*2,"%02x",hash[i]);
    CHECK(std::string(hex)=="8559e6bd32eb3fddd95079633272866deb292211ec4f7e69aeb0ec48fdafef72");
    Config c{};c.file=m.raw.data();c.file_size=m.raw.size();std::memcpy(c.sha256,hash,32);
    c.hook_module=m.hook;c.hook=m.hook+0x100;c.genuine_module=m.genuine;c.genuine_create_process=m.genuine+0x180;
    Api api{&m,Map::query,Map::protect,Map::error};Installer installer;
    Result armed=arm(&installer,c,api);CHECK(armed.error==Error::None&&installer.armed&&installer.slot_rva==0xa5358);
    std::vector<U8> expected(m.memory,m.memory+m.image_size);w64(expected.data()+0xa5358,reinterpret_cast<U64>(c.hook));
    Result installed=install(&installer,m.memory);
    if(installed.error!=Error::None)std::fprintf(stderr,"installer error=%u\n",unsigned(installed.error));
    CHECK(installed.error==Error::None&&installed.rollback_complete&&installer.installed);
    CHECK(std::equal(expected.begin(),expected.end(),m.memory));CHECK(m.raw==pristine);
    CHECK(m.calls.size()==2&&m.calls[0].old==2&&m.calls[0].flags==4&&m.calls[1].old==4&&m.calls[1].flags==2&&m.pages[0xa5].protection==2);
    CHECK(install(&installer,m.memory).error==Error::None&&m.calls.size()==2);
    std::printf("PASS official tier0_s64.dll SHA256 %s: 7 sections, %u actual DIR64 relocations; installer accepts actual metadata, only IAT[0xa5358] changes; page R-RW-R, file unchanged, no PE instructions executed\n",hex,m.relocations);
}
'''
with tempfile.TemporaryDirectory(prefix='check-official-map-', dir=HERE) as temp:
    folder = Path(temp)
    (folder / 'test.cpp').write_text(source)
    subprocess.run([os.environ.get('CXX', 'g++'), '-std=c++17', '-O1', '-g',
                    '-Wall', '-Wextra', '-Werror', '-Wno-misleading-indentation',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie',
                    '-I' + str(HERE), str(folder / 'test.cpp'), str(HERE / 'iat_install.cpp'),
                    '-o', str(folder / 'check-official-map')], check=True)
    subprocess.run([str(folder / 'check-official-map'), str(a.file)], check=True)
assert a.file.read_bytes() == before, 'Official file changed during host test'
