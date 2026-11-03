#!/usr/bin/env python3
"""ASan/UBSan checks of the real test-only PE64 IAT installer.

The persistent build/synthetic-tier0.dll is synthetic test data, never executed.
All temporary compiled products remain under this fixture directory.
"""
from pathlib import Path
import hashlib
import os
import struct
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
BUILD = HERE / 'build'
BUILD.mkdir(exist_ok=True)
raw = bytearray(0x3400)
def w16(p, v): struct.pack_into('<H', raw, p, v)
def w32(p, v): struct.pack_into('<I', raw, p, v)
def w64(p, v): struct.pack_into('<Q', raw, p, v)
w16(0, 0x5a4d)
marker = b'SYNTHETIC TEST DATA ONLY!'
raw[2:2 + len(marker)] = marker
w32(0x3c, 0x80)
w32(0x80, 0x4550)
w16(0x84, 0x8664)
w16(0x86, 3)
w16(0x94, 240)
w16(0x96, 0x2022)
opt = 0x98
w16(opt, 0x20b)
w32(opt + 4, 0x1000)
w32(opt + 8, 0x2000)
w32(opt + 16, 0x1000)
w32(opt + 20, 0x1000)
w64(opt + 24, 0x140000000)
w32(opt + 32, 0x1000)
w32(opt + 36, 0x200)
w16(opt + 40, 6)
w16(opt + 48, 6)
w32(opt + 56, 0x4000)
w32(opt + 60, 0x400)
w16(opt + 68, 3)
w16(opt + 70, 0x160)
w64(opt + 72, 0x100000)
w64(opt + 80, 0x1000)
w64(opt + 88, 0x100000)
w64(opt + 96, 0x1000)
w32(opt + 108, 16)
w32(opt + 120, 0x2000)
w32(opt + 124, 40)
w32(opt + 152, 0x3000)
w32(opt + 156, 12)
w32(opt + 208, 0x2180)
w32(opt + 212, 16)
for index, (name, rva, off, flags) in enumerate([
    (b'.text', 0x1000, 0x400, 0x60000020),
    (b'.rdata', 0x2000, 0x1400, 0x40000040),
    (b'.reloc', 0x3000, 0x2400, 0x42000040),
]):
    p = opt + 240 + index * 40
    raw[p:p + len(name)] = name
    w32(p + 8, 0x1000)
    w32(p + 12, rva)
    w32(p + 16, 0x1000)
    w32(p + 20, off)
    w32(p + 36, flags)
raw[0x400:0x1400] = b'\x90' * 0x1000
w64(0x408, 0x140001080)
w32(0x1400, 0x2080)
w32(0x1400 + 12, 0x2040)
w32(0x1400 + 16, 0x2180)
raw[0x1440:0x1440 + 13] = b'KERNEL32.dll\0'
w64(0x1480, 0x20c0)
w16(0x14c0, 0)
raw[0x14c2:0x14c2 + 15] = b'CreateProcessW\0'
w64(0x1580, 0x20c0)
w32(0x2400, 0x1000)
w32(0x2404, 12)
w16(0x2408, 0xa008)
w16(0x240a, 0)
fixture = BUILD / 'synthetic-tier0.dll'
fixture.write_bytes(raw)
fixture_sha = hashlib.sha256(raw).hexdigest()

harness = r'''
#include "fixture_args.h"
#include "sha256.h"
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>
using namespace madeira_cef_fixture;
static unsigned checks;
static const char *current="initialization";
#define REQUIRE(x) do { if(!(x)){std::fprintf(stderr,"FAIL %s: %s at %d\n",current,#x,__LINE__);std::abort();} } while(0)
static void w16(U8*p,U16 v){p[0]=U8(v);p[1]=U8(v>>8);}
static void w32(U8*p,U32 v){w16(p,U16(v));w16(p+2,U16(v>>16));}
static void w64(U8*p,U64 v){w32(p,U32(v));w32(p+4,U32(v>>32));}
struct Call { void *address;Size length;U32 requested;U32 previous;bool success; };
struct Fixture {
    std::vector<U8> raw;U8 *mapped,*hook_base,*genuine_base;
    U32 protection[4]={2,0x20,2,2};void *owners[4];
    void *hook_owner,*genuine_owner;U32 hook_protection=0x20,genuine_protection=0x20;
    U32 state=0x1000,type=0x1000000,last=0x1111;
    std::vector<Call> calls;unsigned protect_number=0;
    unsigned fail_protect=0,fail_also=0,wrong_old=0;
    bool race=false;U32 failure_error=0x7654,success_error=0x9999;
    Installer installer;
    explicit Fixture(const char *path) {
        std::ifstream in(path,std::ios::binary);raw.assign(std::istreambuf_iterator<char>(in),{});
        REQUIRE(raw.size()==0x3400);
        mapped=static_cast<U8*>(std::aligned_alloc(4096,0x4000));
        hook_base=static_cast<U8*>(std::aligned_alloc(4096,4096));
        genuine_base=static_cast<U8*>(std::aligned_alloc(4096,4096));
        REQUIRE(mapped&&hook_base&&genuine_base);
        hook_owner=hook_base;genuine_owner=genuine_base;
        for(void*&owner:owners)owner=mapped;
        map_image();
    }
    ~Fixture(){std::free(mapped);std::free(hook_base);std::free(genuine_base);}
    void map_image(bool wine_rebased=true) {
        std::memset(mapped,0,0x4000);std::memcpy(mapped,raw.data(),0x400);
        for(unsigned i=0;i<3;i++)std::memcpy(mapped+0x1000+i*0x1000,raw.data()+0x400+i*0x1000,0x1000);
        w64(mapped+0x1008,reinterpret_cast<U64>(mapped)+0x1080);
        w64(mapped+0x2180,reinterpret_cast<U64>(genuine()));
        if(wine_rebased)w64(mapped+0x98+24,reinterpret_cast<U64>(mapped));
    }
    const void *hook()const{return hook_base+0x100;}
    const void *genuine()const{return genuine_base+0x180;}
    Config config() {
        Config c{};c.file=raw.data();c.file_size=raw.size();sha256(c.file,c.file_size,c.sha256);
        c.hook_module=hook_base;c.hook=hook();c.genuine_create_process=genuine();c.genuine_module=genuine_base;return c;
    }
    static bool query(void *context,const void *address,Region *r) {
        auto &f=*static_cast<Fixture*>(context);U64 a=reinterpret_cast<U64>(address),base=reinterpret_cast<U64>(f.mapped);
        if(a>=base&&a-base<0x4000){unsigned page=unsigned((a-base)/4096);
            *r={f.mapped+page*4096,f.owners[page],4096,f.state,f.protection[page],f.type};return true;}
        base=reinterpret_cast<U64>(f.hook_base);
        if(a>=base&&a-base<4096){*r={f.hook_base,f.hook_owner,4096,0x1000,f.hook_protection,0x1000000};return true;}
        base=reinterpret_cast<U64>(f.genuine_base);
        if(a>=base&&a-base<4096){*r={f.genuine_base,f.genuine_owner,4096,0x1000,f.genuine_protection,0x1000000};return true;}
        return false;
    }
    static bool protect(void *context,void *address,Size length,U32 requested,U32 *old) {
        auto &f=*static_cast<Fixture*>(context);
        // Any attempt to write executable memory, another page, or more than one page fails this test.
        REQUIRE(address==f.mapped+0x2000&&length==4096&&(requested==2||requested==4));
        ++f.protect_number;bool okay=f.protect_number!=f.fail_protect&&f.protect_number!=f.fail_also;
        U32 before=f.protection[2];f.calls.push_back({address,length,requested,before,okay});
        if(!okay){f.last=f.failure_error;return false;}
        *old=f.wrong_old&&f.protect_number==1?f.wrong_old:before;
        f.protection[2]=requested;
        if(f.race&&f.protect_number==1)w64(f.mapped+0x2180,0x12345678);
        f.last=f.success_error;return true;
    }
    static U32 error(void *context){return static_cast<Fixture*>(context)->last;}
    Api api(){return {this,query,protect,error};}
    Result arm_here(){auto c=config();return arm(&installer,c,api());}
    std::vector<U8> snapshot()const{return {mapped,mapped+0x4000};}
    void unchanged(const std::vector<U8>&before){REQUIRE(std::equal(before.begin(),before.end(),mapped));}
    void only_slot(const std::vector<U8>&before,U64 value) {
        auto expected=before;w64(expected.data()+0x2180,value);unchanged(expected);
    }
};
template<class F>static void run(const char*name,F test){current=name;test();++checks;}
static void no_install(Fixture &f,Error expected) {
    REQUIRE(f.arm_here().error==Error::None);auto before=f.snapshot();
    Result r=install(&f.installer,f.mapped);REQUIRE(r.error==expected&&r.rollback_complete);
    REQUIRE(f.calls.empty()&&!f.installer.installed);f.unchanged(before);
}
static void no_arm(Fixture &f,Error expected) {
    auto before=f.snapshot();REQUIRE(f.arm_here().error==expected);
    REQUIRE(f.calls.empty()&&!f.installer.armed);f.unchanged(before);
}
int main(int argc,char **argv) {
    REQUIRE(argc==2);const char*path=argv[1];
    run("known SHA-256 vectors",[]{
        struct V{const char*s;const char*hex;};V vectors[]={
            {"","e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
            {"abc","ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
            {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq","248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"}};
        for(auto v:vectors){U8 digest[32];sha256(reinterpret_cast<const U8*>(v.s),std::strlen(v.s),digest);
            char hex[65];for(unsigned i=0;i<32;i++)std::sprintf(hex+i*2,"%02x",digest[i]);REQUIRE(std::string(hex)==v.hex);}
    });
    for(bool wine_rebased:{false,true})run(wine_rebased?"Wine rewritten ImageBase and DIR64":"original ImageBase and DIR64",[&]{
        Fixture f(path);f.map_image(wine_rebased);auto before=f.snapshot();
        REQUIRE(f.arm_here().error==Error::None);REQUIRE(f.installer.slot_rva==0x2180);
        Result r=install(&f.installer,f.mapped);REQUIRE(r.error==Error::None&&r.rollback_complete&&f.installer.installed);
        REQUIRE(f.calls.size()==2&&f.calls[0].previous==2&&f.calls[0].requested==4&&f.calls[1].previous==4&&f.calls[1].requested==2&&f.protection[2]==2);
        f.only_slot(before,reinterpret_cast<U64>(f.hook()));
        REQUIRE(install(&f.installer,f.mapped).error==Error::None&&f.calls.size()==2);
    });
    run("default disarmed",[&]{Fixture f(path);auto before=f.snapshot();REQUIRE(install(&f.installer,f.mapped).error==Error::Disarmed);REQUIRE(f.calls.empty());f.unchanged(before);});
    run("wrong SHA pin",[&]{Fixture f(path);auto c=f.config();c.sha256[0]^=1;REQUIRE(arm(&f.installer,c,f.api()).error==Error::PinMismatch);REQUIRE(f.calls.empty()&&!f.installer.armed);});
    run("raw text changed after host pin",[&]{Fixture f(path);auto c=f.config();f.raw[0x440]^=1;REQUIRE(arm(&f.installer,c,f.api()).error==Error::PinMismatch);REQUIRE(f.calls.empty());});
    run("raw text changed after arming",[&]{Fixture f(path);REQUIRE(f.arm_here().error==Error::None);auto before=f.snapshot();f.raw[0x440]^=1;REQUIRE(install(&f.installer,f.mapped).error==Error::PinMismatch);REQUIRE(f.calls.empty());f.unchanged(before);});
    run("mutated mapped text",[&]{Fixture f(path);f.mapped[0x1040]^=1;no_install(f,Error::WrongImage);});
    run("mutated mapped header",[&]{Fixture f(path);f.mapped[0x40]^=1;no_install(f,Error::WrongImage);});
    run("mutated mapped readonly data",[&]{Fixture f(path);f.mapped[0x2240]^=1;no_install(f,Error::WrongImage);});
    run("DIR64 not applied",[&]{Fixture f(path);w64(f.mapped+0x1008,0x140001080);no_install(f,Error::WrongImage);});
    run("unknown relocation kind",[&]{Fixture f(path);w16(f.raw.data()+0x2408,0x3008);f.map_image();no_install(f,Error::WrongImage);});
    run("bad relocation block size",[&]{Fixture f(path);w32(f.raw.data()+0x2404,7);f.map_image();no_install(f,Error::WrongImage);});
    run("wrong header mapping owner",[&]{Fixture f(path);f.owners[0]=f.hook_base;no_install(f,Error::WrongImage);});
    run("wrong text mapping owner",[&]{Fixture f(path);f.owners[1]=f.hook_base;no_install(f,Error::WrongImage);});
    run("wrong IAT mapping owner",[&]{Fixture f(path);f.owners[2]=f.hook_base;no_install(f,Error::WrongImage);});
    run("mapping is not committed",[&]{Fixture f(path);f.state=0x2000;no_install(f,Error::WrongImage);});
    run("mapping is not MEM_IMAGE",[&]{Fixture f(path);f.type=0x20000;no_install(f,Error::WrongImage);});
    run("IAT mapped executable",[&]{Fixture f(path);f.protection[2]=0x20;no_install(f,Error::WrongImage);});
    run("IAT mapped writable",[&]{Fixture f(path);f.protection[2]=4;no_install(f,Error::WrongImage);});
    run("IAT section executable",[&]{Fixture f(path);w32(f.raw.data()+0x188+40+36,0x60000040);f.map_image();f.protection[2]=0x20;no_install(f,Error::WrongProtection);});
    run("IAT section writable",[&]{Fixture f(path);w32(f.raw.data()+0x188+40+36,0xc0000040);f.map_image();f.protection[2]=4;no_install(f,Error::WrongProtection);});
    run("text section writable and executable",[&]{Fixture f(path);w32(f.raw.data()+0x188+36,0xe0000020);f.map_image();no_install(f,Error::WrongImage);});
    run("unresolved original IAT",[&]{Fixture f(path);w64(f.mapped+0x2180,0x20c0);no_install(f,Error::NotResolved);});
    run("mismatched original IAT",[&]{Fixture f(path);w64(f.mapped+0x2180,reinterpret_cast<U64>(f.hook()));no_install(f,Error::NotResolved);});
    run("duplicate named import",[&]{Fixture f(path);w64(f.raw.data()+0x1488,0x20c0);no_arm(f,Error::WrongImport);});
    run("ordinal cannot stand for named CreateProcessW",[&]{Fixture f(path);w64(f.raw.data()+0x1480,0x8000000000001234ULL);no_arm(f,Error::WrongImport);});
    run("wrong import DLL",[&]{Fixture f(path);std::memcpy(f.raw.data()+0x1440,"USER32.dll",11);no_arm(f,Error::WrongImport);});
    run("missing import descriptor terminator",[&]{Fixture f(path);w32(f.raw.data()+0x1414+12,0x2040);no_arm(f,Error::WrongImport);});
    run("slot outside declared IAT",[&]{Fixture f(path);w32(f.raw.data()+0x98+208,0x2190);no_arm(f,Error::WrongImport);});
    run("wrong hook owner",[&]{Fixture f(path);f.hook_owner=f.genuine_base;no_arm(f,Error::WrongHook);});
    run("hook is writable",[&]{Fixture f(path);f.hook_protection=0x40;no_arm(f,Error::WrongHook);});
    run("wrong genuine API owner",[&]{Fixture f(path);f.genuine_owner=f.hook_base;no_arm(f,Error::WrongHook);});
    run("genuine API is not RX",[&]{Fixture f(path);f.genuine_protection=2;no_arm(f,Error::WrongHook);});
    run("missing genuine API module",[&]{Fixture f(path);auto c=f.config();c.genuine_module=nullptr;REQUIRE(arm(&f.installer,c,f.api()).error==Error::InvalidConfig&&f.calls.empty());});
    run("make writable failure keeps error",[&]{Fixture f(path);REQUIRE(f.arm_here().error==Error::None);auto before=f.snapshot();f.fail_protect=1;Result r=install(&f.installer,f.mapped);REQUIRE(r.error==Error::MakeWritableFailed&&r.system_error==f.failure_error&&r.rollback_complete);REQUIRE(f.calls.size()==1&&f.protection[2]==2&&!f.installer.installed);f.unchanged(before);});
    run("restore failure rolls original back and restores again",[&]{Fixture f(path);REQUIRE(f.arm_here().error==Error::None);auto before=f.snapshot();f.fail_protect=2;Result r=install(&f.installer,f.mapped);REQUIRE(r.error==Error::RestoreFailed&&r.system_error==f.failure_error&&r.rollback_complete);REQUIRE(f.calls.size()==3&&f.calls[0].requested==4&&f.calls[1].requested==2&&!f.calls[1].success&&f.calls[2].requested==2&&f.calls[2].success&&f.protection[2]==2&&!f.installer.installed);REQUIRE(f.last==f.success_error);f.unchanged(before);});
    run("second restore failure explicitly incomplete",[&]{Fixture f(path);REQUIRE(f.arm_here().error==Error::None);auto before=f.snapshot();f.fail_protect=2;f.fail_also=3;Result r=install(&f.installer,f.mapped);REQUIRE(r.error==Error::RollbackIncomplete&&r.system_error==f.failure_error&&!r.rollback_complete&&f.protection[2]==4&&!f.installer.installed);f.unchanged(before);});
    run("inconsistent old protection never requests executable page",[&]{Fixture f(path);REQUIRE(f.arm_here().error==Error::None);auto before=f.snapshot();f.wrong_old=0x40;Result r=install(&f.installer,f.mapped);REQUIRE(r.error==Error::WrongProtection&&r.rollback_complete&&f.calls.size()==2&&f.calls[0].requested==4&&f.calls[1].requested==2&&f.protection[2]==2&&!f.installer.installed);f.unchanged(before);});
    run("IAT changed before CAS is preserved",[&]{Fixture f(path);REQUIRE(f.arm_here().error==Error::None);auto before=f.snapshot();f.race=true;Result r=install(&f.installer,f.mapped);REQUIRE(r.error==Error::NotResolved&&f.calls.size()==2&&f.protection[2]==2&&!f.installer.installed);f.only_slot(before,0x12345678);});
    run("malformed DOS header",[&]{Fixture f(path);f.raw[0]=0;no_arm(f,Error::PinMismatch);});
    run("wrong ISA",[&]{Fixture f(path);w16(f.raw.data()+0x84,0x14c);no_arm(f,Error::PinMismatch);});
    run("bad e_lfanew",[&]{Fixture f(path);w32(f.raw.data()+0x3c,0xffffff00);no_arm(f,Error::PinMismatch);});
    std::printf("PASS %u installer cases: pinned PE64/relocations, mapping ownership, exact sole IAT mutation, nonexecuting R-RW-R, fail-closed imports and rollback error capture\n",checks);
}
'''
with tempfile.TemporaryDirectory(prefix='check-iat-', dir=HERE) as temp:
    folder = Path(temp)
    (folder / 'test.cpp').write_text(harness)
    subprocess.run([os.environ.get('CXX', 'g++'), '-std=c++17', '-O1', '-g',
                    '-Wall', '-Wextra', '-Werror', '-Wno-misleading-indentation',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie',
                    '-I' + str(HERE), str(folder / 'test.cpp'), str(HERE / 'iat_install.cpp'),
                    '-o', str(folder / 'check-iat')], check=True)
    subprocess.run([str(folder / 'check-iat'), str(fixture)], check=True)
print(f'SYNTHETIC TEST DATA {fixture}: SHA256 {fixture_sha}', flush=True)
