#!/usr/bin/env python3
"""Normal-input process-local feature selection and real FEX ARM64 emission.
Execute the staged profile + actual CPUFeatures selector + scalar StoreMemTSO
body using the pinned real CodeEmitter headers. Only config/IR/register-allocation
and logging services are adapted. Emitted ARM64 bytes are inspected, not executed;
no executable/protected mappings or deliberate faults are used.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]
def function(text, signature):
    start=text.index(signature);brace=text.index('{',start);depth=1;end=brace+1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return text[start:end]+'\n'
with tempfile.TemporaryDirectory(prefix='madeira-cs2-tso-') as directory:
    work=Path(directory);stage=work/'stage'
    subprocess.run(['python3',str(ROOT/'tools/build/stage-fex-compat.py'),'stage',str(stage),'--backend','arm64ec'],check=True)
    module=(stage/'Source/Windows/ARM64EC/Module.cpp').read_text()
    init=function(module,'NTSTATUS ProcessInit()')
    assert init.index('LoadConfig(')<init.index('ReloadMetaLayer(')<init.index('Logging::Init()')<init.index('MadeiraConfigureCS2TSO(')<init.index('CPUFeatures::FetchHostFeatures(')<init.index('CreateNewContext(')
    owned_name = next(line.strip() for line in init.splitlines() if 'const fextl::string ExecutableName {' in line)
    basename = function((ROOT/'FEX/Source/Windows/Common/Module.h').read_text(),'inline std::string_view BaseName(')
    profile=function(module,'static bool MadeiraConfigureCS2TSO(')
    assert 'setenv' not in profile and 'putenv' not in profile and 'ReloadMetaLayer' not in profile
    selected=function(module,'    if (MadeiraCS2TSO)')
    cpu=function((ROOT/'FEX/Source/Windows/Common/CPUFeatures.cpp').read_text(),'FEXCore::HostFeatures CPUFeatures::FetchHostFeatures(')
    memory=(ROOT/'FEX/FEXCore/Source/Interface/Core/JIT/MemoryOps.cpp').read_text()
    store=function(memory,'DEF_OP(StoreMemTSO)')
    scalar=store[:store.index('\n  } else {')]+ '  }\n}\n'
    scalar=scalar.replace('DEF_OP(StoreMemTSO)', 'void StoreMemTSO(const IR::Header* IROp)')
    # Use the actual config generator's enum, not invented feature-bit values.
    generator=(ROOT/'FEX/FEXCore/Scripts/config_generator.py').read_text()
    # Enum declarations are deterministically generated from the pinned JSON.
    import json
    data=json.loads((ROOT/'FEX/FEXCore/Source/Interface/Config/Config.json.in').read_text())
    enums=next(group['HostFeatures']['Enums'] for group in data['Options'].values() if 'HostFeatures' in group)
    assert '1 <<' in generator or '1ULL <<' in generator
    bits='\n'.join(f'constexpr uint64_t {name}=UINT64_C(1)<<{i};' for i,name in enumerate(enums))
    stub=work/'include';(stub/'FEXCore/Utils').mkdir(parents=True);(stub/'FEXCore/fextl').mkdir(parents=True)
    (stub/'FEXCore/fextl/vector.h').write_text('#pragma once\n#include <vector>\nnamespace fextl {template<class T>using vector=std::vector<T>;}\n')
    (stub/'FEXCore/Utils/LogManager.h').write_text(r'''
#pragma once
#include <cassert>
#include <iostream>
#include <sstream>
#include <string>
#define LOGMAN_THROW_A_FMT(c,...) assert(c)
#define LOGMAN_MSG_A_FMT(...) assert(false)
namespace LogMan::Msg {
inline void format(std::ostringstream& o, const char* f) {o<<f;}
template<class T,class...Rest> void format(std::ostringstream& o,const char* f,T value,Rest...rest) {
 const std::string text(f);const auto pos=text.find("{}");assert(pos!=std::string::npos);
 o<<text.substr(0,pos)<<std::boolalpha<<value;format(o,f+pos+2,rest...);
}
template<class...T>void IFmt(const char* f,T...value){std::ostringstream o;format(o,f,value...);std::cout<<o.str()<<"\n";}
}
''')
    code=r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <unordered_map>
#include <strings.h>
#include <CodeEmitter/Emitter.h>
#include <FEXCore/Core/HostFeatures.h>
#define FEX_IOS_HOST 1
#define ARCHITECTURE_arm64ec 1
namespace fextl {using string=std::string;namespace fmt {inline std::string format(const char*,uint64_t n){return std::to_string(n);}}}
#define _stricmp strcasecmp
namespace FEXCore::Config {
namespace HostFeatures {
@BITS@
}
enum ConfigOption {CONFIG_HOSTFEATURES,CONFIG_ENABLECODECACHINGWIP,CONFIG_TSOENABLED,CONFIG_HALFBARRIERTSOENABLED};
struct ProcessConfig {std::unordered_map<ConfigOption,uint64_t> values;};
static ProcessConfig* active;
static uint64_t get(ConfigOption option){return active->values.at(option);}
static void Set(ConfigOption option,std::string_view text){active->values[option]=std::stoull(std::string(text));}
}
#define FEX_CONFIG_OPT(name,key) auto name=[](){if constexpr(FEXCore::Config::CONFIG_##key==FEXCore::Config::CONFIG_TSOENABLED || FEXCore::Config::CONFIG_##key==FEXCore::Config::CONFIG_HALFBARRIERTSOENABLED)return bool(FEXCore::Config::get(FEXCore::Config::CONFIG_##key));else return FEXCore::Config::get(FEXCore::Config::CONFIG_##key);}
@PROFILE@
namespace FEX::Windows {
struct CPUFeatures {static FEXCore::HostFeatures FetchHostFeatures(bool,FEXCore::HostFeatures::HostTypeEnum);};
@CPU@
}
namespace IR {
enum class RegClass {GPR, FPR};
enum class OpSize {i8Bit,i16Bit,i32Bit,i64Bit};
enum class MemOffsetType {SXTX};
struct Ref {unsigned reg{};bool invalid{};uint64_t value{};bool IsInvalid() const{return invalid;}};
struct IROp_StoreMemTSO {RegClass Class=RegClass::GPR;Ref Addr{26},Value{22},Offset{0,true};unsigned OffsetScale=1;MemOffsetType OffsetType=MemOffsetType::SXTX;};
struct Header {IR::OpSize Size;IROp_StoreMemTSO op;template<class T>const T* C() const{return &op;}};
}
struct JIT : ARMEmitter::Emitter {
 struct Context {FEXCore::HostFeatures HostFeatures;};Context* CTX;
 explicit JIT(Context* context,uint8_t* bytes,size_t length):Emitter(bytes,length),CTX(context){}
 ARMEmitter::Register GetReg(IR::Ref ref){return ARMEmitter::Register(ref.reg);}
 ARMEmitter::Register GetZeroableReg(IR::Ref ref){return GetReg(ref);}
 bool IsInlineConstant(IR::Ref ref,uint64_t* value){*value=ref.value;return true;}
 @STORE@
};
static void check_emission(const FEXCore::HostFeatures& features) {
 for(unsigned width=0;width<4; ++width) {
  alignas(16) uint32_t words[8]{};JIT::Context context{features};JIT jit(&context,(uint8_t*)words,sizeof(words));
  IR::Header op{IR::OpSize(width),{}};
  if (width==3) {op.op.Addr.reg=6;op.op.Value.reg=19;} // captured d90000d3 site
  jit.StoreMemTSO(&op);
  const uint32_t stlr[]={0x089ffc00u,0x489ffc00u,0x889ffc00u,0xc89ffc00u};
  const uint32_t stlur[]={0x19000000u,0x59000000u,0x99000000u,0xd9000000u};
  unsigned index=width?1:0;
  if(width)assert(words[0]==0xd503201fu); // original half-barrier/backpatch slot preserved
  const auto expected=(features.SupportsTSOImm9?stlur[width]:stlr[width])|(op.op.Addr.reg<<5)|op.op.Value.reg;
  assert(words[index]==expected && jit.GetCursorOffset()==4*(index+1));
  printf("EMITTED LRCPC2=%d width=%u word=%08x kind=%s\n",features.SupportsTSOImm9,1u<<width,words[index],features.SupportsTSOImm9?"STLUR":"STLR");
 }
}
static void run(const char* ExecutableName, uint64_t mask, bool expected) {
 using namespace FEXCore::Config;
 ProcessConfig process{{{CONFIG_HOSTFEATURES,mask},{CONFIG_ENABLECODECACHINGWIP,1},{CONFIG_TSOENABLED,1},{CONFIG_HALFBARRIERTSOENABLED,1}}};active=&process;
 const std::string original_env=getenv("FEX_HOSTFEATURES");
 const bool MadeiraCS2TSO=MadeiraConfigureCS2TSO(ExecutableName);assert(MadeiraCS2TSO==expected);
 assert(original_env==getenv("FEX_HOSTFEATURES"));
 const auto wanted=expected?(mask&~HostFeatures::ENABLELRCPC2)|HostFeatures::DISABLELRCPC2:mask;
 assert(get(CONFIG_HOSTFEATURES)==wanted);
 assert(get(CONFIG_ENABLECODECACHINGWIP)==(expected?0u:1u));
 assert(get(CONFIG_TSOENABLED)==1 && get(CONFIG_HALFBARRIERTSOENABLED)==1);
 auto HostFeatures=FEX::Windows::CPUFeatures::FetchHostFeatures(true,FEXCore::HostFeatures::HostTypeEnum::Arm64ec);
 @SELECTED@
 assert(HostFeatures.SupportsTSOImm9==!expected);
 check_emission(HostFeatures);
}
namespace FEX::Windows {
@BASENAME@
inline fextl::string GetExecutableFilePath(){return "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Counter-Strike Global Offensive\\game\\bin\\win64\\cs2.exe";}
}
static void check_owned_name() {
 @OWNED@
 static_assert(std::is_same_v<decltype(ExecutableName),const fextl::string>);
 std::vector<std::string> ordinary_allocations(128,std::string(128,'x'));
 assert(ExecutableName=="cs2.exe" && ordinary_allocations.size()==128);
 puts("PASS actual initializer owns its executable basename across config allocations (no borrowed view)");
}
int main() {
 check_owned_name();
 // Fixture-owned environment only. Production profile never changes it.
 assert(!setenv("FEX_MADEIRA_HOSTPROBE","AFP=1,FLAGM=1,RCPC=1,LRCPC2=1,ATOMICS=1",1));
 assert(!setenv("FEX_HOSTFEATURES","enableafp,disableavx",1));
 using namespace FEXCore::Config;
 run("steam.exe",HostFeatures::ENABLEAFP|HostFeatures::DISABLEAVX,false);
 run("steamwebhelper.exe",0,false);
 run("cs2.exe",HostFeatures::ENABLEAFP|HostFeatures::DISABLEAVX,true);
 run("CS2.EXE",HostFeatures::ENABLELRCPC2|HostFeatures::DISABLEAVX,true);
 run("notcs2.exe",0,false);run("cs2.exe.bak",0,false);
 run("cs2.exe",0,true);
 puts("PASS staged CS2-only profile merges flags, preserves TSO/halfbar and parent environment; real pinned CPUFeatures and StoreMemTSO/CodeEmitter emit STLR fallback with unchanged NOP slots; other guests retain STLUR");
}
'''
    for key,value in {'BITS':bits,'PROFILE':profile,'CPU':cpu,'STORE':scalar,'SELECTED':selected,'OWNED':owned_name,'BASENAME':basename}.items():code=code.replace('@'+key+'@',value)
    source=work/'tso.cpp';binary=work/'tso';source.write_text(code)
    subprocess.run([os.environ.get('CXX','c++'),'-std=c++20','-O2','-Wall','-Wextra','-Werror','-Wno-unused-parameter',
      '-I'+str(stub),'-I'+str(ROOT/'FEX/FEXCore/include'),'-I'+str(ROOT/'FEX/CodeEmitter'),'-I'+str(ROOT/'FEX/FEXHeaderUtils'),str(source),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
