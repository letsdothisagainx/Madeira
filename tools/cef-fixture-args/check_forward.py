#!/usr/bin/env python3
"""Exercise every CreateProcessW argument and BOOL/LastError preservation."""
from pathlib import Path
import os,subprocess,tempfile
here=Path(__file__).resolve().parent
native_root=next(parent for parent in here.parents if (parent/'build/ntdll-unix/steam_cef_policy.h').is_file())
source=r'''
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <string>
#define _WIN64 1
#define __declspec(x)
#define MADEIRA_CEF_ARGS_TEST_ONLY 1
#define MADEIRA_CEF_ARGS_EMBEDDED 1
#include "windows_loader.cpp"
static U32 error_value;static bool fail_heap;static int answer;static U32 outgoing;
static const U16 *expected_app,*expected_dir;static U16 *expected_line;static bool changed;
static std::u16string wide(const char *s){std::u16string r;while(*s)r+=char16_t(*s++);return r;}
static int genuine(const U16 *app,U16 *line,SecurityAttributes *pa,SecurityAttributes *ta,int inherit,
    U32 flags,void *env,const U16 *dir,StartupInfoW *si,ProcessInformation *pi){
    assert(GetLastError()==0x77);assert(app==expected_app&&dir==expected_dir);
    assert(pa==reinterpret_cast<SecurityAttributes*>(0x101)&&ta==reinterpret_cast<SecurityAttributes*>(0x202));
    assert(inherit==7&&flags==0x12345678&&env==reinterpret_cast<void*>(0x303));
    assert(si==reinterpret_cast<StartupInfoW*>(0x404)&&pi==reinterpret_cast<ProcessInformation*>(0x505));
    if(changed){assert(line!=expected_line);std::u16string s(reinterpret_cast<char16_t*>(line));
        assert(s.find(u"--single-process")!=s.npos&&s.find(u"--js-flags=--jitless")!=s.npos);
        assert(s.find(u"--auth-token=retain")!=s.npos&&s.find(u"PartitionAllocBackupRefPtr")==s.npos);
    }else assert(line==expected_line);
    SetLastError(outgoing);return answer;
}
extern "C" {
void *GetModuleHandleW(const U16 *){return nullptr;}
int GetModuleHandleExW(U32,const U16 *,void **){return 0;}
void *GetProcAddress(void *,const char *){return nullptr;}
U32 GetModuleFileNameW(void *,U16 *,U32){return 0;}
U32 GetEnvironmentVariableW(const U16 *,U16 *,U32){return 0;}
U32 GetFullPathNameW(const U16 *input,U32 cap,U16 *out,U16 **){Size n=0;while(input[n])++n;
    assert(n<cap);for(Size i=0;i<=n;++i)out[i]=input[i];error_value=0x999;return U32(n);}
U32 GetLastError(){return error_value;}void SetLastError(U32 e){error_value=e;}
Size VirtualQuery(const void *,Mbi *,Size){return 0;}
int VirtualProtect(void *,Size,U32,U32 *){return 0;}int DisableThreadLibraryCalls(void *){return 1;}
void *GetProcessHeap(){error_value=0x666;return reinterpret_cast<void*>(1);}
void *HeapAlloc(void *,U32,Size size){error_value=0x777;return fail_heap?nullptr:std::malloc(size);}
int HeapFree(void *,U32,void *memory){error_value=0x888;std::free(memory);return 1;}
void *CreateFileW(const U16 *,U32,U32,void *,U32,U32,void *){return reinterpret_cast<void*>(~Size(0));}
int GetFileSizeEx(void *,long long *){return 0;}int ReadFile(void *,void *,U32,U32 *,void *){return 0;}
int CloseHandle(void *){return 1;}void OutputDebugStringA(const char *){error_value=0xaaa;}
}
int main(){
    auto prefix=wide("C:\\fixture\\");root_length=prefix.size();for(Size i=0;i<root_length;++i)root[i]=prefix[i];
    auto helper=wide("C:\\fixture\\bin\\steamwebhelper.exe"),other=wide("C:\\fixture\\game.exe"),dir=wide("C:\\fixture");
    auto browser=wide("steamwebhelper.exe --auth-token=retain --sandbox=enabled"),child=wide("steamwebhelper.exe --type=renderer");
    original=genuine;expected_dir=reinterpret_cast<const U16*>(dir.c_str());unsigned cases=0;
    for(int result:{0,1,-7})for(U32 after:{0u,5u,0xdeadbeefu})for(unsigned mode=0;mode<6;++mode){
        answer=result;outgoing=after;fail_heap=mode==3;changed=mode==0||mode==4;
        expected_app=mode==2?reinterpret_cast<const U16*>(other.c_str()):mode==4?nullptr:reinterpret_cast<const U16*>(helper.c_str());
        auto command=mode==1?child:browser;if(mode==4)command=wide("\"C:\\fixture\\bin\\steamwebhelper.exe\" --auth-token=retain");
        if(mode==5)expected_app=reinterpret_cast<const U16*>(u"C:\\elsewhere\\steamwebhelper.exe");
        auto before=command;expected_line=reinterpret_cast<U16*>(command.data());error_value=0x77;
        int got=MadeiraCefFixtureCreateProcessW(expected_app,expected_line,reinterpret_cast<SecurityAttributes*>(0x101),
            reinterpret_cast<SecurityAttributes*>(0x202),7,0x12345678,reinterpret_cast<void*>(0x303),expected_dir,
            reinterpret_cast<StartupInfoW*>(0x404),reinterpret_cast<ProcessInformation*>(0x505));
        assert(got==answer&&GetLastError()==after&&command==before);++cases;
    }
    std::printf("PASS %u CreateProcessW forwarding cases; all ten arguments, BOOL and LastError preserved\n",cases);
}
'''
with tempfile.TemporaryDirectory(prefix='cef-forward-') as tmp:
    tmp=Path(tmp);(tmp/'fixture_pin.h').write_text('static constexpr unsigned char fixture_sha256[32]={};\nstatic constexpr long long fixture_file_size=1;\nstatic constexpr char fixture_test_token[]="00000000000000000000000000000000";\n')
    (tmp/'test.cpp').write_text('#include <cstdio>\n'+source)
    cmd=[os.environ.get('CXX','g++'),'-std=c++20','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',
         '-I'+str(here),'-I'+str(tmp),'-I'+str(native_root/'build/ntdll-unix'),str(tmp/'test.cpp'),str(here/'fixture_args.cpp'),str(here/'iat_install.cpp'),'-o',str(tmp/'test')]
    subprocess.run(cmd,check=True);subprocess.run([str(tmp/'test')],check=True)
