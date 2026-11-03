#!/usr/bin/env python3
"""Host regression checks against the real native Steam CEF argument policy.

Extracts the Steam NtCreateUserProcess block, never the Social Club helper.
All build products live in an automatically removed fixture-local directory.
"""
from pathlib import Path
import os
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = next(parent for parent in HERE.parents if (parent/'build/ntdll-unix/steam_cef_policy.h').is_file())
source = (ROOT / 'build/ntdll-unix/process_ios.c').read_text()
start = source.index('    {', source.index('    /* task #34 single-process CEF:'))
end = source.index('    /* madeira-bcd: env.MADEIRA_CHILD_ARGS', start)
block = source[start:end]
assert 'BRP left to Valve' in block
assert 'static const char sp_jitless[]' in block

reference = r'''
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "steam_cef_policy.h"
#include "madeira_redact.h"
typedef unsigned short WCHAR;
typedef struct { WCHAR *Buffer; unsigned short Length, MaximumLength; } STRING;
typedef struct { STRING ImagePathName, CommandLine; } PARAMS;
#define STATUS_ACCESS_DENIED 0xc0000022u
static int ref_jitless;
static char *fixture_getenv(const char *key) {
    if (!strcmp(key,"MADEIRA_JITLESS")) return ref_jitless ? "1" : "0";
    return NULL;
}
#define getenv fixture_getenv
static int capture(int fd,const char *format,...) { (void)fd; (void)format; return 0; }
#define dprintf capture
static unsigned apply(PARAMS *params) { BLOCK return 0; }
int native_reference(const WCHAR *image, size_t image_length, const WCHAR *line,
                     size_t length, int jitless, WCHAR *out, size_t capacity) {
    PARAMS p={{(WCHAR *)image,image_length*2,image_length*2+2},
              {(WCHAR *)line,length*2,length*2+2}};
    ref_jitless=jitless;
    unsigned status=apply(&p);
    if(status || p.CommandLine.Buffer==line) return -1;
    size_t count=p.CommandLine.Length/2;
    if(count+1>capacity) { free(p.CommandLine.Buffer); return -1; }
    memcpy(out,p.CommandLine.Buffer,(count+1)*2);
    free(p.CommandLine.Buffer);
    return (int)count;
}
'''.replace('BLOCK', block)

harness = r'''
#include "fixture_args.h"
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>
using namespace madeira_cef_fixture;
extern "C" int native_reference(const U16 *,size_t,const U16 *,size_t,int,U16 *,size_t);
static unsigned checks;
static std::vector<U16> wide(const std::string &s) {
    std::vector<U16> w; for(unsigned char c:s)w.push_back(c); w.push_back(0); return w;
}
static const char *fixed=" --single-process --enable-logging --v=1 --log-severity=verbose --no-proxy-server --winhttp-proxy-resolver";
static const char *features=",SegmentationPlatform,OptimizationTargetPrediction,OptimizationHints";
static const char *js=" --js-flags=--jitless";
static std::string ascii(const std::vector<U16>&w, int n) {
    std::string s; for(int i=0;i<n;i++) { assert(w[i]<256);s.push_back(char(w[i])); }return s;
}
static void compare_wide(std::vector<U16> image,std::vector<U16> line,bool jitless,
                         int expect_changed=-1) {
    auto original=line, original_image=image;
    std::vector<U16> got(40000,0xcccc), ref(40000,0xcccc);
    int n=browser_args(image.data(),image.size()-1,line.data(),line.size()-1,jitless,got.data(),got.size());
    int r=native_reference(image.data(),image.size()-1,line.data(),line.size()-1,jitless,ref.data(),ref.size());
    assert(n==r && got==ref && line==original && image==original_image);
    if(expect_changed>=0)assert((n>=0)==bool(expect_changed));
    if(n>=0) {
        assert(got[n]==0 && got[n+1]==0xcccc);
        std::string tail=std::string(fixed)+(jitless?js:"");auto wt=wide(tail);
        assert(n>=int(wt.size()-1));
        assert(std::equal(wt.begin(),wt.end()-1,got.begin()+n-(wt.size()-1)));
    } else assert(got==std::vector<U16>(40000,0xcccc));
    ++checks;
}
static void compare(const std::string&line,bool jitless=true,int changed=-1,
                    const std::string&image="C:\\Steam\\bin\\SteamWebHelper.EXE") {
    compare_wide(wide(image),wide(line),jitless,changed);
}
static void exact(const std::string &line,const std::string &expected,bool jitless=true) {
    auto i=wide("C:\\Steam\\steamwebhelper.exe"),w=wide(line);
    std::vector<U16> got(40000,0xcccc);auto original=w;
    int n=browser_args(i.data(),i.size()-1,w.data(),w.size()-1,jitless,got.data(),got.size());
    assert(n==int(expected.size()) && ascii(got,n)==expected && w==original);
    ++checks;
}
int main() {
    const std::string base="steamwebhelper.exe";
    exact(base,base+fixed+js);
    exact(base,base+fixed,false);
    exact(base+" --disable-features=ValveFeature",base+" --disable-features=ValveFeature"+features+fixed+js);
    exact(base+" --disable-features=",base+" --disable-features="+features+fixed+js);
    exact(base+" --disable-features=One --disable-features=Two",base+" --disable-features=One"+features+" --disable-features=Two"+fixed+js);
    exact(base+" --disable-features=\"One,Two\"",base+" --disable-features="+features+"\"One,Two\""+fixed+js);
    exact(base+" --log-file=\"C:\\Steam\\web log.txt\" --auth-token=fixture --sandbox=enabled --enable-features=PartitionAllocBackupRefPtr",
          base+" --log-file=\"C:\\Steam\\web log.txt\" --auth-token=fixture --sandbox=enabled --enable-features=PartitionAllocBackupRefPtr"+fixed+js);
    exact(base+" --js-flags=\"--existing --flags\" --single-process --no-proxy-server",base+" --js-flags=\"--existing --flags\" --single-process --no-proxy-server"+fixed+js);
    struct RoleCase { const char *tail; bool browser; } roles[]={
        {"",true},{" --type=renderer",false},{" --type=gpu-process",false},
        {" --type=utility",false},{" --type=crashpad-handler",false},
        {" \"--type=crashpad-handler\"",false},{" --type=renderer --type=",true},
        {" --type=renderer --type",true},{" --type= --type=renderer",false},
        {" --type=renderer --type=crashpad-handler",false},
        {" --type=crashpad-handler --type=renderer",false},
        {" --type=crashpad-handler-extra",false},{" /type=renderer",false},
        {" -type=renderer",false},{" --Type=renderer",true},{" --type=RENDERER",false},
        {" -- --type=renderer",true},{" --type=renderer -- --type=",false},
        {" --log-file=\"C:\\--type=renderer\"",true},
        {" --other=\"--type=renderer\"",true},{" \"--type=renderer\"",false},
        {" --ty\"pe\"=renderer",false},{" --type=\"renderer\"",false},
        {" --type=\"\"",true},{" \"--type=ren\"\"derer\"",false},
        {" --other=\\\"--type=renderer",true},{" --type=renderer\t--type=",true},
        {" --type=\"renderer with space\"",false}
    };
    for(auto c:roles)for(bool jitless:{false,true})compare(base+c.tail,jitless,c.browser);
    std::vector<std::string> cases={base,
        base+" --disable-features=ValveFeature --auth-token=fixture",
        base+" --disable-features=One,Two --disable-features=Three",
        base+" --disable-features=\"One,Two\"",
        base+" \"--disable-features=One,Two\"",
        base+" --disable-features=One\t--test=Two",
        base+" --other=\"--disable-features=embedded\"",
        base+" --disable-features=",
        base+" --disable-features=One --js-flags=\"--old --flag\"",
        base+" --enable-logging=file --v=9 --log-severity=fatal --proxy-server=fixture",
        base+" --auth-token=fixture --sandbox=enabled --enable-features=PartitionAllocBackupRefPtr",
        base+" -- --disable-features=One",
        "\"C:\\Steam Folder\\steamwebhelper.exe\" --log-file=\"C:\\logs\\file.txt\"",
        base+" --password=\"white space \\\" quote\" --type=\"\""};
    for(const auto&c:cases)for(bool jitless:{false,true})compare(c,jitless,1);
    for(const char* image:{"C:\\steamwebhelper.exe\\game.exe","notsteamwebhelper.exe","steamwebhelper.exe.old","C:/Steam/game.exe",""})
        compare(base,true,0,image);
    compare(base,true,1,"steamwebhelper.exe");
    compare(base,true,1,"C:/Steam/STEAMWEBHELPER.EXE");
    auto nonascii=wide(base+" --auth-token=");nonascii.pop_back();
    nonascii.insert(nonascii.end(),{0x03b1,0xd83d,0xde00,0x4e2d,0});
    compare_wide(wide("C:\\Steam\\steamwebhelper.exe"),nonascii,true,1);
    std::mt19937 random(0xcef);
    const char* tokens[]={"--disable-features=One","--disable-features=Two,Three","--type=renderer","--type=","--other=\"--type=renderer\"","--js-flags=--existing","--single-process","--log-file=\"C:\\space path\\x\"","--auth-token=fixture","--sandbox=enabled","--","/type=utility","\"--type=crashpad-handler\"","--enable-features=PartitionAllocBackupRefPtr"};
    for(int z=0;z<240;++z){std::string line=base;for(unsigned n=1+random()%9;n;--n)line+=(random()%3==0?"\t":" ")+std::string(tokens[random()%(sizeof(tokens)/sizeof(*tokens))]);compare(line,random()%2);}
    // Capacity and boundary failures are transactional: input/output bytes survive.
    auto image=wide("C:\\Steam\\steamwebhelper.exe"),line=wide(base),copy=line;
    const size_t needed=base.size()+strlen(fixed)+strlen(js);
    for(size_t cap:{size_t(0),size_t(1),needed}){
        std::vector<U16> out(needed+3,0xaaaa), before=out;
        assert(browser_args(image.data(),image.size()-1,line.data(),line.size()-1,true,out.data(),cap)==-1);
        assert(out==before && line==copy);++checks;
    }
    {std::vector<U16> out(needed+2,0xaaaa);assert(browser_args(image.data(),image.size()-1,line.data(),line.size()-1,true,out.data(),needed+1)==int(needed));assert(out[needed]==0 && out[needed+1]==0xaaaa);++checks;}
    for(size_t length:{size_t(32766),size_t(32767)}){
        std::vector<U16> large(length+1,'x'),before=large,out(40000,0xaaaa),saved=out;large.back()=before.back()=0;
        assert(browser_args(image.data(),image.size()-1,large.data(),length,true,out.data(),out.size())==-1);
        assert(large==before && out==saved);++checks;
    }
    {std::vector<U16> out(40000,0xaaaa),saved=out;
        assert(browser_args(nullptr,0,line.data(),line.size()-1,true,out.data(),out.size())==-1);
        assert(browser_args(image.data(),image.size()-1,nullptr,0,true,out.data(),out.size())==-1);
        assert(browser_args(image.data(),image.size()-1,line.data(),line.size()-1,true,nullptr,0)==-1);
        assert(out==saved && line==copy);checks+=3;}
    std::printf("PASS %u argument cases: native-byte differential, role/quoting, security/auth preservation, jitless, bounds and transactional rejection\n",checks);
}
'''

with tempfile.TemporaryDirectory(prefix='check-args-', dir=HERE) as temp:
    folder = Path(temp)
    (folder / 'native_reference.c').write_text(reference)
    (folder / 'test.cpp').write_text(harness)
    common = ['-O1', '-g', '-Wall', '-Wextra', '-Werror',
              '-Wno-misleading-indentation', '-fsanitize=address,undefined',
              '-fno-omit-frame-pointer', '-fno-pie']
    subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', *common,
                    '-I' + str(ROOT / 'build/ntdll-unix'), '-I' + str(ROOT / 'build'),
                    '-c', str(folder / 'native_reference.c'), '-o', str(folder / 'native_reference.o')], check=True)
    subprocess.run([os.environ.get('CXX', 'g++'), '-std=c++17', *common, '-no-pie',
                    '-I' + str(HERE), '-I'+str(ROOT/'build/ntdll-unix'), str(folder / 'test.cpp'), str(HERE / 'fixture_args.cpp'),
                    str(folder / 'native_reference.o'), '-o', str(folder / 'check-args')], check=True)
    subprocess.run([str(folder / 'check-args')], check=True)
