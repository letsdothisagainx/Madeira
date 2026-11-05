/* SPDX-License-Identifier: MIT. Test the exact runtime argument helper. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "htmlipc_log_path.h"

static const char steam[]="C:\\Program Files (x86)\\Steam\\steam.exe";
static const char file[]=" --log-file=\"C:\\Program Files (x86)\\Steam\\logs\\madeira-cef-debug.log\"";
static const char stderr_flag[]=" --enable-logging=stderr";
static size_t widen(uint16_t *out,const char *s)
{ size_t n=strlen(s);for(size_t i=0;i<=n;i++)out[i]=(unsigned char)s[i];return n; }
static void equal(const uint16_t *s,size_t n,const char *a)
{ assert(n==strlen(a));for(size_t i=0;i<n;i++)assert(s[i]==(unsigned char)a[i]);assert(!s[n]); }
static void test(const char *command,const char *parent,enum madeira_htmlipc_log_route route,const char *tail)
{
    uint16_t out[4096],image[1024],original[4096];size_t n=widen(out,command),sn=widen(image,parent),written=0;
    memcpy(original,out,(n+1)*sizeof(*out));
    assert(madeira_htmlipc_route_log(out,n,4096,image,sn,&written)==route);
    assert(!memcmp(out,original,n*sizeof(*out))); /* Every original argument stays byte-identical. */
    if(tail){equal(out+n,written-n,tail);assert(written==n+strlen(tail));}
    else{assert(written==n);equal(out,written,command);}
}
int main(void)
{
    test("helper.exe -steampid=32 -buildid=1792618285 -logdir=\"C:\\Program Files (x86)\\Steam\\logs\" --single-process --enable-logging",
         steam,MADEIRA_HTMLIPC_LOG_STEAM,file);
    test("helper.exe \"-logdir=C:\\Program Files (x86)\\Steam\\logs\" --js-flags=\"--jitless --max_old_space_size=128\"",
         steam,MADEIRA_HTMLIPC_LOG_STEAM,file);
    test("helper.exe -logdir \"C:\\Program Files (x86)\\Steam\\logs\" --disable-features=KeepValveValues",
         steam,MADEIRA_HTMLIPC_LOG_STEAM,file);
    test("helper.exe -logdir=elsewhere --log-file=\"D:\\Valve Logs\\existing.log\"",steam,MADEIRA_HTMLIPC_LOG_EXPLICIT,NULL);
    test("helper.exe --LOG-FILE \"D:\\Valve Logs\\existing.log\"",steam,MADEIRA_HTMLIPC_LOG_EXPLICIT,NULL);
    test("helper.exe --log-file=",steam,MADEIRA_HTMLIPC_LOG_EXPLICIT,NULL);
    test("helper.exe --enable-logging --js-flags=\"--log-file=C:\\fake.log -logdir=unsafe\"",steam,MADEIRA_HTMLIPC_LOG_STDERR,stderr_flag);
    test("helper.exe -logdir=C:\\elsewhere",steam,MADEIRA_HTMLIPC_LOG_STDERR,stderr_flag);
    test("helper.exe -logdir=",steam,MADEIRA_HTMLIPC_LOG_STDERR,stderr_flag);
    test("helper.exe",steam,MADEIRA_HTMLIPC_LOG_STDERR,stderr_flag);
    test("helper.exe \"-logdir=C:\\Program Files (x86)\\Steam\\logs\" -logdir=C:\\other",steam,MADEIRA_HTMLIPC_LOG_STDERR,stderr_flag);
    test("helper.exe -logdir=C:\\Steam\\logs","C:\\Steam\\..\\steam.exe",MADEIRA_HTMLIPC_LOG_STDERR,stderr_flag);
    test("helper.exe -logdir=C:\\windows\\madeira-compat\\logs","C:\\windows\\madeira-compat\\Steam.exe",MADEIRA_HTMLIPC_LOG_STDERR,stderr_flag);
    test("helper.exe -logdir=C:\\Steam\\logs","\\\\server\\Steam\\Steam.exe",MADEIRA_HTMLIPC_LOG_STDERR,stderr_flag);
    {
        uint16_t out[1024],image[256],original[1024];size_t n,sn,written=123;
        n=widen(out,"helper.exe -- --log-file=positional");sn=widen(image,steam);
        assert(madeira_htmlipc_route_log(out,n,1024,image,sn,&written)==MADEIRA_HTMLIPC_LOG_STDERR);
        equal(out,written,"helper.exe  --enable-logging=stderr -- --log-file=positional");
        n=widen(out,"helper.exe -logdir=\"broken");memcpy(original,out,(n+1)*2);
        assert(madeira_htmlipc_route_log(out,n,1024,image,sn,&written)==MADEIRA_HTMLIPC_LOG_ERROR);
        assert(!memcmp(original,out,(n+1)*2));
        n=widen(out,"helper.exe");memcpy(original,out,(n+1)*2);
        assert(madeira_htmlipc_route_log(out,n,n+1,image,sn,&written)==MADEIRA_HTMLIPC_LOG_ERROR);
        assert(!memcmp(original,out,(n+1)*2));
    }
    puts("PASS CEF mutable output: trusted Steam logs, explicit paths, argv preservation, safe stderr fallback and bounds");
}
