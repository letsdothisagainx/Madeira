/* SPDX-License-Identifier: MIT. Selection, wire-readiness and argv invariants. */
#include <assert.h>
#include <stdio.h>
#include "htmlipc_policy.h"
static size_t wide(uint16_t *out,const char *in){size_t i;for(i=0;in[i];i++)out[i]=(unsigned char)in[i];out[i]=0;return i;}
static struct madeira_htmlipc_preload_state recursion;
static unsigned loads;
static int load_good(void *p){(void)p;loads++;assert(madeira_htmlipc_preload(&recursion,0,load_good,NULL)==0);assert(madeira_htmlipc_preload(&recursion,1,load_good,NULL)==-1);return 1;}
static int load_bad(void *p){(void)p;loads++;return 0;}
int main(void){
    uint16_t helper[32768],cache[32768],old[32768],out[32768];size_t hn,cn,n,written,end;
    struct madeira_htmlipc_ready a={MADEIRA_HTMLIPC_READY_MAGIC,80,1,2,7,32,0,0,0,0x50000,17,0x71000000,0x72000000,9},b=a;
    assert(madeira_htmlipc_ready_valid(&a,&b,0x50000,17,32,0x71000000));
#define BAD(field,value) do{b=a;b.field=value;assert(!madeira_htmlipc_ready_valid(&b,&b,0x50000,17,32,0x71000000));}while(0)
    BAD(magic,0);BAD(size,0);BAD(version,2);BAD(sequence,0);BAD(sequence,3);BAD(flags,3);
    BAD(pid,33);BAD(provider_error,1);BAD(installer_error,1);BAD(reserved,1);BAD(owner_peb,0x60000);
    BAD(owner_lease,18);BAD(self_module,0x71001000);BAD(installed_module,0);BAD(generation,0);
    b=a;b.sequence=4;assert(!madeira_htmlipc_ready_valid(&a,&b,0x50000,17,32,0x71000000));
    assert(!madeira_htmlipc_ready_valid(&a,&a,0x50000,0,32,0x71000000));
    hn=wide(helper,"C:\\windows\\madeira-compat\\SteamBrowserRuntime\\v1\\bin\\cef\\cef.win7\\steamwebhelper.exe");
    cn=wide(cache,"C:\\windows\\madeira-compat\\SteamBrowserRuntime\\v1\\bin\\cef\\cef.win7");
    assert(madeira_htmlipc_cache_target(helper,hn,cache,cn));
    cache[0]='D';assert(!madeira_htmlipc_cache_target(helper,hn,cache,cn));cache[0]='C';
    assert(!madeira_htmlipc_cache_target(helper,hn,cache,cn-1));
    n=wide(old,"\"C:\\Program Files (x86)\\Steam\\bin\\cef\\cef.win7\\steamwebhelper.exe\" -nocrashdialog \"-cachedir=C:\\users\\mobile\\AppData\\Local\\Steam\\htmlcache\" \"-steampid=32\" \"-buildid=1769731672\" \"-steamid=0\" --js-flags=\"--jitless --foo\"  --auth=opaque\t--tail");
    assert(madeira_htmlipc_steam_tags(old,n,32));assert(!madeira_htmlipc_steam_tags(old,n,33));
    end=madeira_htmlipc_argv0_end(old,n);
    assert(madeira_htmlipc_replace_argv0(old,n,helper,hn,out,32768,&written));
    assert(written==hn+2+n-end&&out[0]=='"'&&out[hn+1]=='"');
    assert(!memcmp(out+1,helper,hn*2));assert(!memcmp(out+hn+2,old+end,(n-end+1)*2));
    assert(!madeira_htmlipc_replace_argv0(old,n,helper,hn,out,written,&written));
    assert(!madeira_htmlipc_replace_argv0(old,n,helper,32763,out,32768,&written));
    assert(!madeira_htmlipc_replace_argv0(old,n,helper,hn,out,32768,NULL));
    n=wide(old,"steamwebhelper.exe -steampid=32 -buildid=123");assert(madeira_htmlipc_steam_tags(old,n,32));
    assert(madeira_htmlipc_replace_argv0(old,n,helper,hn,out,32768,&written));
    n=wide(old,"steamwebhelper.exe --foo=\" -steampid=32 -buildid=123 a\"--bar");assert(!madeira_htmlipc_steam_tags(old,n,32));
    n=wide(old,"steamwebhelper.exe \"-steampid=32\" \"-buildid=123\" --foo=\" -steampid=55\"");assert(madeira_htmlipc_steam_tags(old,n,32));
    n=wide(old,"steamwebhelper.exe -steampid=32 -buildid=123 -steampid=32");assert(!madeira_htmlipc_steam_tags(old,n,32));
    n=wide(old,"steamwebhelper.exe -steampid=4294967296 -buildid=123");assert(!madeira_htmlipc_steam_tags(old,n,32));
    n=wide(old,"steamwebhelper.exe -steampid=32 \"-buildid=123\\\"");assert(!madeira_htmlipc_steam_tags(old,n,32));
    n=wide(old,"\"steamwebhelper.exe -steampid=32 -buildid=123");assert(!madeira_htmlipc_argv0_end(old,n));
    n=wide(old,"C:\\x\\SteamWebHelper.exe");assert(madeira_htmlipc_basename(old,n,"steamwebhelper.exe"));
    n=wide(old,"C:\\x\\notsteamwebhelper.exe");assert(!madeira_htmlipc_basename(old,n,"steamwebhelper.exe"));
    loads=0;assert(madeira_htmlipc_preload(&recursion,0,load_good,NULL)==0&&!loads);
    assert(madeira_htmlipc_preload(&recursion,1,load_good,NULL)==1&&loads==1);
    assert(madeira_htmlipc_preload(&recursion,1,load_good,NULL)==1&&loads==1);
    recursion.state=0;assert(madeira_htmlipc_preload(&recursion,1,load_bad,NULL)==-1&&loads==2);
    assert(madeira_htmlipc_preload(&recursion,1,load_good,NULL)==-1&&loads==2);
    puts("policy: ready/failed/stale PID+lease, exact paths, Windows argv/tail, preload recursion+failure passed");
    return 0;
}
