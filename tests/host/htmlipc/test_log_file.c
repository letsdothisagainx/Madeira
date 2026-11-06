/* SPDX-License-Identifier: MIT. Exact owned-helper file policy and real I/O. */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include "htmlipc_log_file.h"
static const char cache[]="C:\\windows\\madeira-compat\\SteamBrowserRuntime\\fixture-log-v1\\bin\\cef\\cef.win7";
static const char helper[]="C:\\windows\\madeira-compat\\SteamBrowserRuntime\\fixture-log-v1\\bin\\cef\\cef.win7\\steamwebhelper.exe";
static const char requested[]="\\??\\C:\\windows\\madeira-compat\\SteamBrowserRuntime\\fixture-log-v1\\bin\\cef\\cef.win7\\debug.log";
static const char target[]="\\??\\C:\\windows\\madeira-compat\\SteamBrowserLogs\\debug.log";
static size_t wide(uint16_t *out,size_t cap,const char *s)
{size_t n=strlen(s);assert(n<cap);for(size_t i=0;i<=n;i++)out[i]=(unsigned char)s[i];return n;}
static int route(const char *req,const char *image,const char *selected,const char *directory,size_t capacity)
{
    uint16_t r[1024],i[1024],out[128];size_t rn=wide(r,1024,req),in=wide(i,1024,image),n=0;
    memset(out,0xa5,sizeof(out));
    int result=madeira_htmlipc_default_log(r,rn,i,in,selected,directory,out,capacity,&n);
    if(result){assert(n==strlen(target));for(size_t j=0;j<=n;j++)assert(out[j]==(unsigned char)target[j]);}
    else for(size_t j=0;j<128;j++)assert(out[j]==0xa5a5);
    return result;
}
int main(int argc,char **argv)
{
    if(argc==5&&!strcmp(argv[1],"write")){
        if(!route(argv[2],argv[3],argv[3],argv[4],128))return 2;
        const char *path=getenv("MADEIRA_TEST_HOST_LOG");
        if(!path||!madeira_htmlipc_mutable_log_owned(path))return 3;
        int fd=open(path,O_WRONLY|O_APPEND|O_CREAT|O_NOFOLLOW,0600);
        if(fd<0)return 4;
        const char message[]="helper executable log fixture\n";
        int ok=write(fd,message,sizeof(message)-1)==sizeof(message)-1;close(fd);return ok?0:5;
    }
    assert(argc==1);
    assert(route(requested,helper,helper,cache,128));
    assert(route(requested,"\\??\\C:\\windows\\madeira-compat\\SteamBrowserRuntime\\fixture-log-v1\\bin\\cef\\cef.win7\\steamwebhelper.exe",helper,cache,128));
    assert(!route(requested,"C:\\Steam\\steamwebhelper.exe",helper,cache,128));
    assert(!route(requested,helper,"C:\\other\\steamwebhelper.exe",cache,128));
    assert(!route(requested,helper,helper,"C:\\other",128));
    assert(!route("\\??\\C:\\Steam\\debug.log",helper,helper,cache,128));
    assert(!route("debug.log",helper,helper,cache,128));
    assert(!route(requested,helper,helper,cache,8));
    uint16_t r[1024];size_t n=wide(r,1024,requested);
    assert(madeira_htmlipc_default_log_candidate(r,n,cache));
    assert(!madeira_htmlipc_default_log_candidate(r,n,NULL));
    assert(!madeira_htmlipc_default_log_candidate(r,n,"C:\\elsewhere"));
    char directory[]="/tmp/madeira-log-policy-XXXXXX";assert(mkdtemp(directory));
    char path[1024],marker[1024],other[1024];
    assert(snprintf(path,sizeof(path),"%s/debug.log",directory)>0);
    assert(snprintf(marker,sizeof(marker),"%s/%s",directory,MADEIRA_HTMLIPC_LOG_OWNER)>0);
    assert(snprintf(other,sizeof(other),"%s/other",directory)>0);
    assert(!madeira_htmlipc_mutable_log_owned(path));
    int fd=open(marker,O_WRONLY|O_CREAT|O_EXCL,0600);assert(fd>=0);
    assert(write(fd,MADEIRA_HTMLIPC_LOG_OWNER_BYTES,sizeof(MADEIRA_HTMLIPC_LOG_OWNER_BYTES)-1)==sizeof(MADEIRA_HTMLIPC_LOG_OWNER_BYTES)-1);close(fd);
    assert(madeira_htmlipc_mutable_log_owned(path));
    assert(symlink(marker,path)==0);assert(!madeira_htmlipc_mutable_log_owned(path));assert(!unlink(path));
    fd=open(path,O_WRONLY|O_CREAT|O_EXCL,0600);assert(fd>=0);close(fd);
    assert(madeira_htmlipc_mutable_log_owned(path));
    assert(!link(path,other));assert(!madeira_htmlipc_mutable_log_owned(path));assert(!unlink(other));
    assert(madeira_htmlipc_mutable_log_owned(path));
    assert(!link(marker,other));assert(!madeira_htmlipc_mutable_log_owned(path));assert(!unlink(other));
    assert(!unlink(path));assert(!unlink(marker));assert(!rmdir(directory));
    puts("PASS exact cached-helper default logger routing, owner marker, missing/unowned/link rejection and bounded output");
}
