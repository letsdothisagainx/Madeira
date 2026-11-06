/* SPDX-License-Identifier: MIT. The helper executable's private base logger
 * ignores CEF --log-file and defaults beside GetModuleFileNameW(NULL).
 * Only that exact file of the host-selected cached helper is redirected.
 */
#ifndef MADEIRA_HTMLIPC_LOG_FILE_H
#define MADEIRA_HTMLIPC_LOG_FILE_H
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include "../scm-rpc/htmlipc_policy.h"
#define MADEIRA_HTMLIPC_LOG_OWNER ".madeira-browser-logs-owner-v1"
#define MADEIRA_HTMLIPC_LOG_OWNER_BYTES "org.madeira.SteamBrowserLogs/v1\n"
static inline int madeira_htmlipc_log_ascii_equal(const uint16_t *wide,size_t n,const char *ascii)
{
    size_t i;if(!wide||!ascii||strlen(ascii)!=n)return 0;
    for(i=0;i<n;i++)if((unsigned char)ascii[i]<32||(unsigned char)ascii[i]>126||
        madeira_htmlipc_lower(wide[i])!=madeira_htmlipc_lower((unsigned char)ascii[i]))return 0;
    return 1;
}
/* Cheap pathname prefilter before inspecting native process state. */
static inline int madeira_htmlipc_default_log_candidate(const uint16_t *requested,size_t rn,const char *cache)
{
    static const char nt[]="\\??\\",name[]="\\debug.log";size_t n,i;
    if(!requested||!cache||(n=strlen(cache))>32764||!n||rn!=4+n+sizeof(name)-1)return 0;
    for(i=0;i<4;i++)if(requested[i]!=(unsigned char)nt[i])return 0;
    for(i=0;i<n;i++)if(madeira_htmlipc_lower(requested[i+4])!=madeira_htmlipc_lower((unsigned char)cache[i]))return 0;
    for(i=0;i<sizeof(name)-1;i++)if(madeira_htmlipc_lower(requested[i+4+n])!=(unsigned char)name[i])return 0;
    return 1;
}
/* No guest argument or arbitrary path selects the destination. envHelper and
 * envCache are the launch worker's locked, verified pair; the actual current
 * image must match them. Relative/rooted/reparse/directory opens stay normal.
 */
static inline int madeira_htmlipc_default_log(const uint16_t *requested,size_t rn,
    const uint16_t *image,size_t in,const char *envHelper,const char *envCache,
    uint16_t *out,size_t capacity,size_t *written)
{
    static const char nt[]="\\??\\";
    static const char name[]="\\debug.log";
    static const char target[]="\\??\\C:\\windows\\madeira-compat\\SteamBrowserLogs\\debug.log";
    size_t cn,i;
    if(!requested||!image||!written||in<19||in>32764)return 0;
    if(in>=4&&image[0]=='\\'&&image[1]=='?'&&image[2]=='?'&&image[3]=='\\'){image+=4;in-=4;}
    if(in<19)return 0;
    cn=in-19;
    if(!madeira_htmlipc_log_ascii_equal(image,in,envHelper)||
       !madeira_htmlipc_log_ascii_equal(image,cn,envCache)||
       !madeira_htmlipc_cache_target(image,in,image,cn)||rn!=4+cn+sizeof(name)-1)return 0;
    for(i=0;i<4;i++)if(requested[i]!=(unsigned char)nt[i])return 0;
    for(i=0;i<cn;i++)if(madeira_htmlipc_lower(requested[i+4])!=madeira_htmlipc_lower(image[i]))return 0;
    for(i=0;i<sizeof(name)-1;i++)if(madeira_htmlipc_lower(requested[4+cn+i])!=(unsigned char)name[i])return 0;
    if(!out||capacity<sizeof(target))return 0;
    for(i=0;i<sizeof(target);i++)out[i]=(unsigned char)target[i];
    *written=sizeof(target)-1;return 1;
}
/* The private mutable namespace is introduced by Swift with an exact owner
 * record. Failure never falls back to opening the immutable requested path.
 * Symlink roots, markers and log files and hard-linked files are not adopted.
 */
static inline int madeira_htmlipc_mutable_log_owned(const char *path)
{
    static const char owner[]=MADEIRA_HTMLIPC_LOG_OWNER_BYTES;
    const char *slash;char *directory,bytes[sizeof(owner)];struct stat st;
    size_t n,done=0;int dir=-1,marker=-1,result=0,saved=errno;
    if(!path||!(slash=strrchr(path,'/'))||strcmp(slash+1,"debug.log"))return 0;
    n=(size_t)(slash-path);if(!n||!(directory=malloc(n+1)))return 0;
    memcpy(directory,path,n);directory[n]=0;
    dir=open(directory,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);free(directory);
    if(dir<0)goto out;
    marker=openat(dir,MADEIRA_HTMLIPC_LOG_OWNER,O_RDONLY|O_NOFOLLOW);
    if(marker<0||fstat(marker,&st)||!S_ISREG(st.st_mode)||st.st_nlink!=1||st.st_size!=(off_t)(sizeof(owner)-1))goto out;
    while(done<sizeof(owner)-1){ssize_t got=read(marker,bytes+done,sizeof(owner)-1-done);if(got<0&&errno==EINTR)continue;if(got<=0)goto out;done+=(size_t)got;}
    if(memcmp(bytes,owner,sizeof(owner)-1))goto out;
    if(fstatat(dir,"debug.log",&st,AT_SYMLINK_NOFOLLOW)){
        if(errno!=ENOENT)goto out;
    }else if(!S_ISREG(st.st_mode)||st.st_nlink!=1)goto out;
    result=1;
out:
    if(marker>=0)close(marker);if(dir>=0)close(dir);errno=saved;return result;
}
#endif
