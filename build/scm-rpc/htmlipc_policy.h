/* SPDX-License-Identifier: MIT. Exact Steam-only HTMLIPC selection policy. */
#ifndef MADEIRA_HTMLIPC_POLICY_H
#define MADEIRA_HTMLIPC_POLICY_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "htmlipc_ready_abi.h"

static inline uint16_t madeira_htmlipc_lower(uint16_t c)
{ return c >= 'A' && c <= 'Z' ? c + ('a'-'A') : c; }
static inline int madeira_htmlipc_basename(const uint16_t *path,size_t n,const char *name)
{
    size_t i=0,start=0;
    if(!path||!n)return 0;
    for(i=0;i<n;i++){if(!path[i])return 0;if(path[i]=='\\'||path[i]=='/')start=i+1;}
    for(i=0;name[i];i++)if(start+i>=n||madeira_htmlipc_lower(path[start+i])!=(uint16_t)name[i])return 0;
    return start+i==n;
}
/* First-token parsing is deliberately bounded and rejects malformed quoting.
 * argv[0] in Windows process command lines treats quotes as grouping; backslash
 * is a literal path separator. Tail starts at the original whitespace byte. */
static inline size_t madeira_htmlipc_argv0_end(const uint16_t *s,size_t n)
{
    size_t i=0;int quoted=0;
    if(!s||!n||s[0]==' '||s[0]=='\t')return 0;
    for(;i<n;i++){
        if(!s[i])return 0;
        if(s[i]=='"'){quoted=!quoted;continue;}
        if(!quoted&&(s[i]==' '||s[i]=='\t'))break;
    }
    return quoted?0:i;
}
/* full C:\\ path, no UNC/device/traversal/quote/control characters. Prefix is
 * host selected; a validated cache directory and filename bind the target. */
static inline int madeira_htmlipc_cache_target(const uint16_t *helper,size_t hn,
                                               const uint16_t *cache,size_t cn)
{
    static const char prefix[]="C:\\windows\\madeira-compat\\SteamBrowserRuntime\\";
    size_t i;
    if(!helper||!cache||cn<=sizeof(prefix)-1||hn<=cn+1||hn>32764||cn>32764||
       madeira_htmlipc_lower(cache[0])!='c'||cache[1]!=':'||cache[2]!='\\'||
       cache[cn-1]=='\\'||cache[cn-1]=='/')return 0;
    for(i=0;i<sizeof(prefix)-1;i++)
        if(madeira_htmlipc_lower(cache[i])!=madeira_htmlipc_lower((uint16_t)(unsigned char)prefix[i]))return 0;
    for(i=0;i<hn;i++){
        uint16_t c=helper[i];
        if(c<32||c=='"'||c=='/'||c=='%'||c=='?'||c=='*'||c=='<'||c=='>'||c=='|'||(i>1&&c==':'))return 0;
        if((c=='.'||c==' ')&&(i+1==hn||helper[i+1]=='\\'))return 0;
        if(c=='.'&&(i==0||helper[i-1]=='\\')&&
           (i+1==hn||helper[i+1]=='\\'||(helper[i+1]=='.'&&(i+2==hn||helper[i+2]=='\\'))))return 0;
    }
    for(i=0;i<cn;i++)if(madeira_htmlipc_lower(helper[i])!=madeira_htmlipc_lower(cache[i]))return 0;
    return helper[cn]=='\\'&&madeira_htmlipc_basename(helper+cn+1,hn-cn-1,"steamwebhelper.exe")&&
           hn-cn-1==18;
}
static inline int madeira_htmlipc_replace_argv0(const uint16_t *old,size_t n,
    const uint16_t *helper,size_t hn,uint16_t *out,size_t capacity,size_t *written)
{
    size_t end=madeira_htmlipc_argv0_end(old,n),need,i;
    if(!end||!helper||!hn||hn>32762||!written||end>n||n-end>32764-hn-2)return 0;
    need=hn+2+n-end;
    if(!out||capacity<=need)return 0;
    out[0]='"';for(i=0;i<hn;i++){if(helper[i]=='"'||!helper[i])return 0;out[i+1]=helper[i];}
    out[hn+1]='"';memcpy(out+hn+2,old+end,(n-end)*sizeof(*out));out[need]=0;
    *written=need;return 1;
}
/* Decode Windows argument grouping so switches inside another quoted value
 * cannot authorize a browser. Unknown arguments, including mixed quoting and
 * JS flags, remain untouched in the command line. */
static inline int madeira_htmlipc_steam_tags(const uint16_t *s,size_t n,uint32_t pid)
{
    size_t i=madeira_htmlipc_argv0_end(s,n);unsigned found=0;
    if(!i||!pid)return 0;
    while(i<n){
        uint16_t token[64];size_t used=0,j;int quote=0,overflow=0;uint64_t v=0;
        const char *key=NULL;unsigned bit=0;
        while(i<n&&(s[i]==' '||s[i]=='\t'))i++;
        if(i==n)break;
        while(i<n&&(quote||(s[i]!=' '&&s[i]!='\t'))){
            size_t slashes=0;uint16_t c=s[i];
            if(!c)return 0;
            if(c=='\\'){
                while(i<n&&s[i]=='\\'){slashes++;i++;}
                if(i<n&&s[i]=='"'){
                    for(j=0;j<slashes/2;j++){if(used<64)token[used++]= '\\';else overflow=1;}
                    if(slashes&1){if(used<64)token[used++]='"';else overflow=1;i++;continue;}
                }else{
                    for(j=0;j<slashes;j++){if(used<64)token[used++]='\\';else overflow=1;}
                    continue;
                }
                c=s[i];
            }
            if(c=='"'){
                if(quote&&i+1<n&&s[i+1]=='"'){if(used<64)token[used++]='"';else overflow=1;i+=2;}
                else{quote=!quote;i++;}
            }else{if(used<64)token[used++]=c;else overflow=1;i++;}
        }
        if(quote)return 0;
        if(overflow)continue;
        {
            const char *keys[]={"-steampid=","-buildid="};
            for(unsigned k=0;k<2;k++){
                for(j=0;keys[k][j]&&j<used&&token[j]==(uint16_t)keys[k][j];j++);
                if(!keys[k][j]){key=keys[k];bit=1u<<k;break;}
            }
        }
        if(!key)continue;
        if(found&bit)return 0;
        for(j=0;key[j];j++);
        if(j==used)return 0;
        for(;j<used;j++){
            if(token[j]<'0'||token[j]>'9'||v>(UINT32_MAX-(token[j]-'0'))/10)return 0;
            v=v*10+(token[j]-'0');
        }
        if(!v||(bit==1&&v!=pid))return 0;
        found|=bit;
    }
    return found==3;
}
static inline int madeira_htmlipc_ready_valid(const struct madeira_htmlipc_ready *a,
    const struct madeira_htmlipc_ready *b,uint64_t owner,uint64_t lease,uint32_t pid,
    uint64_t module)
{
    return a&&b&&owner&&lease&&pid&&module&&
        a->magic==MADEIRA_HTMLIPC_READY_MAGIC&&a->size==sizeof(*a)&&
        a->version==MADEIRA_HTMLIPC_READY_VERSION&&a->sequence&&!(a->sequence&1)&&
        !memcmp(a,b,sizeof(*a))&&a->flags==MADEIRA_HTMLIPC_READY_FLAGS&&
        a->pid==pid&&!a->provider_error&&!a->installer_error&&!a->reserved&&
        a->owner_peb==owner&&a->owner_lease==lease&&a->self_module==module&&
        a->installed_module&&a->generation;
}
/* No success/failure cache is shared between PEBs; Wine's private ntdll .data
 * owns this guard. Recursive chromehtml loading during bridge attach is refused.
 * Other recursive dependencies pass through the normal loader unchanged. */
struct madeira_htmlipc_preload_state { unsigned state; };
static inline int madeira_htmlipc_preload(struct madeira_htmlipc_preload_state *state,
                                         int selected,int (*load)(void *),void *context)
{
    int ok;
    if(!selected)return 0;
    if(state->state==2)return 1;
    if(state->state==1||state->state==3)return -1;
    state->state=1;ok=load(context);state->state=ok?2:3;
    return ok?1:-1;
}
#endif
