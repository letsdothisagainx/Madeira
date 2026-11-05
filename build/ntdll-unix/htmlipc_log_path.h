/* SPDX-License-Identifier: MIT. Mutable CEF output, never the verified cache. */
#ifndef MADEIRA_HTMLIPC_LOG_PATH_H
#define MADEIRA_HTMLIPC_LOG_PATH_H
#include <stdlib.h>
#include "../scm-rpc/htmlipc_policy.h"

enum madeira_htmlipc_log_route { MADEIRA_HTMLIPC_LOG_ERROR, MADEIRA_HTMLIPC_LOG_EXPLICIT,
    MADEIRA_HTMLIPC_LOG_STEAM, MADEIRA_HTMLIPC_LOG_STDERR };

/* Decode one Windows argument without modifying the original command line. */
static inline int madeira_htmlipc_log_arg(const uint16_t *s,size_t n,size_t *at,
                                          uint16_t *out,size_t *used)
{
    size_t i=*at,o=0;int quote=0;
    while(i<n&&(s[i]==' '||s[i]=='\t'))i++;
    while(i<n&&(quote||(s[i]!=' '&&s[i]!='\t'))){
        size_t slashes=0,j;
        if(!s[i])return 0;
        if(s[i]=='\\'){
            while(i<n&&s[i]=='\\'){slashes++;i++;}
            if(i<n&&s[i]=='"'){
                for(j=0;j<slashes/2;j++)out[o++]='\\';
                if(slashes&1){out[o++]='"';i++;continue;}
            }else{for(j=0;j<slashes;j++)out[o++]='\\';continue;}
        }
        if(s[i]=='"'){
            if(quote&&i+1<n&&s[i+1]=='"'){out[o++]='"';i+=2;}
            else{quote=!quote;i++;}
        }else out[o++]=s[i++];
    }
    if(quote)return 0;
    *at=i;*used=o;return 1;
}
static inline int madeira_htmlipc_log_key(const uint16_t *s,size_t n,const char *key)
{
    size_t i;for(i=0;key[i];i++)if(i>=n||madeira_htmlipc_lower(s[i])!=(uint16_t)key[i])return 0;
    return i==n||s[i]=='=';
}
/* The verified Steam parent's canonical DOS image path determines the ONLY
 * accepted -logdir. Never trust an arbitrary child argument as a destination. */
static inline int madeira_htmlipc_log_parent(const uint16_t *s,size_t n,size_t *root)
{
    static const char immutable[]="c:\\windows\\madeira-compat\\";
    size_t i,start=3;
    if(!s||n<13||!((s[0]>='A'&&s[0]<='Z')||(s[0]>='a'&&s[0]<='z'))||s[1]!=':'||s[2]!='\\'||
       !madeira_htmlipc_basename(s,n,"steam.exe"))return 0;
    for(i=0;i<sizeof(immutable)-1&&i<n&&madeira_htmlipc_lower(s[i])==(uint16_t)immutable[i];i++);
    if(i==sizeof(immutable)-1)return 0;
    for(i=3;i<=n;i++){
        if(i<n&&(s[i]<32||s[i]=='/'||s[i]=='"'||s[i]==':'||s[i]=='%'||s[i]=='?'||s[i]=='*'||
           s[i]=='<'||s[i]=='>'||s[i]=='|'))return 0;
        if(i==n||s[i]=='\\'){
            if(i==start||s[i-1]=='.'||s[i-1]==' ')return 0;
            start=i+1;
        }
    }
    *root=n-9;return *root>3;
}
/* Preserve explicit CEF paths. Otherwise add a normal --log-file only when
 * Valve's -logdir matches Steam's own logs directory. Unsupported/missing
 * logdir uses stderr, so default debug.log cannot dirty immutable runtime data.
 * No file is created, truncated, moved or deleted by this command-line helper. */
static inline enum madeira_htmlipc_log_route madeira_htmlipc_route_log(
    uint16_t *command,size_t n,size_t capacity,const uint16_t *steam,size_t sn,size_t *written)
{
    static const char suffix[]="logs\\madeira-cef-debug.log";
    static const char file_switch[]=" --log-file=\"";
    static const char stderr_switch[]=" --enable-logging=stderr";
    uint16_t *token;size_t at=madeira_htmlipc_argv0_end(command,n),used,root=0,insert=n,add,o,i;
    unsigned logdirs=0;int trusted=madeira_htmlipc_log_parent(steam,sn,&root),valid=0;
    enum madeira_htmlipc_log_route route=MADEIRA_HTMLIPC_LOG_STDERR;
    if(!at||!written||n>=capacity||n>32764||!(token=malloc((n+1)*sizeof(*token))))return MADEIRA_HTMLIPC_LOG_ERROR;
    while(at<n){
        size_t begin=at,value=0;
        while(begin<n&&(command[begin]==' '||command[begin]=='\t'))begin++;
        if(!madeira_htmlipc_log_arg(command,n,&at,token,&used)){free(token);return MADEIRA_HTMLIPC_LOG_ERROR;}
        if(used==2&&token[0]=='-'&&token[1]=='-'){insert=begin;break;}
        if(madeira_htmlipc_log_key(token,used,"--log-file")){free(token);*written=n;return MADEIRA_HTMLIPC_LOG_EXPLICIT;}
        if(!madeira_htmlipc_log_key(token,used,"-logdir"))continue;
        logdirs++;value=7;
        if(used==7){
            if(at==n||!madeira_htmlipc_log_arg(command,n,&at,token,&used)){free(token);return MADEIRA_HTMLIPC_LOG_ERROR;}
            value=0;
        }else value=8;
        valid=trusted&&used-value==root+4;
        for(i=0;valid&&i<root;i++)if(madeira_htmlipc_lower(token[value+i])!=madeira_htmlipc_lower(steam[i]))valid=0;
        for(i=0;valid&&i<4;i++)if(madeira_htmlipc_lower(token[value+root+i])!=(uint16_t)"logs"[i])valid=0;
    }
    free(token);
    if(logdirs==1&&valid){route=MADEIRA_HTMLIPC_LOG_STEAM;add=sizeof(file_switch)-1+root+sizeof(suffix)-1+1;}
    else add=sizeof(stderr_switch)-1;
    if(insert<n)add++; /* Separate the original -- terminator after insertion. */
    if(add>32764-n||n+add>=capacity)return MADEIRA_HTMLIPC_LOG_ERROR;
    memmove(command+insert+add,command+insert,(n-insert)*sizeof(*command));o=insert;
    if(route==MADEIRA_HTMLIPC_LOG_STEAM){
        for(i=0;i<sizeof(file_switch)-1;i++)command[o++]=(unsigned char)file_switch[i];
        memcpy(command+o,steam,root*sizeof(*command));o+=root;
        for(i=0;i<sizeof(suffix)-1;i++)command[o++]=(unsigned char)suffix[i];
        command[o++]='"';
    }else for(i=0;i<sizeof(stderr_switch)-1;i++)command[o++]=(unsigned char)stderr_switch[i];
    if(insert<n)command[o++]=' ';
    command[n+add]=0;*written=n+add;return route;
}
#endif
