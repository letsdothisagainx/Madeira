/* SPDX-License-Identifier: MIT */
#include "fixture_args.h"
#if !defined(MADEIRA_CEF_ARGS_EMBEDDED)
extern "C" void *memcpy(void *to,const void *from,madeira_cef_fixture::Size n){
    auto *d=static_cast<unsigned char*>(to);auto *s=static_cast<const unsigned char*>(from);
    for(madeira_cef_fixture::Size i=0;i<n;++i)d[i]=s[i];return to;
}
extern "C" void *memset(void *to,int c,madeira_cef_fixture::Size n){
    auto *d=static_cast<unsigned char*>(to);for(madeira_cef_fixture::Size i=0;i<n;++i)d[i]=c;return to;
}
#endif
extern "C" int strcmp(const char *a,const char *b){while(*a&&*a==*b){++a;++b;}return (unsigned char)*a-(unsigned char)*b;}
extern "C" int strncmp(const char *a,const char *b,madeira_cef_fixture::Size n){
    while(n&&*a&&*a==*b){++a;++b;--n;}return n?(unsigned char)*a-(unsigned char)*b:0;
}
