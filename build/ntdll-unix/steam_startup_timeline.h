/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Bounded observational timing of real Steam/CS2 process creation and exit.
 * Durations are monotonic wall intervals: nested/parallel intervals overlap,
 * and neither a successful CreateProcess nor an exit request proves that an
 * installer succeeded, every callback quiesced, or a game became interactive.
 * Never emit command lines, filenames, paths, account data or guest log bodies.
 */
#ifndef MADEIRA_STEAM_STARTUP_TIMELINE_H
#define MADEIRA_STEAM_STARTUP_TIMELINE_H
#include <stdint.h>
#include <stddef.h>
void ios_startup_timeline_begin(void);
uint32_t ios_startup_process_request(const uint16_t *,size_t,const uint16_t *,size_t,uint32_t);
void ios_startup_process_created(uint32_t,uint32_t);
void ios_startup_process_returned(uint32_t,uint32_t,int);
void ios_startup_process_bind(uint32_t,void *);
void ios_startup_process_pe_entry(uint32_t,void *);
void ios_startup_process_exit_request(uint32_t,void *,uint32_t,int);
void ios_startup_process_quiesced(void *);

#ifdef MADEIRA_STEAM_STARTUP_TIMELINE_IMPLEMENTATION
#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <inttypes.h>

enum { IOS_STARTUP_RECORD_LIMIT=128, IOS_STARTUP_EVENT_LIMIT=640 };
struct ios_startup_process {
    uint64_t requested,created;
    void *owner;
    uint32_t token,creator,pid,status;
    const char *phase;
    unsigned returned,exit_requested,closed,pe_entry;
};
static struct ios_startup_process ios_startup_processes[IOS_STARTUP_RECORD_LIMIT];
static pthread_mutex_t ios_startup_mutex=PTHREAD_MUTEX_INITIALIZER;
static uint64_t ios_startup_origin;
static unsigned ios_startup_started,ios_startup_count,ios_startup_events;

#ifndef MADEIRA_STARTUP_NOW_NS
static uint64_t ios_startup_now_ns(void)
{
    struct timespec now;
    if(clock_gettime(CLOCK_MONOTONIC,&now)||now.tv_sec<0||now.tv_nsec<0||
       now.tv_nsec>=1000000000L||(uint64_t)now.tv_sec>UINT64_MAX/1000000000ULL)return 0;
    if((uint64_t)now.tv_nsec>UINT64_MAX-(uint64_t)now.tv_sec*1000000000ULL)return 0;
    return (uint64_t)now.tv_sec*1000000000ULL+(uint64_t)now.tv_nsec;
}
#define MADEIRA_STARTUP_NOW_NS() ios_startup_now_ns()
#endif

static unsigned ios_startup_fold(unsigned c)
{ return c>='A'&&c<='Z'?c+('a'-'A'):c; }
static int ios_startup_word(const uint16_t *text,size_t length,const char *word)
{
    size_t n=strlen(word),i,j;
    if(!text||length>32767||n>length)return 0;
    for(i=0;i+n<=length;i++)
    {
        if(i&&text[i-1]!=' '&&text[i-1]!='\t'&&text[i-1]!='"'&&
           text[i-1]!='/'&&text[i-1]!='\\')continue;
        for(j=0;j<n&&ios_startup_fold(text[i+j])==ios_startup_fold((unsigned char)word[j]);j++);
        if(j==n&&(i+n==length||text[i+n]==' '||text[i+n]=='\t'||text[i+n]=='"'))return 1;
    }
    return 0;
}
static int ios_startup_image(const uint16_t *image,size_t length,const char *name)
{
    size_t start=0,n=strlen(name),i;
    if(!image||!length||length>32767)return 0;
    for(i=0;i<length;i++)if(image[i]=='/'||image[i]=='\\')start=i+1;
    if(length-start!=n)return 0;
    for(i=0;i<n;i++)if(ios_startup_fold(image[start+i])!=ios_startup_fold((unsigned char)name[i]))return 0;
    return 1;
}
static const char *ios_startup_phase(const uint16_t *image,size_t length,const uint16_t *cmd,size_t cmd_length)
{
    if(ios_startup_image(image,length,"steam.exe"))return "steam-client";
    if(ios_startup_image(image,length,"steamwebhelper.exe"))return "chromium";
    if(ios_startup_image(image,length,"madeira-steam-service.exe"))return "service-launcher";
    if(ios_startup_image(image,length,"SteamService.exe"))
        return ios_startup_word(cmd,cmd_length,"/installscript")?"installscript":"steam-service";
    if(ios_startup_image(image,length,"VC_redist.x86.exe"))return "vcredist-x86";
    if(ios_startup_image(image,length,"VC_redist.x64.exe"))return "vcredist-x64";
    if(ios_startup_image(image,length,"msiexec.exe"))return "msi";
    if(ios_startup_image(image,length,"DXSETUP.exe"))return "directx-setup";
    if(ios_startup_image(image,length,"infinst.exe"))return "directx-plugin";
    if(ios_startup_image(image,length,"cs2.exe"))return "cs2";
    if(ios_startup_image(image,length,"cmd.exe"))
    {
        if(ios_startup_word(cmd,cmd_length,"Microsoft Visual C++ 2019 x86.cmd"))return "vcredist-x86-script";
        if(ios_startup_word(cmd,cmd_length,"Microsoft Visual C++ 2019 x64.cmd"))return "vcredist-x64-script";
    }
    return NULL;
}
/* Optional app preflight origin. It is the same CLOCK_MONOTONIC domain, not
 * a guest clock or wall timestamp. Bad/stale input only loses cross-layer
 * timing: it never gates Wine or changes a process result. */
static uint64_t ios_startup_app_origin(const char *text,uint64_t now)
{
    uint64_t value=0;unsigned digits=0;
    if(!text||!*text)return 0;
    for(;*text;text++)
    {
        unsigned digit=(unsigned char)*text-'0';
        if(digit>9||++digits>20||value>(UINT64_MAX-digit)/10)return 0;
        value=value*10+digit;
    }
    if(!value||value>now||now-value>86400000000000ULL)return 0;
    return value;
}
static void ios_startup_epoch_locked(uint64_t now,const char *source)
{
    if(!ios_startup_started)
    {
        uint64_t app=ios_startup_app_origin(getenv("MADEIRA_STARTUP_T0_NS"),now);
        ios_startup_started=1;ios_startup_origin=app?app:now;
        ++ios_startup_events;
        dprintf(2,"[startup-timeline-v1] event=origin source=%s clock=monotonic t-ms=%" PRIu64 " intervals=overlap-allowed cpu-time=unmeasured\n",
                app?"app-launch":source,(uint64_t)((now-ios_startup_origin)/1000000ULL));
    }
}
static void ios_startup_emit_locked(const struct ios_startup_process *p,const char *event,
                                    uint64_t now,uint64_t duration,uint32_t status,int ready)
{
    if(ios_startup_events>=IOS_STARTUP_EVENT_LIMIT||now<ios_startup_origin)return;
    ++ios_startup_events;
    dprintf(2,"[startup-timeline-v1] event=%s phase=%s attempt=%u creator=%04x pid=%04x "
            "t-ms=%" PRIu64 " duration-ms=%" PRIu64 " status=%08x create-ok=%u intervals=overlap-allowed\n",
            event,p->phase,p->token,p->creator,p->pid,(uint64_t)((now-ios_startup_origin)/1000000ULL),
            (uint64_t)(duration/1000000ULL),status,(unsigned)!!ready);
}
static struct ios_startup_process *ios_startup_token_locked(uint32_t token)
{
    if(!token||token>ios_startup_count)return NULL;
    return &ios_startup_processes[token-1];
}
static struct ios_startup_process *ios_startup_owner_locked(uint32_t pid,void *owner)
{
    unsigned i=ios_startup_count;
    while(i--)
    {
        struct ios_startup_process *p=&ios_startup_processes[i];
        if(!p->closed&&p->owner==owner&&p->pid==pid)return p;
    }
    return NULL;
}
void ios_startup_timeline_begin(void)
{
    int saved=errno;uint64_t now=MADEIRA_STARTUP_NOW_NS();
    if(now){pthread_mutex_lock(&ios_startup_mutex);ios_startup_epoch_locked(now,"wine-entry");pthread_mutex_unlock(&ios_startup_mutex);}
    errno=saved;
}
uint32_t ios_startup_process_request(const uint16_t *image,size_t length,const uint16_t *cmd,size_t cmd_length,uint32_t creator)
{
    int saved=errno;uint32_t token=0;uint64_t now=MADEIRA_STARTUP_NOW_NS();
    const char *phase=ios_startup_phase(image,length,cmd,cmd_length);
    if(now&&phase)
    {
        pthread_mutex_lock(&ios_startup_mutex);
        ios_startup_epoch_locked(now,"first-observed-create");
        if(ios_startup_count<IOS_STARTUP_RECORD_LIMIT&&now>=ios_startup_origin)
        {
            struct ios_startup_process *p=&ios_startup_processes[ios_startup_count++];
            *p=(struct ios_startup_process){.requested=now,.creator=creator,.phase=phase,.token=ios_startup_count};
            token=p->token;ios_startup_emit_locked(p,"create-request",now,0,0,0);
        }
        pthread_mutex_unlock(&ios_startup_mutex);
    }
    errno=saved;return token;
}
void ios_startup_process_created(uint32_t token,uint32_t pid)
{
    int saved=errno;uint64_t now=MADEIRA_STARTUP_NOW_NS();
    if(now&&pid){pthread_mutex_lock(&ios_startup_mutex);
        struct ios_startup_process *p=ios_startup_token_locked(token);
        if(p&&!p->pid&&now>=p->requested){p->pid=pid;p->created=now;ios_startup_emit_locked(p,"server-created",now,now-p->requested,0,0);}
        pthread_mutex_unlock(&ios_startup_mutex);}
    errno=saved;
}
void ios_startup_process_returned(uint32_t token,uint32_t status,int ready)
{
    int saved=errno;uint64_t now=MADEIRA_STARTUP_NOW_NS();
    if(now){pthread_mutex_lock(&ios_startup_mutex);
        struct ios_startup_process *p=ios_startup_token_locked(token);
        if(p&&!p->returned&&now>=p->requested){p->returned=1;ios_startup_emit_locked(p,"create-return",now,now-p->requested,status,ready);}
        pthread_mutex_unlock(&ios_startup_mutex);}
    errno=saved;
}
void ios_startup_process_bind(uint32_t pid,void *owner)
{
    int saved=errno;uint64_t now=MADEIRA_STARTUP_NOW_NS();
    if(now&&pid&&owner){pthread_mutex_lock(&ios_startup_mutex);
        unsigned i=ios_startup_count;
        while(i--){struct ios_startup_process *p=&ios_startup_processes[i];
            if(p->pid==pid&&!p->owner&&!p->closed&&now>=p->requested){p->owner=owner;ios_startup_emit_locked(p,"native-entry",now,now-p->requested,0,0);break;}}
        pthread_mutex_unlock(&ios_startup_mutex);}
    errno=saved;
}
void ios_startup_process_pe_entry(uint32_t pid,void *owner)
{
    int saved=errno;uint64_t now=MADEIRA_STARTUP_NOW_NS();
    if(now&&owner){pthread_mutex_lock(&ios_startup_mutex);
        struct ios_startup_process *p=ios_startup_owner_locked(pid,owner);
        if(p&&!p->pe_entry&&now>=p->requested){p->pe_entry=1;
            ios_startup_emit_locked(p,"pe-start-dispatch",now,now-p->requested,0,0);}
        pthread_mutex_unlock(&ios_startup_mutex);}
    errno=saved;
}
void ios_startup_process_exit_request(uint32_t pid,void *owner,uint32_t status,int aborted)
{
    int saved=errno;uint64_t now=MADEIRA_STARTUP_NOW_NS();
    if(now&&owner){pthread_mutex_lock(&ios_startup_mutex);
        struct ios_startup_process *p=ios_startup_owner_locked(pid,owner);
        if(p&&!p->exit_requested&&now>=p->requested){p->exit_requested=1;p->status=status;
            ios_startup_emit_locked(p,aborted?"abort-request":"exit-request",now,now-p->requested,status,0);}
        pthread_mutex_unlock(&ios_startup_mutex);}
    errno=saved;
}
void ios_startup_process_quiesced(void *owner)
{
    int saved=errno;uint64_t now=MADEIRA_STARTUP_NOW_NS();
    if(now&&owner){pthread_mutex_lock(&ios_startup_mutex);
        unsigned i=ios_startup_count;
        while(i--){struct ios_startup_process *p=&ios_startup_processes[i];
            if(p->owner==owner&&!p->closed&&now>=p->requested){p->closed=1;
                ios_startup_emit_locked(p,p->exit_requested?"owner-quiesced":"owner-quiesced-status-unobserved",
                                        now,now-p->requested,p->status,0);break;}}
        pthread_mutex_unlock(&ios_startup_mutex);}
    errno=saved;
}
#endif
#endif
