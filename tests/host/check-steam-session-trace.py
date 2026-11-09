#!/usr/bin/env python3
"""Exercise the production successful-write observer, never replay private bodies.

MADEIRA_STEAM_LAUNCH_HEADER may point at the previous production header: it
compiles the same fixture, then fails because genuine connection/game/service
messages never produce the required bounded summaries.
"""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
header = Path(os.environ.get('MADEIRA_STEAM_LAUNCH_HEADER',
                             root / 'build/ntdll-unix/steam_launch_trace.h'))
source = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
typedef unsigned short WCHAR;
typedef struct { WCHAR *Buffer; unsigned short Length; } UNICODE_STRING;
typedef struct { UNICODE_STRING ImagePathName; } RTL_USER_PROCESS_PARAMETERS;
typedef struct { RTL_USER_PROCESS_PARAMETERS *ProcessParameters; } PEB;
typedef struct { PEB *Peb; } TEB;
static __thread WCHAR image[256];
static __thread RTL_USER_PROCESS_PARAMETERS params;
static __thread PEB peb;
static __thread TEB fake_teb;
static __thread unsigned int identity;
static __thread const char *fd_path;
#define NtCurrentTeb() (&fake_teb)
#define GetCurrentProcessId() (0x320 + identity)
#define GetCurrentThreadId() (0x324 + identity)
static int madeira_steam_ui_image(const WCHAR *name, unsigned int length)
{
    static const char expected[]="steam.exe";
    unsigned int base=0;
    if(!name) return 0;
    for(unsigned i=0;i<length;i++)if(name[i]=='\\'||name[i]=='/')base=i+1;
    if(length-base!=sizeof(expected)-1)return 0;
    for(unsigned i=base;i<length;i++) {
        WCHAR c=name[i];if(c>='A'&&c<='Z')c+='a'-'A';
        if(c!=(unsigned char)expected[i-base])return 0;
    }
    return 1;
}
static int ios_guest_log_fd_path(int fd,char *path,size_t size)
{(void)fd;snprintf(path,size,"%s",fd_path?fd_path:"");return 1;}
#include "HEADER"
static void select_image(const char *name,const char *path)
{
    size_t n=strlen(name);assert(n<256);
    for(size_t i=0;i<=n;i++)image[i]=(unsigned char)name[i];
    params.ImagePathName=(UNICODE_STRING){image,n*sizeof(WCHAR)};
    peb.ProcessParameters=&params;fake_teb.Peb=&peb;fd_path=path;
}
static void note(int fd,const char *line)
{
    errno=EAGAIN;ios_steam_launch_log_observe(fd,line,strlen(line));assert(errno==EAGAIN);
}
static void *pressure(void *arg)
{
    identity=(unsigned)(uintptr_t)arg;
    select_image("C:\\Steam\\steam.exe","/private/account-secret/Steam/logs/connection_log.txt");
    FILE *file=tmpfile();assert(file);
    for(unsigned i=0;i<100;i++) {
        char line[128];snprintf(line,sizeof(line),"SteamServersDisconnected EResult=%u private-token-secret\n",i);
        note(fileno(file),line);
    }
    fclose(file);return NULL;
}
int main(void)
{
    FILE *file=tmpfile(),*other=tmpfile();assert(file&&other);int fd=fileno(file);
    select_image("C:\\Steam\\Steam.exe","/private/account-secret/Steam/logs/connection_log.txt");
    note(fd,"SteamServersConnected account-secret steamid=76561198012345678\n");
    note(fd,"SteamServersConnected repeated private-token-secret\n");
    note(fd,"SteamServersDisconnected EResult=3 https://private.invalid/?token=private-token-secret\n");
    note(fd,"SteamServerConnectFailure EResult: 84 local=192.0.2.100 remote=203.0.113.1\n");
    select_image("C:\\game\\cs2.exe","/private/account-secret/game/csgo/console.log");
    note(fd,"[S_API] SteamAPI_Init(): Loaded 'C:\\private\\steamclient64.dll' OK\n");
    note(fd,"SteamAPI_Init failed EResult=17 password=private-token-secret\n");
    note(fd,"VAC connection failed: account-secret details=private-token-secret\n");
    note(fd,"VACUUM and ordinary console body private-token-secret\n");
    note(fd,"k_EAuthSessionResponseVACCheckTimed");
    note(fd,"Out AuthSessionResponse=5 SteamID=76561198012345678\n");
    note(fd,"k_EAuthSessionResponseAuthTicketInvalidAlreadyUsed EResult=3\n");
    note(fd,"k_EAuthSessionResponseOK2 EResult=99999999999999999 secret\n");
    note(fd,"SteamNetworkingSockets ProblemDetectedLocally EResult=99999999999999999\n");
    note(fd,"SteamNetworkingSockets ClosedByPeer EResult123=4 account-secret\n");
    note(fd,"src\\steamnetworkingsockets\\socket.cpp: No control data returned even though we asked for TOS?\n");
    fd_path="/private/account-secret/loginusers.vdf";
    note(fd,"k_EAuthSessionResponseVACBanned account-secret\n");
    select_image("C:\\game\\cs2.exe","/private/account-secret/console_log.txt");
    note(fd,"k_EAuthSessionResponseVACBanned account-secret\n");
    select_image("C:\\Steam\\steamwebhelper.exe","/private/account-secret/console.log");
    note(fd,"k_EAuthSessionResponseVACBanned account-secret\n");
    select_image("C:\\Steam\\SteamService.exe","/private/account-secret/Steam/service_log.txt");
    note(fd,"Failed to initialize service EResult=2 pathname=C:\\account-secret\\private-token-secret\n");
    select_image("C:\\game\\cs2.exe","/private/account-secret/game/csgo/console.log");
    char oversized[900];memset(oversized,'a',sizeof(oversized));oversized[899]=0;
    note(fd,oversized);note(fd,"k_EAuthSessionResponsePublisherIssuedBan\n");
    note(fd,"SteamServerConnectFailure EResult=4\n");
    note(fd,"k_EAuthSessionResponse");
    note(fileno(other),"VACBanned account-secret\n"); /* never join two different files */
    note(fileno(other),"SteamServersDisconnected EResult=9\n");
#ifdef MADEIRA_STEAM_SESSION_TRACE_H
    assert(ios_steam_launch_lines==0);
    unsigned int code=0;
    assert(ios_steam_session_code("EResult=3","EResult",&code)&&code==3);
    assert(!ios_steam_session_code("secretEResult=3","EResult",&code));
    assert(!ios_steam_session_code("EResult123=4","EResult",&code));
    assert(!ios_steam_session_code("EResult=12345678901234567","EResult",&code));
    assert(!ios_steam_session_has("k_EAuthSessionResponseOK2","k_EAuthSessionResponseOK"));
    assert(ios_steam_session_lines==14);
#endif
    pthread_t workers[4];
    for(uintptr_t i=0;i<4;i++)assert(!pthread_create(&workers[i],NULL,pressure,(void *)(i+1)));
    for(unsigned i=0;i<4;i++)assert(!pthread_join(workers[i],NULL));
#ifdef MADEIRA_STEAM_SESSION_TRACE_H
    assert(ios_steam_session_lines==96);
#endif
    fclose(other);fclose(file);
    puts("PASS production Steam/session observer fixture complete; application-log evidence is not authentication validation");
}
'''.replace('HEADER', str(header.resolve()))

with tempfile.TemporaryDirectory(prefix='madeira-steam-session-') as directory:
    path = Path(directory)
    fixture, executable = path / 'check.c', path / 'check'
    fixture.write_text(source)
    subprocess.run([os.environ.get('CC') or shutil.which('clang') or 'cc', '-std=c11',
                    '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', '-pthread', str(fixture), '-o', str(executable)], check=True)
    result = subprocess.run([str(executable)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    assert result.returncode == 0, result.stdout
    lines = [line for line in result.stdout.splitlines() if '[steam-session-v1]' in line]
    assert len(lines) == 96, f'genuine game/client/service messages missing or unbounded: {len(lines)}\n{result.stdout}'
    sources = [line for line in result.stdout.splitlines() if '[steam-session-source-v1]' in line]
    assert 3 <= len(sources) <= 32
    assert all('successful-write-observed=1 body=excluded authentication-result=unknown' in line for line in sources)
    assert all(any(f'role={role} ' in line for line in sources) for role in ['steam', 'cs2', 'service'])
    assert len(set(re.findall(r'\bsequence=(\d+)', result.stdout))) == 96
    assert all('auth-validation=unclaimed body=excluded' in line for line in lines)
    for token in ['event=api-client-loaded', 'event=api-initialization-failed',
                  'event=vac-message', 'event=auth-session-response', 'event=network-tos-control-missing',
                  'event=network-closed-by-peer', 'event=service-error-message',
                  'reported-token=k_EAuthSessionResponseVACCheckTimedOut numeric-result-present=1 numeric-result=5']:
        assert any(token in line for line in lines), token
    assert not any('reported-token=k_EAuthSessionResponseVACBanned' in line for line in lines)
    assert not any('PublisherIssuedBan' in line for line in lines)
    assert sum('event=api-client-loaded' in line for line in lines) == 1
    assert sum('event=steam-servers-connected-message' in line for line in lines) == 1
    assert any('event=network-closed-by-peer' in line and 'numeric-result-present=0 numeric-result=0' in line for line in lines)
    assert not any(secret in result.stdout for secret in ['account-secret', 'private-token-secret',
                   '76561198012345678', 'https://', '/private/', '192.0.2.100', '203.0.113.1', 'password=', 'steamclient64.dll'])
    print('PASS production successful-write session observer: Steam/CS2/service role and filename gates; '
          'fragmentation, fd reuse, overlong records, fixed enum/numeric summaries, privacy, errno, '
          'dedup and 4-thread bounded96-event capture; no fabricated authentication status')
