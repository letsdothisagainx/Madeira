#!/usr/bin/env python3
"""Compile the real CEF command-line transformation and child-launch gate."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root/'build/ntdll-unix/process_ios.c').read_text()
start = source.index('    {', source.index('    /* task #34 single-process CEF:'))
end = source.index('    /* madeira-bcd: env.MADEIRA_CHILD_ARGS', start)
block = source[start:end]
code = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "steam_cef_policy.h"
#include "madeira_redact.h"
typedef unsigned short WCHAR;
typedef struct { WCHAR *Buffer; unsigned short Length, MaximumLength; } STRING;
typedef struct { STRING ImagePathName, CommandLine; } PARAMS;
#define STATUS_ACCESS_DENIED 0xc0000022u
static int capture(int fd,const char *format,...) { (void)fd; (void)format; errno=EIO; return 0; }
#define dprintf capture
static unsigned apply(PARAMS *params) { BLOCK return 0; }
static WCHAR *wide(const char *s) {
    size_t n=strlen(s); WCHAR *w=malloc((n+1)*sizeof(*w)); assert(w);
    for(size_t i=0;i<=n;i++) w[i]=(unsigned char)s[i]; return w;
}
static int has(const WCHAR *w,const char *s) {
    WCHAR *needle=wide(s); size_t n=strlen(s),length=0;
    while(w[length]) length++;
    for(size_t i=0;i+n<=length;i++) if(!memcmp(w+i,needle,n*sizeof(*w))) { free(needle);return 1; }
    free(needle);return 0;
}
static void check(const char *image,const char *command,const char *policy,int changed,unsigned status) {
    if(policy) setenv("MADEIRA_STEAM_CEF_POLICY",policy,1); else unsetenv("MADEIRA_STEAM_CEF_POLICY");
    WCHAR *i=wide(image),*c=wide(command); size_t n=strlen(command);
    PARAMS p={{i,strlen(image)*2,strlen(image)*2+2},{c,n*2,n*2+2}};
    errno=EAGAIN;
    assert(apply(&p)==status);
    if(policy && !strcmp(policy,"valve")) assert(errno==EAGAIN);
    if(changed) {
        assert(p.CommandLine.Buffer!=c);
        assert(has(p.CommandLine.Buffer,"--single-process"));
        assert(has(p.CommandLine.Buffer," --enable-logging --v=1"));
        assert(!has(p.CommandLine.Buffer,"--enable-logging=file"));
        assert(!has(p.CommandLine.Buffer,"--no-sandbox"));
        assert(!has(p.CommandLine.Buffer,"PartitionAllocBackupRefPtr"));
        assert(has(p.CommandLine.Buffer,"--disable-features=ValveFeature,SegmentationPlatform"));
        free(p.CommandLine.Buffer);
    } else {
        assert(p.CommandLine.Buffer==c && p.CommandLine.Length==n*2);
        for(size_t j=0;j<=n;j++) assert(c[j]==(unsigned char)command[j]);
    }
    free(i); free(c);
}
int main(void) {
    const char *image="C:\\Steam\\bin\\SteamWebHelper.EXE";
    const char *command="steamwebhelper.exe --disable-features=ValveFeature --auth-token=fixture";
    check(image,command,"valve",0,0);
    check(image,"steamwebhelper.exe --type=renderer --sandbox=enabled","valve",0,0);
    check(image,command,NULL,1,0);
    check(image,"steamwebhelper.exe --type=renderer",NULL,0,STATUS_ACCESS_DENIED);
    check(image,"steamwebhelper.exe --type=crashpad-handler --database=fixture",NULL,0,0);
    check(image,"steamwebhelper.exe \"--type=crashpad-handler\" --database=fixture",NULL,0,0);
    check(image,"steamwebhelper.exe --type=renderer --type=crashpad-handler",NULL,0,0);
    check(image,"steamwebhelper.exe --type=crashpad-handler --type=renderer",NULL,0,STATUS_ACCESS_DENIED);
    check(image,"steamwebhelper.exe --type=crashpad-handler-extra",NULL,0,STATUS_ACCESS_DENIED);
    check(image,"steamwebhelper.exe --type=renderer --log-file=\"C:\\--type=crashpad-handler\"",NULL,0,STATUS_ACCESS_DENIED);
    setenv("MADEIRA_DOCK_SESSION","1",1);
    check(image,"steamwebhelper.exe --type=crashpad-handler",NULL,0,STATUS_ACCESS_DENIED);
    unsetenv("MADEIRA_DOCK_SESSION");
    check("C:\\steamwebhelper.exe\\game.exe",command,NULL,0,0);
    check("notsteamwebhelper.exe",command,NULL,0,0);
    check(image,command,"unknown",1,0);
    puts("PASS real browser rewrite uses valid logging; crashpad arguments and normal creation preserved; quoted/duplicate/substrings classified; Valve policy and security settings preserved");
}
'''.replace('BLOCK',block)
with tempfile.TemporaryDirectory(prefix='madeira-cef-policy-') as temp:
    path,binary=Path(temp)/'test.c',Path(temp)/'test'; path.write_text(code)
    subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-Wall','-Wextra','-Werror',
                    '-Wno-misleading-indentation','-fsanitize=address,undefined',
                    '-I'+str(root/'build/ntdll-unix'),'-I'+str(root/'build'),
                    str(path),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
