#!/usr/bin/env python3
"""Compile the real passive log observer; reject unrelated/private log bodies."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
header = root / 'build/ntdll-unix/steam_launch_trace.h'
source = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
typedef unsigned short WCHAR;
typedef struct { WCHAR *Buffer; unsigned short Length; } UNICODE_STRING;
typedef struct { UNICODE_STRING ImagePathName; } RTL_USER_PROCESS_PARAMETERS;
typedef struct { RTL_USER_PROCESS_PARAMETERS *ProcessParameters; } PEB;
typedef struct { PEB *Peb; } TEB;
static WCHAR image[] = {'s','t','e','a','m','.','e','x','e',0};
static RTL_USER_PROCESS_PARAMETERS params = {{image,18}};
static PEB peb = {&params};
static TEB fake_teb = {&peb};
static int role = 1;
static const char *fd_path = "/private/account-secret/Steam/logs/content_log.txt";
#define NtCurrentTeb() (&fake_teb)
#define GetCurrentProcessId() (0x68)
#define GetCurrentThreadId() (0x28c)
static int madeira_steam_ui_image(const WCHAR *name, unsigned int length)
{ (void)name; (void)length; return role; }
static int ios_guest_log_fd_path(int fd, char *path, size_t size)
{ (void)fd; snprintf(path,size,"%s",fd_path); return 1; }
#include "HEADER"
static void note(int fd, const char *text)
{
    errno=EAGAIN;
    ios_steam_launch_log_observe(fd,text,strlen(text));
    assert(errno==EAGAIN);
}
int main(void)
{
    FILE *file=tmpfile(); assert(file); int fd=fileno(file);
    assert(!ios_steam_launch_app730("AppID 7300 update state : Validating"));
    assert(ios_steam_launch_app730("[date] AppID 730 update state : Validating"));
    assert(!strcmp(ios_steam_launch_task("changed task to UpdatingAppInfo with token-secret"),"UpdatingAppInfo"));
    assert(!strcmp(ios_steam_launch_task("changed task to UpdatingAppInfoUnknown"),"unknown"));
    note(fd,"[date] AppID 730 update state : Validating, Update Running, private-token-secret\n");
    unsigned int count=ios_steam_launch_lines; assert(count==1);
    note(fd,"[date] AppID 730 update state : Validating, Update Running, private-token-secret\n");
    assert(ios_steam_launch_lines==count);
    note(fd,"[date] AppID 7300 update state : Validating\n");
    note(fd,"[date] AppID 730 login account-secret private-token-secret\n");
    assert(ios_steam_launch_lines==count);
    fd_path="/private/account-secret/Steam/logs/loginusers.vdf";
    note(fd,"GameAction [AppID 730] : LaunchApp changed task to CreatingProcess\n");
    assert(ios_steam_launch_lines==count);
    fd_path="/private/account-secret/Steam/logs/console_log.txt";
    role=2; note(fd,"GameAction [AppID 730] : LaunchApp changed task to CreatingProcess\n");
    role=1; assert(ios_steam_launch_lines==count);
    note(fd,"GameAction [AppID 730] : LaunchApp changed task to Updat");
    assert(ios_steam_launch_lines==count);
    note(fd,"ingAppInfo with https://host/?token=private-token-secret\n");
    assert(ios_steam_launch_lines==++count);
    note(fd,"GameAction [AppID 730] : LaunchApp changed task to Token_secret with private-token-secret\n");
    assert(ios_steam_launch_lines==++count);
    note(fd,"GameAction [AppID 730] : ShowError AppError_47 with private-token-secret\n");
    assert(ios_steam_launch_lines==++count);
    note(fd,"GameAction [AppID 730] : ShowError AppError_123456 private-token-secret\n");
    assert(ios_steam_launch_lines==++count);
    char oversized[900]; memset(oversized,'x',sizeof(oversized)); oversized[sizeof(oversized)-1]=0;
    note(fd,oversized);
    note(fd,"GameAction [AppID 730] : LaunchApp changed task to CreatingProcess\n");
    assert(ios_steam_launch_lines==count); /* dropped overlong line is not reparsed */
    note(fd,"GameAction [AppID 730] : LaunchApp changed task to CreatingProcess\n");
    assert(ios_steam_launch_lines==++count);
    fd_path="/private/account-secret/Steam/logs/gameprocess_log.txt";
    note(fd,"AppID 730 Adding process 768 /private/account-secret/cs2.exe token-secret\n");
    assert(ios_steam_launch_lines==++count);
    note(fd,"AppID 730 Removing process 768 /private/account-secret/cs2.exe token-secret\n");
    assert(ios_steam_launch_lines==++count);
    for(unsigned int i=0;i<200;i++) {
        char line[150]; snprintf(line,sizeof(line),"GameAction [AppID 730] : ShowError AppError_%u\n",i);
        note(fd,line);
    }
    assert(ios_steam_launch_lines==128);
    fclose(file);
    puts("PASS production launch observer: exact app/role/file gates, fragmented writes, bounded summaries, privacy, error/task parsing and errno");
}
'''.replace('HEADER', str(header))
with tempfile.TemporaryDirectory() as temp:
    fixture = Path(temp) / 'check.c'
    fixture.write_text(source)
    exe = Path(temp) / 'check'
    subprocess.run([os.environ.get('CC') or shutil.which('clang') or 'cc', '-std=c11',
                    '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', str(fixture), '-o', str(exe)], check=True)
    result = subprocess.run([str(exe)], check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    output = result.stdout
    assert output.count('[steam-launch-v1]') == 128
    assert 'task=UpdatingAppInfo' in output and 'task=unknown' in output
    assert 'app-error-present=1 app-error=47' in output
    assert 'event=process-added' in output and 'event=process-removed' in output
    assert not any(secret in output for secret in ['private-token-secret', 'account-secret', 'https://', 'token-secret', '/private/', 'cs2.exe'])
    print(output.splitlines()[-1])

build = (root / 'build/ntdll-unix/build.sh').read_text()
start = build.index('source, output, header = map(Path, sys.argv[1:])')
end = build.index('\nPYCODE', start)
with tempfile.TemporaryDirectory() as temp:
    output = Path(temp) / 'file.c'
    namespace = {'Path': Path, 'sys': type('Args', (), {'argv': [
        'stage', str(root / 'wine/dlls/ntdll/unix/file.c'), str(output),
        str(root / 'build/ntdll-unix/io_status_trace.h')]})}
    exec(build[start:end], namespace)
    staged = output.read_text()
    assert str(header) in staged
    assert staged.count('if (total) ios_steam_launch_log_observe( unix_handle, buffer, total );') == 1
    assert 'ios_guest_log_mirror( unix_handle, buffer, total );' in staged
    print('PASS actual Wine staging observes successful log writes without changing guest log or I/O behavior')
