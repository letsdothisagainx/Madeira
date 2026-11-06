#!/usr/bin/env python3
"""Compile the production failure probe; real filesystem queries must preserve errno."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / 'build/wineserver/fd_ios.c').read_text()
start = source.index('static void ios_report_system_create_failure(')
body = source[start:source.index('\n}', start) + 2]
call = source.index('ios_report_system_create_failure( name, flags, access, sharing, options );')
assert call < source.index('file_set_error();', call)
prefix = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define FILE_UNIX_WRITE_ACCESS 2
struct process { unsigned id; } process = { 0x354 };
struct thread { struct process *process; unsigned id; } thread = { &process, 0x358 }, *current = &thread;
'''
main = r'''
int main(int argc, char **argv)
{
    char path[4096], target[4096], parent[4096], moved[4096]; struct stat st;
    assert(argc == 2);
    snprintf(parent,sizeof(parent),"%s/windows",argv[1]); assert(!mkdir(parent,0700));
    snprintf(parent,sizeof(parent),"%s/windows/system32",argv[1]); assert(!mkdir(parent,0700));
    snprintf(path,sizeof(path),"%s/windows/system32/vcamp140.dll",argv[1]);
    snprintf(target,sizeof(target),"%s/absent-container/Madeira.app/vcamp140.dll",argv[1]);
    assert(!symlink(target,path));
    int fd=open(path,O_RDWR|O_CREAT,0600); assert(fd==-1&&errno==ENOENT);
    ios_report_system_create_failure(path,O_CREAT|O_TRUNC,2,0,0x60);
    assert(errno==ENOENT&&!lstat(path,&st)&&S_ISLNK(st.st_mode));
    assert(!unlink(path));
    errno=ENOENT; ios_report_system_create_failure(path,O_CREAT|O_TRUNC,2,0,0x60); assert(errno==ENOENT);
    fd=open(path,O_CREAT|O_EXCL|O_WRONLY,0600); assert(fd>=0&&write(fd,"owned",5)==5&&!close(fd));
    errno=EBUSY; ios_report_system_create_failure(path,O_CREAT|O_TRUNC,2,0,0x60); assert(errno==EBUSY);
    snprintf(moved,sizeof(moved),"%s/moved",argv[1]); assert(!rename(parent,moved));
    errno=ENOENT; ios_report_system_create_failure(path,O_CREAT|O_TRUNC,2,0,0x60); assert(errno==ENOENT);
    assert(!rename(moved,parent));
    errno=EIO; ios_report_system_create_failure(path,0,2,0,0x60); assert(errno==EIO);
    for(unsigned n=0;n<24;n++){
        errno=EACCES; ios_report_system_create_failure(path,O_CREAT|O_TRUNC,2,0,0x60); assert(errno==EACCES);
    }
    fd=open(path,O_RDONLY); char data[5]; assert(fd>=0&&read(fd,data,5)==5&&!memcmp(data,"owned",5)&&!close(fd));
    puts("PASS production system-create probe: actual dangling/absent/regular/parent states, original errno, unchanged files and bounded relative-only output");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-system-create-') as folder:
    work = Path(folder)
    c = work / 'probe.c'
    c.write_text(prefix + body + main)
    exe = work / 'probe'
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all', str(c), '-o', str(exe)], check=True)
    result = subprocess.run([str(exe), str(work)], capture_output=True, text=True, check=True)
    rows = result.stderr.splitlines()
    assert len(rows) == 16 and all('relative=windows/system32/vcamp140.dll' in r for r in rows)
    assert str(work) not in result.stderr
    assert 'leaf=symlink' in rows[0] and 'target-errno=2' in rows[0] and 'parent=directory' in rows[0]
    assert 'leaf=absent' in rows[1] and 'leaf=regular' in rows[2] and 'parent=unavailable' in rows[3]
    print(result.stdout, end='')
