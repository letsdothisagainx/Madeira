#!/usr/bin/env python3
"""Execute the actual positional-read function with bounded fd observations.

The data is read using real pread into owned mappings. Only injected errors,
write-watch unprotection and capture clocks are controlled, never completion.
"""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
virtual = (root / "build/ntdll-unix/virtual_ios.c").read_text()
start = virtual.index("ssize_t virtual_locked_pread( int fd, void *addr, size_t size, off_t offset )\n{")
actual = virtual[start:virtual.index("\n}", start)+2]
prefix = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
typedef int BOOL;
#define TRUE 1
#define FALSE 0
#define max(a,b) ((a)>(b)?(a):(b))
static pthread_mutex_t virtual_mutex = PTHREAD_MUTEX_INITIALIZER;
static int use_kernel_writewatch, force_fault, reject_access, watch_updates, watch_bytes;
static int native_calls, alias_route, lock_depth, block_retry, retry_entered, release_retry;
static int competing_entered;
static pthread_mutex_t gate_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_cond = PTHREAD_COND_INITIALIZER;
static _Thread_local unsigned owner = 1;
static uint64_t now_ticks;
static uint64_t clock_step=10000000;
static int owner_role(unsigned *pid,unsigned *tid) { *pid=0x38c;*tid=0x390;return owner==1; }
static uint64_t test_now(void) { return __atomic_add_fetch(&now_ticks,clock_step,__ATOMIC_RELAXED); }
static int private_path(int fd,char *out,size_t capacity)
{ (void)fd;snprintf(out,capacity,"/private/secret-user-token/steamapps/game/resource.vpk");errno=EACCES;return 0; }
static ssize_t test_native_pread(int fd,void *buf,size_t n,off_t off)
{
    native_calls++;
    if (force_fault) { force_fault=0;errno=EFAULT;return -1; }
    if (block_retry && lock_depth)
    {
        pthread_mutex_lock(&gate_lock);retry_entered=1;pthread_cond_broadcast(&gate_cond);
        while(!release_retry)pthread_cond_wait(&gate_cond,&gate_lock);
        pthread_mutex_unlock(&gate_lock);
    }
    return pread(fd,buf,n,off);
}
#define IOS_PREAD_OWNER owner_role
#define IOS_PREAD_NOW test_now
#define IOS_PREAD_PATH private_path
#define IOS_PREAD_BACKING_FD (-1)
#define pread test_native_pread
#include "pread_observation.h"
#undef pread
static int ios_kw_has_rw_alias(uintptr_t lo,uintptr_t hi) { (void)lo;(void)hi;return alias_route; }
static ssize_t ios_kw_read(int fd,void *buf,size_t n,off_t off,BOOL positional)
{ assert(positional);return ios_pread_native(fd,buf,n,off); }
static void server_enter_uninterrupted_section(pthread_mutex_t *lock,sigset_t *mask)
{ (void)mask;pthread_mutex_lock(lock);lock_depth++; }
static void server_leave_uninterrupted_section(pthread_mutex_t *lock,sigset_t *mask)
{ (void)mask;lock_depth--;pthread_mutex_unlock(lock); }
static int check_write_access(void *buf,size_t n,BOOL *watch)
{ (void)buf;(void)n;if(reject_access)return -1;*watch=1;return 0; }
static void update_write_watches(void *buf,size_t n,size_t used)
{ (void)buf;assert(used<=n);watch_updates++;watch_bytes=used; }
'''
suffix = r'''
static int input;
static char output[8192];
static void *read_thread(void *unused)
{ (void)unused;assert(virtual_locked_pread(input,output,sizeof(output),123)==8192);return NULL; }
static void *protect_thread(void *unused)
{ (void)unused;pthread_mutex_lock(&virtual_mutex);competing_entered=1;pthread_mutex_unlock(&virtual_mutex);return NULL; }
int main(void)
{
    FILE *f=tmpfile();assert(f);input=fileno(f);
    char data[16384];for(unsigned i=0;i<sizeof(data);i++)data[i]=i*7;
    assert(write(input,data,sizeof(data))==sizeof(data));
    assert(lseek(input,31,SEEK_SET)==31);
    native_calls=0;errno=EDOM;
    assert(virtual_locked_pread(input,output,sizeof(output),123)==8192);
    assert(native_calls==1&&!memcmp(output,data+123,sizeof(output))&&errno==EDOM);
    assert(lseek(input,0,SEEK_CUR)==31);
    /* Real EOF short read: no duplicate/zero-progress retry. */
    native_calls=0;assert(virtual_locked_pread(input,output,sizeof(output),16000)==384);assert(native_calls==1);
    assert(virtual_locked_pread(input,output,sizeof(output),16384)==0);
    errno=0;assert(virtual_locked_pread(-1,output,16,0)==-1&&errno==EBADF);
    /* Existing EFAULT/writewatch retry keeps its protection and byte count. */
    ios_pread_sequence=0;force_fault=1;native_calls=0;assert(virtual_locked_pread(input,output,sizeof(output),16000)==384);
    assert(native_calls==2&&watch_updates==1&&watch_bytes==384);
    force_fault=1;reject_access=1;native_calls=0;errno=0;
    assert(virtual_locked_pread(input,output,16,0)==-1&&errno==EFAULT&&native_calls==1);
    reject_access=0;
    ios_pread_sequence=0;alias_route=1;assert(virtual_locked_pread(input,output,16,0)==16);alias_route=0;
    /* The actual writewatch retry retains VM exclusion throughout the read. */
    ios_pread_lines=0;force_fault=1;block_retry=1;
    pthread_t reader,protector;assert(!pthread_create(&reader,NULL,read_thread,NULL));
    pthread_mutex_lock(&gate_lock);while(!retry_entered)pthread_cond_wait(&gate_cond,&gate_lock);pthread_mutex_unlock(&gate_lock);
    assert(!pthread_create(&protector,NULL,protect_thread,NULL));
    usleep(20000);assert(!competing_entered);
    pthread_mutex_lock(&gate_lock);release_retry=1;pthread_cond_broadcast(&gate_cond);pthread_mutex_unlock(&gate_lock);
    assert(!pthread_join(reader,NULL)&&!pthread_join(protector,NULL)&&competing_entered);
    block_retry=0;
    /* Short startup bursts do not spend the log budget before map loading. */
    ios_pread_lines=0;ios_pread_last_line=0;ios_pread_sequence=0;
    for(int i=0;i<4;i++)assert(virtual_locked_pread(input,output,sizeof(output),0)==8192);
    assert(ios_pread_lines==1);
    /* Other pseudo-processes perform no capture clock/fd lookup. */
    owner=2;uint64_t clocks=now_ticks;assert(virtual_locked_pread(input,output,16,0)==16);assert(now_ticks==clocks);owner=1;
    ios_pread_lines=0;ios_pread_last_line=0;clock_step=2000000000;
    for(int i=0;i<3000;i++)assert(virtual_locked_pread(input,output,sizeof(output),0)==8192);
    assert(ios_pread_lines==IOS_PREAD_MAX_LINES);
    clocks=now_ticks;assert(virtual_locked_pread(input,output,sizeof(output),0)==8192);assert(now_ticks==clocks);
    fclose(f);
    puts("PASS actual pread: data/offset/short read/EOF/original errno/writewatch/rejected access preserved; VM exclusion survives racing protection; observer bounded and other owners excluded");
}
'''
with tempfile.TemporaryDirectory(prefix="madeira-pread-observation-") as folder:
    src, exe = Path(folder)/"check.c", Path(folder)/"check"
    src.write_text(prefix + actual + suffix)
    cmd = [os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-pthread",
           "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-I"+str(root/"build/ntdll-unix"), str(src), "-o", str(exe)]
    subprocess.run(cmd, check=True)
    result = subprocess.run([str(exe)], capture_output=True, text=True, check=True)
    assert "secret-user-token" not in result.stderr and "resource.vpk" not in result.stderr
    assert "role=suffix-vpk" in result.stderr
    assert "route=writewatch-retry" in result.stderr and "route=rw-alias-bounce" in result.stderr
    assert "first-result=-1 first-errno=14" in result.stderr
    assert "errno=9" in result.stderr and "native-calls=2" in result.stderr
    assert len(result.stderr.splitlines()) <= 40
    print(result.stdout, end="")
