#!/usr/bin/env python3
"""Run original and staged NtReadFileScatter over real owned file mappings.

Forced POSIX short reads expose the maintained loop's double subtraction. The
fixture executes the complete production function, including native errno,
IOSB, event, APC and completion publication; it never fabricates file bytes.
"""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("scatter_stage", root/"tools/build/stage-ntdll-scatter-read.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
source = (root/"wine/dlls/ntdll/unix/file.c").read_text()
staged = module.stage(source)
try:
    module.stage(staged)
    raise AssertionError("already corrected source accepted without exact original boundary")
except ValueError:
    pass
assert staged.count(module.OLD) == source.count(module.OLD)-2


def actual(text):
    start = text.index("NTSTATUS WINAPI NtReadFileScatter(")
    return text[start:text.index("\n}\n", start)+3]


prefix = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#define WINAPI
#define TRACE(...) ((void)0)
#define min(a,b) ((a)<(b)?(a):(b))
typedef uint32_t NTSTATUS,ULONG,UINT;
typedef uintptr_t ULONG_PTR,client_ptr_t;
typedef void *HANDLE;
typedef int BOOL;
typedef union { long long QuadPart; } LARGE_INTEGER;
typedef struct { void *Buffer; } FILE_SEGMENT_ELEMENT;
typedef struct { NTSTATUS Status; uintptr_t Information; } IO_STATUS_BLOCK;
typedef void (*PIO_APC_ROUTINE)(void);
typedef void (*PNTAPCFUNC)(void);
#define FALSE 0
#define TRUE 1
#define STATUS_SUCCESS 0u
#define STATUS_PENDING 0x103u
#define STATUS_ACCESS_VIOLATION 0xc0000005u
#define STATUS_INVALID_PARAMETER 0xc000000du
#define STATUS_END_OF_FILE 0xc0000011u
#define STATUS_ACCESS_DENIED 0xc0000022u
#define STATUS_INVALID_HANDLE 0xc0000008u
#define FILE_READ_DATA 1
#define FILE_SYNCHRONOUS_IO_ALERT 0x10
#define FILE_SYNCHRONOUS_IO_NONALERT 0x20
#define FILE_NO_INTERMEDIATE_BUFFERING 0x8
#define FILE_USE_FILE_POINTER_POSITION (-2)
enum server_fd_type { FD_TYPE_FILE, FD_TYPE_OTHER };
static const unsigned page_size=4096;
static int real_fd, call_number, short_at, interrupt_at, fail_at, native_mode;
static unsigned events,apcs,completions;
static NTSTATUS completion_status;
static unsigned completion_bytes;
static off_t offsets[16];static size_t wants[16];
static client_ptr_t iosb_client_ptr(IO_STATUS_BLOCK *io) { return (uintptr_t)io; }
static unsigned server_get_unix_fd(HANDLE file,unsigned rights,int *fd,int *close_fd,enum server_fd_type *type,unsigned *options)
{ (void)file;assert(rights==FILE_READ_DATA);*fd=real_fd;*close_fd=0;*type=FD_TYPE_FILE;*options=FILE_NO_INTERMEDIATE_BUFFERING;return STATUS_SUCCESS; }
static ssize_t actual_read(int fd,void *buffer,size_t length,off_t offset,int positional)
{
    int call=++call_number;assert(call<16);wants[call]=length;offsets[call]=offset;
    if(call==interrupt_at){errno=EINTR;return -1;}
    if(call==fail_at){errno=EACCES;return -1;}
    if(call==short_at&&length>2048)length=2048;
    return positional?pread(fd,buffer,length,offset):read(fd,buffer,length);
}
static ssize_t virtual_locked_pread(int fd,void *buffer,size_t n,off_t off) { native_mode=1;return actual_read(fd,buffer,n,off,1); }
static ssize_t virtual_locked_read(int fd,void *buffer,size_t n) { native_mode=2;return actual_read(fd,buffer,n,0,0); }
static NTSTATUS errno_to_status(int error) { assert(error==EACCES);return STATUS_ACCESS_DENIED; }
static void set_sync_iosb(IO_STATUS_BLOCK *io,NTSTATUS status,unsigned total,unsigned options)
{ assert(options==FILE_NO_INTERMEDIATE_BUFFERING);io->Status=status;io->Information=total; }
static void NtSetEvent(HANDLE event,void *out) { assert(event==(void*)1&&!out);events++; }
static void NtResetEvent(HANDLE event,void *out) { (void)event;(void)out;assert(0); }
static HANDLE GetCurrentThread(void) { return (void*)2; }
static void NtQueueApcThread(HANDLE thread,PNTAPCFUNC function,ULONG_PTR arg,client_ptr_t io,unsigned zero)
{ assert(thread==(void*)2&&function&&arg==0x1234&&io&&!zero);apcs++; }
static void add_completion(HANDLE file,ULONG_PTR value,NTSTATUS status,unsigned total,BOOL queued)
{ assert(file==(void*)3&&value==0x1234&&queued);completions++;completion_status=status;completion_bytes=total; }
'''
suffix = r'''
static unsigned char pattern[12288];
static void callback(void) {}
static unsigned char *mapping;
static void reset(void)
{
    call_number=short_at=interrupt_at=fail_at=native_mode=0;
    events=apcs=completions=0;completion_status=0;completion_bytes=0;
    memset(offsets,0,sizeof(offsets));memset(wants,0,sizeof(wants));
    memset(mapping,0xcc,8192);assert(lseek(real_fd,0,SEEK_SET)==0);
}
static IO_STATUS_BLOCK run(int positioned,int use_apc,off_t start,unsigned n)
{
    FILE_SEGMENT_ELEMENT segments[2]={{mapping},{mapping+4096}};
    IO_STATUS_BLOCK io={0xeeeeeeee,0xeeeeeeee};LARGE_INTEGER offset={.QuadPart=start};
    NTSTATUS status=NtReadFileScatter((void*)3,(void*)1,use_apc?callback:NULL,(void*)0x1234,
        &io,segments,n,positioned?&offset:NULL,NULL);
    assert(status==STATUS_PENDING&&events==1);
    assert(use_apc?(apcs==1&&!completions):(!apcs&&completions==1));
    if(!use_apc)assert(completion_status==io.Status&&completion_bytes==io.Information);
    return io;
}
int main(void)
{
    FILE *file=tmpfile();assert(file);real_fd=fileno(file);
    for(unsigned i=0;i<sizeof(pattern);i++)pattern[i]=i*13+9;
    assert(write(real_fd,pattern,sizeof(pattern))==sizeof(pattern));
    mapping=mmap(NULL,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(mapping!=MAP_FAILED);
    for(int positional=0;positional<2;positional++)for(int use_apc=0;use_apc<2;use_apc++)
    {
        reset();short_at=2;IO_STATUS_BLOCK io=run(positional,use_apc,0,8192);
#ifdef ORIGINAL
        assert(io.Status==STATUS_SUCCESS&&io.Information==6144&&call_number==3&&wants[3]==0);
#else
        assert(io.Status==STATUS_SUCCESS&&io.Information==8192&&call_number==3&&wants[3]==2048);
        assert(!memcmp(mapping,pattern,8192)&&native_mode==(positional?1:2));
        if(positional)assert(offsets[1]==0&&offsets[2]==4096&&offsets[3]==6144);
#endif
    }
#ifndef ORIGINAL
    reset();short_at=2;interrupt_at=3;IO_STATUS_BLOCK io=run(1,0,0,8192);
    assert(io.Status==STATUS_SUCCESS&&io.Information==8192&&call_number==4);
    assert(offsets[3]==6144&&offsets[4]==6144&&!memcmp(mapping,pattern,8192));
    reset();io=run(1,0,10240,8192);assert(io.Status==STATUS_SUCCESS&&io.Information==2048&&call_number==2);
    assert(!memcmp(mapping,pattern+10240,2048)&&mapping[2048]==0xcc);
    reset();io=run(1,0,12288,8192);assert(io.Status==STATUS_END_OF_FILE&&!io.Information);
    reset();fail_at=1;io=run(1,0,0,8192);assert(io.Status==STATUS_ACCESS_DENIED&&!io.Information&&call_number==1);
    reset();fail_at=2;io=run(1,0,0,8192);assert(io.Status==STATUS_ACCESS_DENIED&&io.Information==4096&&call_number==2);
    assert(!memcmp(mapping,pattern,4096)&&mapping[4096]==0xcc);
    puts("PASS actual staged NtReadFileScatter: full data after half-page short read, positioned/current offsets, EINTR, real EOF, original errors, IOSB/APC/event/IOCP semantics");
#else
    reset();fail_at=1;IO_STATUS_BLOCK io=run(1,0,0,8192);assert(io.Status==STATUS_END_OF_FILE&&!io.Information);
    puts("PASS negative control: original stops at 6144/8192 bytes and overwrites first native error with EOF");
#endif
    assert(!munmap(mapping,8192));fclose(file);
}
'''
with tempfile.TemporaryDirectory(prefix="madeira-scatter-short-read-") as folder:
    for label, text in (("original", source), ("corrected", staged)):
        src, exe = Path(folder)/(label+".c"), Path(folder)/label
        src.write_text(prefix+actual(text)+suffix)
        cmd = [os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-pthread",
               "-Wno-unused-parameter", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", str(src), "-o", str(exe)]
        if label == "original":
            cmd.insert(1, "-DORIGINAL")
        subprocess.run(cmd, check=True)
        result = subprocess.run([str(exe)], capture_output=True, text=True, check=True)
        print(result.stdout, end="")
    # CLI output is staged; the upstream submodule file stays byte-for-byte.
    out=Path(folder)/"file.c"
    subprocess.run(["python3",str(root/"tools/build/stage-ntdll-scatter-read.py"),"--source",str(root/"wine/dlls/ntdll/unix/file.c"),"--output",str(out)],check=True)
    assert out.read_text()==staged and (root/"wine/dlls/ntdll/unix/file.c").read_text()==source
    print("PASS exact-boundary build staging; pinned Wine source unchanged; drift and already-staged inputs rejected")
