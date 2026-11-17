#!/usr/bin/env python3
"""Equivalent warm-file before/after pread timings; native host, not iPhone."""
from pathlib import Path
import os
import hashlib
import re
import statistics
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
test = (root/"tests/host/check-pread-observation.py").read_text()
prefix = test.split("prefix = r'''",1)[1].split("'''",1)[0]
# Use the production monotonic clock and real pread, without fault injection.
prefix = prefix.replace("#define IOS_PREAD_NOW test_now\n", "")
prefix = prefix.replace("#define pread test_native_pread\n", "")
prefix = prefix.replace("#undef pread\n", "")
current = (root/"build/ntdll-unix/virtual_ios.c").read_text()
# Verbatim daf3dcec virtual_locked_pread, independent of shallow CI history.
original = r'''ssize_t virtual_locked_pread( int fd, void *addr, size_t size, off_t offset )
{
    sigset_t sigset;
    BOOL has_write_watch = FALSE;
    int err = EFAULT;
    ssize_t ret;

    if (ios_kw_has_rw_alias( (uintptr_t)addr, (uintptr_t)addr + size )) return ios_kw_read( fd, addr, size, offset, TRUE );
    ret = pread( fd, addr, size, offset );
    if (ret != -1 || use_kernel_writewatch || errno != EFAULT) return ret;

    server_enter_uninterrupted_section( &virtual_mutex, &sigset );
    if (!check_write_access( addr, size, &has_write_watch ))
    {
        ret = pread( fd, addr, size, offset );
        err = errno;
        if (has_write_watch) update_write_watches( addr, size, max( 0, ret ));
    }
    server_leave_uninterrupted_section( &virtual_mutex, &sigset );
    errno = err;
    return ret;
}'''
assert hashlib.sha256(original.encode()).hexdigest() == "2ecd88260d0124c4c83862bacdefb08b0d4e5c9a841709b60d786668d7c0ee79"


def function(text, name):
    start = text.index("ssize_t virtual_locked_pread( int fd, void *addr, size_t size, off_t offset )\n{")
    body = text[start:text.index("\n}",start)+2]
    return body.replace("ssize_t virtual_locked_pread(", "ssize_t "+name+"(",1)


suffix = r'''
static uint64_t nano(clockid_t clock)
{ struct timespec now;assert(!clock_gettime(clock,&now));return (uint64_t)now.tv_sec*1000000000+now.tv_nsec; }
static void bench(int fd,void *buffer,size_t n,int mode,unsigned repetition)
{
    size_t loops=(128u<<20)/n;ssize_t (*readfn)(int,void*,size_t,off_t)=mode?measured:baseline;
    ios_pread_lines=mode==2?IOS_PREAD_MAX_LINES:0;ios_pread_last_line=0;ios_pread_sequence=0;
    uint64_t cpu=nano(CLOCK_THREAD_CPUTIME_ID),wall=nano(CLOCK_MONOTONIC);
    for(size_t i=0;i<loops;i++)assert(readfn(fd,buffer,n,0)==(ssize_t)n);
    wall=nano(CLOCK_MONOTONIC)-wall;cpu=nano(CLOCK_THREAD_CPUTIME_ID)-cpu;
    printf("n=%zu mode=%d repetition=%u wall-ns=%.1f cpu-ns=%.1f\n",n,mode,repetition,(double)wall/loops,(double)cpu/loops);
}
int main(void)
{
    FILE *f=tmpfile();assert(f);int fd=fileno(f);size_t max=16u<<20;
    void *buffer=malloc(max);assert(buffer);memset(buffer,0xa5,max);
    assert(write(fd,buffer,max)==(ssize_t)max);assert(pread(fd,buffer,max,0)==(ssize_t)max);
    const size_t sizes[]={65536,1048576,16777216};
    for(unsigned i=0;i<3;i++)for(unsigned r=0;r<7;r++)for(unsigned j=0;j<3;j++)bench(fd,buffer,sizes[i],(j+r)%3,r);
    free(buffer);fclose(f);
}
'''
with tempfile.TemporaryDirectory(prefix="madeira-pread-bench-") as folder:
    src,exe=Path(folder)/"bench.c",Path(folder)/"bench"
    src.write_text(prefix+function(original,"baseline")+function(current,"measured")+suffix)
    subprocess.run([os.environ.get("CC","cc"),"-O2","-std=gnu11","-pthread","-I"+str(root/"build/ntdll-unix"),str(src),"-o",str(exe)],check=True)
    result=subprocess.run([str(exe)],check=True,capture_output=True,text=True)
    values={}
    for n,mode,wall,cpu in re.findall(r"n=(\d+) mode=(\d+) repetition=\d+ wall-ns=([\d.]+) cpu-ns=([\d.]+)",result.stdout):
        values.setdefault((int(n),int(mode)),[]).append((float(wall),float(cpu)))
    print("Native-host warm regular file, 128MiB/mode/repetition, 7 alternating repetitions; medians per read. Not iPhone measurements.")
    for n in (65536,1048576,16777216):
        print(f"{n//1024}KiB "+"; ".join(f"{label}: wall={statistics.median(x[0] for x in values[n,m])/1000:.2f}us cpu={statistics.median(x[1] for x in values[n,m])/1000:.2f}us" for m,label in enumerate(("baseline","CS2 capture eligible","capture cap exhausted"))))
