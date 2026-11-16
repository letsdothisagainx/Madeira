#!/usr/bin/env python3
"""Execute production CS2-only child environment policy, with safe native reads.

This runs the exact helper extracted from process_ios.c. Linux kernel-checked pipe
copies stand in for Mach's fault-safe read only; all path, bounds,
identity, custom-setting and UTF-16 merge decisions are production code.
It does not prove Steam login, real CS2 launch, rendering or iPhone performance.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
source = (ROOT / 'build/ntdll-unix/process_ios.c').read_text()
helper = source.split('/* BEGIN CS2 TEXTURE CHILD ENVIRONMENT */', 1)[1].split('/* END CS2 TEXTURE CHILD ENVIRONMENT */', 1)[0]
creation = source.split('NTSTATUS WINAPI NtCreateUserProcess(', 1)[1].split('\n\n#ifdef WINE_IOS\n/******************************************************************************', 1)[0]
assert creation.index('get_pe_file_info(') < creation.index('ios_cs2_texture_environment(') < creation.index('create_startup_info(')
assert 'getenv("MADEIRA_CS2_TEXTURE_DXMT_CONFIG")' in creation
assert 'cs2_texture_params = *params;' in creation
assert 'params = &cs2_texture_params;' in creation
assert 'params->Environment, params->EnvironmentSize' in creation
assert creation.index('spawn_process(') < creation.index('free( cs2_texture_env );')
assert 'setenv(' not in helper and 'unsetenv(' not in helper
assert 'NtCreateUserProcess(' not in helper
print('PASS production child environment is prepared after actual PE validation and before imports; owned local copy freed after spawn; no global environment/process-status spoofing')

prelude = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <pthread.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_vm.h>
#else
#include <sys/syscall.h>
typedef uintptr_t mach_vm_address_t;
typedef size_t mach_vm_size_t;
#define KERN_SUCCESS 0
static int mach_task_self(void) { return 0; }
static int mach_vm_read_overwrite(int task, mach_vm_address_t src, mach_vm_size_t len,
                                  mach_vm_address_t dst, mach_vm_size_t *copied) {
    int fds[2], result = -1;
    size_t offset = 0;
    (void)task;
    *copied = 0;
    if (pipe(fds)) return -1;
    /* Copy through the kernel rather than dereferencing unreadable guest test
     * pages. Small chunks cannot block on pipe capacity; each copy honours
     * source protection and reports partial/unreadable ranges as a failure. */
    while (offset < len) {
        size_t chunk = len-offset < 1024 ? len-offset : 1024;
        ssize_t written = syscall(SYS_write, fds[1], (const void *)(src+offset), chunk);
        if (written < 0 || (size_t)written != chunk ||
            read(fds[0], (void *)(dst+offset), chunk) != written) goto done;
        offset += chunk;
    }
    *copied = offset; result = KERN_SUCCESS;
done:
    close(fds[0]); close(fds[1]); return result;
}
#endif
typedef uint16_t WCHAR;
typedef uint16_t USHORT;
typedef size_t SIZE_T;
typedef int BOOL;
#define TRUE 1
#define FALSE 0
#define IMAGE_FILE_MACHINE_AMD64 0x8664
typedef struct { USHORT Length, MaximumLength; WCHAR *Buffer; } UNICODE_STRING;
static _Thread_local int allocations, fail_allocation;
static void *checked_malloc(size_t bytes) {
    ++allocations;
    if (allocations == fail_allocation) { errno = ENOMEM; return NULL; }
    return malloc(bytes);
}
#define malloc checked_malloc
'''

harness = r'''
#undef malloc
static const char *game = "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Counter-Strike Global Offensive\\game\\bin\\win64\\cs2.exe";
static const char *option = "d3d11.mipClampAuto=1";
static const char *baseline[] = {"SteamAppId=730", "SteamGameId=730", "DXMT_CONFIG=dxgi.customDeviceId=2544;d3d11.preferredMaxFrameRate=60", "Unrelated=keep", "=C:=C:\\preserved", NULL};
static WCHAR *wide(const char *text) {
    size_t len = strlen(text), i;
    WCHAR *out = malloc((len+1)*sizeof(*out)); assert(out);
    for (i = 0; i <= len; ++i) out[i] = (unsigned char)text[i];
    return out;
}
static UNICODE_STRING path(const char *text) {
    UNICODE_STRING s;
    s.Buffer = wide(text); s.Length = strlen(text)*sizeof(WCHAR); s.MaximumLength = s.Length+sizeof(WCHAR);
    return s;
}
static WCHAR *environment(const char *const *entries, SIZE_T *bytes) {
    size_t count = 1, i, j, o = 0;
    WCHAR *out;
    for (i = 0; entries[i]; ++i) count += strlen(entries[i])+1;
    if (count == 1) ++count;
    out = calloc(count, sizeof(*out)); assert(out);
    for (i = 0; entries[i]; ++i) {
        for (j = 0; entries[i][j]; ++j) out[o++] = (unsigned char)entries[i][j];
        out[o++] = 0;
    }
    *bytes = count*sizeof(*out); return out;
}
static int equals(const WCHAR *a, const char *b) {
    size_t i;
    for (i = 0; b[i]; ++i) if (a[i] != (unsigned char)b[i]) return 0;
    return a[i] == 0;
}
static const WCHAR *value(const WCHAR *env, const char *name) {
    const WCHAR *at = env; size_t n = strlen(name), i;
    while (*at) {
        for (i = 0; i < n; ++i) if (ios_cs2_texture_lower(at[i]) != name[i]) break;
        if (i == n && at[n] == '=') return at+n+1;
        while (*at) ++at;
        ++at;
    }
    return NULL;
}
static WCHAR *apply(const char *image, const char *actual, USHORT machine,
                    const WCHAR *env, SIZE_T bytes, const char *policy, SIZE_T *out_bytes) {
    UNICODE_STRING p = path(image), a = path(actual);
    WCHAR *result;
    errno = EBUSY;
    result = ios_cs2_texture_environment(&p, &a, machine, env, bytes, policy, out_bytes);
    assert(errno == EBUSY);
    free(p.Buffer); free(a.Buffer);
    return result;
}
static int cases;
static void denied(const char *image, const char *actual, USHORT machine,
                   const WCHAR *env, SIZE_T bytes, const char *policy) {
    SIZE_T out_bytes = 123;
    WCHAR *out = apply(image, actual, machine, env, bytes, policy, &out_bytes);
    assert(!out && !out_bytes); ++cases;
}
static void denied_entries(const char *const *entries) {
    SIZE_T bytes; WCHAR *env = environment(entries, &bytes);
    denied(game, game, IMAGE_FILE_MACHINE_AMD64, env, bytes, option);
    free(env);
}
struct thread_case { const WCHAR *env; SIZE_T bytes; const char *policy; };
static void *concurrent_case(void *raw) {
    struct thread_case *c = raw;
    for (int i=0;i<16;++i) {
        SIZE_T out_bytes;
        WCHAR *out=apply(game,game,IMAGE_FILE_MACHINE_AMD64,c->env,c->bytes,c->policy,&out_bytes);
        assert(out && out_bytes>c->bytes);
        const WCHAR *config=value(out,"dxmt_config");
        size_t len=0;while(config[len])++len;
        assert(ios_cs2_texture_ascii(config+len-strlen(c->policy),strlen(c->policy),c->policy,FALSE));
        assert(!strcmp(getenv("DXMT_CONFIG"),"native-global-unchanged"));
        free(out);
    }
    return NULL;
}
int main(void) {
    SIZE_T bytes, out_bytes, before_bytes;
    WCHAR *env = environment(baseline, &bytes), *out, *before = malloc(bytes);
    UNICODE_STRING image, actual;
    assert(before); memcpy(before, env, bytes); before_bytes = bytes;
    setenv("DXMT_CONFIG", "native-global-unchanged", 1);
    for (int mode = 0; mode <= 1; ++mode) {
        const char *chosen = mode ? option : "d3d11.mipClampAuto=0";
        out = apply(game, game, IMAGE_FILE_MACHINE_AMD64, env, bytes, chosen, &out_bytes);
        assert(out && out != env && out_bytes > bytes);
        assert(equals(value(out,"dxmt_config"), mode ?
            "dxgi.customDeviceId=2544;d3d11.preferredMaxFrameRate=60;d3d11.mipClampAuto=1" :
            "dxgi.customDeviceId=2544;d3d11.preferredMaxFrameRate=60;d3d11.mipClampAuto=0"));
        assert(equals(value(out,"steamappid"), "730") && equals(value(out,"steamgameid"), "730"));
        assert(equals(value(out,"unrelated"), "keep"));
        assert(!memcmp(before,env,before_bytes));
        assert(!strcmp(getenv("DXMT_CONFIG"),"native-global-unchanged"));
        free(out); ++cases;
    }
    out = apply("C:/PROGRAM FILES (x86)/Steam/steamapps/common/Counter-Strike Global Offensive/game/bin/win64/CS2.EXE",
                "\\??\\C:\\Program Files (x86)\\Steam\\steamapps\\common\\Counter-Strike Global Offensive\\game\\bin\\win64\\cs2.exe",
                IMAGE_FILE_MACHINE_AMD64, env, bytes, option, &out_bytes);
    assert(out); free(out); ++cases;
    const char *unrelated[] = {"C:\\Steam\\steam.exe", "C:\\Steam\\steamwebhelper.exe", "C:\\Probe\\pixel-readback-x64.exe",
      "C:\\Steam\\game\\bin\\win64\\notcs2.exe", "C:\\fake\\cs2.exe", "cs2.exe", "C:\\game\\bin\\win64\\cs2.exe:stream",
      "C:\\game\\bin\\win64\\..\\win64\\cs2.exe", "C:\\game\\bin\\.\\win64\\cs2.exe", "C:/game/bin//win64/cs2.exe"};
    for (size_t i=0; i<sizeof(unrelated)/sizeof(unrelated[0]); ++i)
        denied(unrelated[i],unrelated[i],IMAGE_FILE_MACHINE_AMD64,env,bytes,option);
    denied(game,"C:\\other\\game\\bin\\win64\\cs2.exe",IMAGE_FILE_MACHINE_AMD64,env,bytes,option);
    denied(game,game,0x14c,env,bytes,option); denied(game,game,0xaa64,env,bytes,option);
    denied(game,game,IMAGE_FILE_MACHINE_AMD64,env,bytes,NULL);
    denied(game,game,IMAGE_FILE_MACHINE_AMD64,env,bytes,"unrelated.option=1");
    denied(game,game,IMAGE_FILE_MACHINE_AMD64,env,bytes,"d3d11.mipClampAuto=2");
    denied(game,game,IMAGE_FILE_MACHINE_AMD64,env,bytes,"d3d11.mipClampAuto=1;unexpected=1");
    const char *no_app[] = {"SteamGameId=730",NULL}; denied_entries(no_app);
    const char *wrong_app[] = {"SteamAppId=356400",NULL}; denied_entries(wrong_app);
    const char *bad_game[] = {"SteamAppId=730","SteamGameId=356400",NULL}; denied_entries(bad_game);
    const char *dup_app[] = {"SteamAppId=730","steamappid=730",NULL}; denied_entries(dup_app);
    const char *dup_game[] = {"SteamAppId=730","SteamGameId=730","steamgameid=730",NULL}; denied_entries(dup_game);
    const char *dup_config[] = {"SteamAppId=730","DXMT_CONFIG=x=1","dxmt_config=x=1",NULL}; denied_entries(dup_config);
    const char *custom[] = {"d3d11.mipClampBC=0","d3d11.mipClampBC=2"," d3d11.mipClampAuto = 0 ","d3d11.mipClampAuto=1","d3d11.mipClampAutoMB=1536"};
    for(size_t i=0;i<sizeof(custom)/sizeof(custom[0]);++i) {
        char setting[150]; snprintf(setting,sizeof(setting),"DXMT_CONFIG=x=1;%s",custom[i]);
        const char *entries[]={"SteamAppId=730",setting,NULL}; denied_entries(entries);
    }
    const char *custom_env[]={"SteamAppId=730","MADEIRA_MIP_CLAMP_AUTO=0",NULL}; denied_entries(custom_env);
    const char *white_env[]={"steamappid=730","MADEIRA_MIP_CLAMP_AUTO= \t ","dxmt_config=",NULL};
    SIZE_T small_bytes; WCHAR *small=environment(white_env,&small_bytes);
    out=apply(game,game,IMAGE_FILE_MACHINE_AMD64,small,small_bytes,option,&out_bytes);
    assert(out && equals(value(out,"dxmt_config"),option)); free(out); free(small); ++cases;
    const char *minimal[]={"SteamAppId=730","Unrelated=keep",NULL};
    small=environment(minimal,&small_bytes);
    /* Unicode opaque values and drive-current-directory entries are untouched. */
    const WCHAR unicode_env[]={ 'S','t','e','a','m','A','p','p','I','d','=','7','3','0',0,
        'X','=',0xd83d,0xde00,0x4e2d,0, '=', 'C', ':', '=', 'C', ':', '\\',0,0 };
    out=apply(game,game,IMAGE_FILE_MACHINE_AMD64,unicode_env,sizeof(unicode_env),option,&out_bytes);
    assert(out && !memcmp(out,unicode_env,sizeof(unicode_env)-sizeof(WCHAR)));
    free(out); ++cases;
    out=apply(game,game,IMAGE_FILE_MACHINE_AMD64,small,small_bytes,option,&out_bytes);
    assert(out && equals(value(out,"dxmt_config"),option)); free(out); ++cases;
    denied(game,game,IMAGE_FILE_MACHINE_AMD64,small,0,option);
    denied(game,game,IMAGE_FILE_MACHINE_AMD64,small,small_bytes-1,option);
    denied(game,game,IMAGE_FILE_MACHINE_AMD64,small,small_bytes-sizeof(WCHAR),option);
    denied(game,game,IMAGE_FILE_MACHINE_AMD64,small,65538,option);
    WCHAR malformed[]={ 'S','t','e','a','m','A','p','p','I','d','=','7','3','0',0,'X','=', 'v' };
    denied(game,game,IMAGE_FILE_MACHINE_AMD64,malformed,sizeof(malformed),option);
    denied(game,game,IMAGE_FILE_MACHINE_AMD64,(const WCHAR *)(uintptr_t)1,small_bytes,option);
    for(int fail=1;fail<=2;++fail) {
        allocations=0; fail_allocation=fail;
        denied(game,game,IMAGE_FILE_MACHINE_AMD64,small,small_bytes,option);
        fail_allocation=0;
    }
    image=path(game); actual=path(game);
    actual.MaximumLength=0; /* Native PS_ATTRIBUTE_IMAGE_NAME is counted, not NUL-sized. */
    out=ios_cs2_texture_environment(&image,&actual,IMAGE_FILE_MACHINE_AMD64,env,bytes,option,&out_bytes);
    assert(out);free(out);++cases;
    image.Length--; out_bytes=123;
    assert(!ios_cs2_texture_environment(&image,&actual,IMAGE_FILE_MACHINE_AMD64,env,bytes,option,&out_bytes) && !out_bytes); ++cases;
    image.Length++; image.MaximumLength=image.Length-1;
    assert(!ios_cs2_texture_environment(&image,&actual,IMAGE_FILE_MACHINE_AMD64,env,bytes,option,&out_bytes)); ++cases;
    image.MaximumLength=image.Length+sizeof(WCHAR); WCHAR *good=image.Buffer; image.Buffer=(WCHAR *)(uintptr_t)1;
    assert(!ios_cs2_texture_environment(&image,&actual,IMAGE_FILE_MACHINE_AMD64,env,bytes,option,&out_bytes)); ++cases;
    image.Buffer=good; image.Buffer[10]=0;
    assert(!ios_cs2_texture_environment(&image,&actual,IMAGE_FILE_MACHINE_AMD64,env,bytes,option,&out_bytes)); ++cases;
    free(image.Buffer); free(actual.Buffer);
    /* Test the 259 UTF-16-unit value boundary, preserving all original settings. */
    char config[400]; const size_t option_len=strlen(option), max_base=259-option_len-1;
    memcpy(config,"DXMT_CONFIG=",12); memset(config+12,'x',max_base); config[12+max_base]=0;
    const char *boundary[]={"SteamAppId=730",config,NULL};
    WCHAR *boundary_env=environment(boundary,&small_bytes);
    out=apply(game,game,IMAGE_FILE_MACHINE_AMD64,boundary_env,small_bytes,option,&out_bytes);
    assert(out); const WCHAR *v=value(out,"dxmt_config"); size_t len=0;while(v[len])++len;assert(len==259);
    free(out);free(boundary_env);++cases;
    config[12+max_base]='x';config[13+max_base]=0;
    denied_entries(boundary);
    /* The input may be read-only: no mutation, including on successful merge. */
    long page=sysconf(_SC_PAGESIZE); void *ro=mmap(NULL,page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    assert(ro!=MAP_FAILED && bytes<(size_t)page);memcpy(ro,env,bytes);assert(!mprotect(ro,page,PROT_READ));
    out=apply(game,game,IMAGE_FILE_MACHINE_AMD64,ro,bytes,option,&out_bytes);
    assert(out && !memcmp(ro,before,bytes));free(out);assert(!munmap(ro,page));++cases;
    /* Safe-read must reject a declared block crossing into inaccessible memory. */
    void *cross=mmap(NULL,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);assert(cross!=MAP_FAILED);
    memcpy((char *)cross+page-bytes,env,bytes);assert(!mprotect((char *)cross+page,page,PROT_NONE));
    denied(game,game,IMAGE_FILE_MACHINE_AMD64,(WCHAR *)((char *)cross+page-bytes),bytes+2,option);
    assert(!munmap(cross,page*2));
    WCHAR *padded=calloc(32768,sizeof(WCHAR));assert(padded);memcpy(padded,env,bytes);
    out=apply(game,game,IMAGE_FILE_MACHINE_AMD64,padded,65536,option,&out_bytes);
    assert(out && out_bytes<65536);free(out);free(padded);++cases;
    pthread_t threads[4]; struct thread_case threaded[4];
    for(int i=0;i<4;++i) {
        threaded[i]=(struct thread_case){env,bytes,i%2 ? option : "d3d11.mipClampAuto=0"};
        assert(!pthread_create(&threads[i],NULL,concurrent_case,&threaded[i]));
    }
    for(int i=0;i<4;++i) assert(!pthread_join(threads[i],NULL));
    cases+=64;
    assert(!memcmp(env,before,bytes));
    free(small);free(before);free(env);
    printf("PASS %d production child-policy cases: CS2-only path/architecture/identity, baseline isolation, UTF-16/custom preservation, bounded fault-safe reads, OOM and length failures\n",cases);
    puts("No Steam/CS2 launch or iPhone memory/performance claim: native device validation is still required.");
    return 0;
}
'''
compiler = os.environ.get('CC') or shutil.which('clang') or shutil.which('cc')
if not compiler:
    raise SystemExit('C compiler required')
with tempfile.TemporaryDirectory(prefix='madeira-cs2-child-env-') as temporary:
    cfile = Path(temporary) / 'child.c'
    binary = Path(temporary) / 'child'
    cfile.write_text(prelude + helper + harness)
    subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', '-pthread', str(cfile), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
