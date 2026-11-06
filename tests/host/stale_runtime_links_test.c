/* SPDX-License-Identifier: MIT. Real filesystem tests of the production repair. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif

static unsigned race_kind,race_phase,exclusive_calls;
static char race_path[PATH_MAX];
static void write_file(const char *name,const char *contents)
{
    int fd=open(name,O_WRONLY|O_CREAT|O_EXCL,0600);assert(fd>=0);
    size_t bytes=strlen(contents);assert(write(fd,contents,bytes)==(ssize_t)bytes);assert(!close(fd));
}
static void before_exclusive(void)
{
    exclusive_calls++;
    if(race_kind&&!race_phase){
        assert(!unlink(race_path));write_file(race_path,"RACE_CAPTURED_BYTES");race_phase=1;
    }else if(race_kind==2&&race_phase==1){
        write_file(race_path,"RACE_INCOMING_BYTES");race_phase=2;
    }
}
#if defined(__linux__)
static long test_syscall(long number,...)
{
    va_list args;int from,to;const char *old,*name;unsigned flags;
    assert(number==SYS_renameat2);va_start(args,number);
    from=va_arg(args,int);old=va_arg(args,const char *);to=va_arg(args,int);
    name=va_arg(args,const char *);flags=va_arg(args,unsigned);va_end(args);
    before_exclusive();return syscall(number,from,old,to,name,flags);
}
#define syscall test_syscall
#elif defined(__APPLE__)
static int test_renameatx_np(int from,const char *old,int to,const char *name,unsigned flags)
{before_exclusive();return renameatx_np(from,old,to,name,flags);}
#define renameatx_np test_renameatx_np
#endif
#include "StaleRuntimeLinks.h"
#if defined(__linux__)
#undef syscall
#elif defined(__APPLE__)
#undef renameatx_np
#endif

static unsigned cases,fixture_number;
static const char *root;
static const char current_uuid[]="12345678-1234-4567-89ab-1234567890ab";
static const char old_uuid[]="89ABCDEF-0123-4567-89AB-0123456789AB";
struct fixture {char base[PATH_MAX],prefix[PATH_MAX],bundle[PATH_MAX],catalog[PATH_MAX],windows[PATH_MAX];};
static void path(char out[PATH_MAX],const char *format,...)
{
    va_list args;va_start(args,format);int n=vsnprintf(out,PATH_MAX,format,args);va_end(args);
    assert(n>=0&&n<PATH_MAX);
}
static void mkdirs(const char *name)
{
    char copy[PATH_MAX];path(copy,"%s",name);
    for(char *p=copy+1;*p;p++)if(*p=='/'){*p=0;assert(!mkdir(copy,0700)||errno==EEXIST);*p='/';}
    assert(!mkdir(copy,0700)||errno==EEXIST);
}
static struct fixture fixture(void)
{
    struct fixture f;path(f.base,"%s/case-%u",root,fixture_number++);
    path(f.prefix,"%s/prefix",f.base);path(f.bundle,"%s/Application/%s/Madeira.app",f.base,current_uuid);
    path(f.catalog,"%s/x86_64-vcruntime",f.bundle);path(f.windows,"%s/drive_c/windows",f.prefix);
    mkdirs(f.catalog);char leaf[PATH_MAX];path(leaf,"%s/system32",f.windows);mkdirs(leaf);
    path(leaf,"%s/sysx64",f.windows);mkdirs(leaf);return f;
}
static void catalog(const struct fixture *f,const char *leaf)
{
    char name[PATH_MAX];path(name,"%s/%s",f->catalog,leaf);
    write_file(name,"TRUSTED_BUNDLE_BYTES");assert(!chmod(name,0444));
}
static void old_target(const struct fixture *f,const char *leaf,char out[PATH_MAX])
{path(out,"%s/Application/%s/Madeira.app/x86_64-vcruntime/%s",f->base,old_uuid,leaf);}
static void entry(const struct fixture *f,const char *folder,const char *leaf,char out[PATH_MAX])
{path(out,"%s/%s/%s",f->windows,folder,leaf);}
static void same_link(const char *name,const char *target)
{
    char value[PATH_MAX];struct stat st;assert(!lstat(name,&st)&&S_ISLNK(st.st_mode));
    ssize_t n=readlink(name,value,sizeof(value)-1);assert(n>=0&&n<(ssize_t)sizeof(value)-1);value[n]=0;
    assert(!strcmp(value,target));
}
static void same_file(const char *name,const char *contents)
{
    struct stat st;char data[256];assert(!lstat(name,&st)&&S_ISREG(st.st_mode));
    int fd=open(name,O_RDONLY);assert(fd>=0);ssize_t n=read(fd,data,sizeof(data));assert(n>=0&&!close(fd));
    assert((size_t)n==strlen(contents)&&!memcmp(data,contents,(size_t)n));
}
static unsigned quarantines(const struct fixture *f,char selected[PATH_MAX])
{
    unsigned n=0;DIR *dir=opendir(f->prefix);assert(dir);struct dirent *de;
    while((de=readdir(dir)))if(!strncmp(de->d_name,".madeira-stale-runtime-",23)){
        struct stat st;char name[PATH_MAX];path(name,"%s/%s",f->prefix,de->d_name);
        assert(!lstat(name,&st)&&S_ISDIR(st.st_mode)&&(st.st_mode&0777)==0700);
        if(selected)path(selected,"%s",name);
        n++;
    }
    assert(!closedir(dir));return n;
}
static unsigned repair(const struct fixture *f)
{return madeira_repair_stale_runtime_links(f->prefix,f->bundle);}
static void preserved_case(const char *target_suffix,const char *leaf)
{
    struct fixture f=fixture();char name[PATH_MAX],target[PATH_MAX];catalog(&f,leaf);
    entry(&f,"system32",leaf,name);path(target,"%s/%s",f.base,target_suffix);assert(!symlink(target,name));
    assert(!repair(&f));same_link(name,target);assert(!quarantines(&f,NULL));cases++;
}
static void ancestor_case(void)
{
    struct fixture f;
    char target[PATH_MAX],name[PATH_MAX],folder[PATH_MAX],quarantine[PATH_MAX],kept[PATH_MAX];
    /* App containers can grant search but deny enumeration of ancestors.
     * Ordinary relative DLL creation still works under the trusted prefix;
     * requiring O_RDONLY on every ancestor was the failing control. */
    f=fixture();catalog(&f,"ancestor.dll");old_target(&f,"ancestor.dll",target);
    entry(&f,"system32","ancestor.dll",name);assert(!symlink(target,name));
    assert(madeira_stale_target_missing(target)==1);
    path(folder,"%s/system32",f.windows);assert(!chmod(f.base,0111));
    if(geteuid()!=0){errno=0;int enumerating=open(f.base,O_RDONLY|O_DIRECTORY);assert(enumerating<0&&errno==EACCES);}
    int searchable_farm=open(folder,O_RDONLY|O_DIRECTORY);unsigned migrated=repair(&f);
    int installed=searchable_farm<0?-1:openat(searchable_farm,"ancestor.dll",O_WRONLY|O_CREAT|O_EXCL,0600);
    ssize_t installed_bytes=installed<0?-1:write(installed,"NORMAL_INSTALLER_WRITE",22);
    if(installed>=0)assert(!close(installed));
    if(searchable_farm>=0)assert(!close(searchable_farm));
    assert(!chmod(f.base,0700));assert(migrated==1&&installed>=0&&installed_bytes==22);
    same_file(name,"NORMAL_INSTALLER_WRITE");assert(quarantines(&f,quarantine)==1);
    path(kept,"%s/system32/ancestor.dll",quarantine);same_link(kept,target);cases++;
}
int main(int argc,char **argv)
{
    assert(argc==2);root=argv[1];
    /* Capture diagnostics and prove that full roots, UUIDs and private tokens
     * never escape; production's process-global event budget is unchanged. */
    FILE *diagnostics=tmpfile();assert(diagnostics);int saved_stderr=dup(STDERR_FILENO);assert(saved_stderr>=0);
    assert(dup2(fileno(diagnostics),STDERR_FILENO)==STDERR_FILENO);
    assert(!madeira_repair_stale_runtime_links(NULL,NULL));
    assert(!madeira_repair_stale_runtime_links("",root));cases+=2;
    /* Catalog-based selection is intentionally not a hardcoded DLL-name list. */
    struct fixture f=fixture();const char *leaf="Unique_Fixture_Runtime.DLL";
    char target[PATH_MAX],name[PATH_MAX],quarantine[PATH_MAX],kept[PATH_MAX],bundle_file[PATH_MAX];
    char folder[PATH_MAX],outside[PATH_MAX];
    catalog(&f,leaf);old_target(&f,leaf,target);path(bundle_file,"%s/%s",f.catalog,leaf);
    struct stat before,after;assert(!stat(bundle_file,&before));
    for(unsigned folder=0;folder<2;folder++){
        entry(&f,folder?"sysx64":"system32",leaf,name);assert(!symlink(target,name));
        errno=0;assert(stat(name,&after)<0&&errno==ENOENT);same_link(name,target);
    }
    assert(repair(&f)==2&&quarantines(&f,quarantine)==1);
    for(unsigned folder=0;folder<2;folder++){
        entry(&f,folder?"sysx64":"system32",leaf,name);errno=0;assert(lstat(name,&after)<0&&errno==ENOENT);
        path(kept,"%s/%s/%s",quarantine,folder?"sysx64":"system32",leaf);same_link(kept,target);
        write_file(name,"INSTALLER_CREATED_REAL_DLL");same_file(name,"INSTALLER_CREATED_REAL_DLL");
    }
    assert(!repair(&f)&&quarantines(&f,NULL)==1);
    assert(!stat(bundle_file,&after)&&before.st_dev==after.st_dev&&before.st_ino==after.st_ino&&
           before.st_mode==after.st_mode&&before.st_size==after.st_size);
    same_file(bundle_file,"TRUSTED_BUNDLE_BYTES");cases++;
    ancestor_case();
    /* Predicate normalizes only Apple's exact OS-owned /private/var alias. */
    const char *bundle="/var/containers/Bundle/Application/12345678-1234-4567-89ab-1234567890ab/Madeira.app";
    const char *alias="/private/var/containers/Bundle/Application/89ABCDEF-0123-4567-89AB-0123456789AB/Madeira.app/x86_64-vcruntime/genuine.dll";
    assert(madeira_stale_target_owned(alias,bundle,"genuine.dll"));
    assert(madeira_stale_target_owned(alias+8,bundle,"genuine.dll"));
    assert(!madeira_stale_target_owned(alias,bundle,"different.dll"));
    const char *bad[]={"/private/tmp/../var/a.dll","//var/a.dll","relative.dll","/var//a.dll","/var/./a.dll","/var/a.dll/"};
    for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++)assert(!madeira_stale_target_owned(bad[i],bundle,"genuine.dll"));
    cases+=9;
    preserved_case("foreign/Application/89ABCDEF-0123-4567-89AB-0123456789AB/Madeira.app/x86_64-vcruntime/fixture.dll","fixture.dll");
    preserved_case("Application/not-a-valid-UUID/Madeira.app/x86_64-vcruntime/fixture.dll","fixture.dll");
    preserved_case("Application/89ABCDEF-0123-4567-89AB-0123456789AB/Other.app/x86_64-vcruntime/fixture.dll","fixture.dll");
    preserved_case("Application/89ABCDEF-0123-4567-89AB-0123456789AB/Madeira.app/other-farm/fixture.dll","fixture.dll");
    preserved_case("Application/89ABCDEF-0123-4567-89AB-0123456789AB/Madeira.app/x86_64-vcruntime/other.dll","fixture.dll");
    preserved_case("Application/89ABCDEF-0123-4567-89AB-0123456789AB/Madeira.app/../Documents/fixture.dll","fixture.dll");
    /* Live symlinks and ordinary files remain byte-for-byte/inode intact. */
    f=fixture();catalog(&f,"live.dll");entry(&f,"system32","live.dll",name);path(target,"%s/live.dll",f.catalog);
    assert(!symlink(target,name));assert(!repair(&f));same_link(name,target);assert(!quarantines(&f,NULL));cases++;
    entry(&f,"sysx64","live.dll",name);write_file(name,"EXISTING_USER_FILE");assert(!chmod(name,0444));
    assert(!lstat(name,&before)&&!repair(&f)&&!lstat(name,&after)&&before.st_ino==after.st_ino);
    same_file(name,"EXISTING_USER_FILE");assert(!quarantines(&f,NULL));cases++;
    /* A live historical bundle file is also retained: age alone is no reason
     * to move a link which still resolves successfully. */
    f=fixture();catalog(&f,"historical.dll");old_target(&f,"historical.dll",target);
    char historical_parent[PATH_MAX];path(historical_parent,"%s",target);
    *strrchr(historical_parent,'/')=0;mkdirs(historical_parent);write_file(target,"LIVE_HISTORICAL_DLL");
    entry(&f,"system32","historical.dll",name);assert(!symlink(target,name));
    assert(!repair(&f));same_link(name,target);same_file(target,"LIVE_HISTORICAL_DLL");assert(!quarantines(&f,NULL));cases++;
    /* A plausible stale name without a matching regular catalog file is not
     * owned: absence and linked catalog entries both fail closed. */
    f=fixture();old_target(&f,"missing.dll",target);entry(&f,"system32","missing.dll",name);assert(!symlink(target,name));
    assert(!repair(&f));same_link(name,target);assert(!quarantines(&f,NULL));cases++;
    path(bundle_file,"%s/missing.dll",f.catalog);assert(!symlink("absent-catalog-target",bundle_file));
    assert(!repair(&f));same_link(name,target);assert(!quarantines(&f,NULL));cases++;
    /* A lexically owned target may not traverse existing linked parents even
     * if the final lookup reports ENOENT. */
    f=fixture();catalog(&f,"target-parent.dll");old_target(&f,"target-parent.dll",target);
    path(folder,"%s/Application/%s/Madeira.app",f.base,old_uuid);mkdirs(folder);
    path(outside,"%s/missing-foreign-tree",f.base);path(bundle_file,"%s/x86_64-vcruntime",folder);
    assert(!symlink(outside,bundle_file));entry(&f,"system32","target-parent.dll",name);assert(!symlink(target,name));
    assert(!repair(&f));same_link(name,target);same_link(bundle_file,outside);assert(!quarantines(&f,NULL));cases++;
    /* No parent component or farm may redirect traversal into another tree. */
    f=fixture();catalog(&f,"parent.dll");old_target(&f,"parent.dll",target);
    path(folder,"%s/system32",f.windows);assert(!rmdir(folder));
    path(outside,"%s/outside",f.base);mkdirs(outside);path(name,"%s/parent.dll",outside);assert(!symlink(target,name));
    assert(!symlink(outside,folder)&&!repair(&f));same_link(name,target);assert(!quarantines(&f,NULL));cases++;
    f=fixture();catalog(&f,"parent.dll");old_target(&f,"parent.dll",target);entry(&f,"system32","parent.dll",name);assert(!symlink(target,name));
    char alias_prefix[PATH_MAX];path(alias_prefix,"%s/linked-prefix",f.base);assert(!symlink(f.prefix,alias_prefix));
    assert(!madeira_repair_stale_runtime_links(alias_prefix,f.bundle));same_link(name,target);assert(!quarantines(&f,NULL));cases++;
    f=fixture();catalog(&f,"parent.dll");old_target(&f,"parent.dll",target);entry(&f,"system32","parent.dll",name);assert(!symlink(target,name));
    path(outside,"%s/moved-catalog",f.bundle);assert(!rename(f.catalog,outside)&&!symlink(outside,f.catalog));
    assert(!repair(&f));same_link(name,target);assert(!quarantines(&f,NULL));cases++;
    /* On an ordinary CI account, EACCES must remain distinct from ENOENT.
     * Root can bypass directory permissions, so that branch is honestly
     * skipped locally and exercised by the non-root macOS runner. */
    if(geteuid()!=0){
        f=fixture();catalog(&f,"denied.dll");old_target(&f,"denied.dll",target);
        path(folder,"%s",target);*strrchr(folder,'/')=0;mkdirs(folder);write_file(target,"DENIED_BUT_PRESENT");
        entry(&f,"system32","denied.dll",name);assert(!symlink(target,name));assert(!chmod(folder,0000));
        errno=0;assert(stat(name,&after)<0&&errno==EACCES);unsigned attempted=exclusive_calls;
        errno=0;assert(madeira_stale_target_missing(target)==-1&&errno==EACCES);
        assert(!repair(&f)&&exclusive_calls==attempted);same_link(name,target);assert(!quarantines(&f,NULL));
        assert(!chmod(folder,0700));same_file(target,"DENIED_BUT_PRESENT");cases++;
    }
    /* A source replacement between validation and exclusive capture is never
     * mistaken for the old link; restoration never overwrites a new file. */
    for(unsigned kind=1;kind<=2;kind++){
        f=fixture();catalog(&f,"raced.dll");old_target(&f,"raced.dll",target);entry(&f,"system32","raced.dll",name);
        assert(!symlink(target,name));path(race_path,"%s",name);race_kind=kind;race_phase=0;exclusive_calls=0;
        assert(!repair(&f));assert(race_phase==kind&&exclusive_calls>=2);race_kind=0;
        same_file(name,kind==1?"RACE_CAPTURED_BYTES":"RACE_INCOMING_BYTES");
        assert(quarantines(&f,quarantine)==1);path(kept,"%s/system32/raced.dll",quarantine);
        if(kind==1){errno=0;assert(lstat(kept,&after)<0&&errno==ENOENT);}
        else same_file(kept,"RACE_CAPTURED_BYTES");
        cases++;
    }
    /* Exhaust the actual process-global diagnostic budget without limiting
     * correct repair or depending on the production DLL names. */
    f=fixture();
    for(unsigned i=0;i<25;i++){
        char component[64];snprintf(component,sizeof(component),"budget-fixture-%02u.dll",i);
        catalog(&f,component);old_target(&f,component,target);entry(&f,"system32",component,name);assert(!symlink(target,name));
    }
    assert(repair(&f)==25&&quarantines(&f,quarantine)==1);
    for(unsigned i=0;i<25;i++){
        char component[64];snprintf(component,sizeof(component),"budget-fixture-%02u.dll",i);
        old_target(&f,component,target);path(kept,"%s/system32/%s",quarantine,component);same_link(kept,target);
    }
    cases++;
    fflush(stderr);assert(dup2(saved_stderr,STDERR_FILENO)==STDERR_FILENO&&!close(saved_stderr));
    assert(!fseek(diagnostics,0,SEEK_END));long length=ftell(diagnostics);assert(length>=0&&length<16384);
    assert(!fseek(diagnostics,0,SEEK_SET));char *messages=calloc((size_t)length+1,1);assert(messages);
    assert(fread(messages,1,(size_t)length,diagnostics)==(size_t)length);unsigned lines=0;
    for(long i=0;i<length;i++)if(messages[i]=='\n')lines++;
    assert(lines==16&&!strstr(messages,root)&&!strstr(messages,current_uuid)&&
           !strstr(messages,old_uuid)&&!strstr(messages,"PRIVATE_TOKEN"));
    assert(strstr(messages,"[stale-runtime-link-v1]")&&strstr(messages,"relative=windows/"));
    if(geteuid()!=0){
        char unavailable[256];snprintf(unavailable,sizeof(unavailable),"relative=windows/system32/denied.dll reason=target-unavailable action=not-authorized result=unknown code=%d",EACCES);
        assert(strstr(messages,unavailable));
    }
    free(messages);fclose(diagnostics);
    printf("PASS production stale-runtime-link repair: %u contracts, real ENOENT/installer replacement, catalog/bundle preservation, exclusive-capture races and bounded private diagnostics\n",cases);
    return 0;
}
