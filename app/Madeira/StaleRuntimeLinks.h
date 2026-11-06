/* SPDX-License-Identifier: GPL-3.0-or-later
 * Pre-Wine migration of obsolete Madeira bundle-farm links only. The caller
 * owns prefix quiescence. No file contents, installer result or Wine file API
 * is changed: a proven stale link is retained in a new private quarantine. */
#ifndef MADEIRA_STALE_RUNTIME_LINKS_H
#define MADEIRA_STALE_RUNTIME_LINKS_H
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static inline int madeira_stale_normalize(const char *input,char out[PATH_MAX])
{
    const char *start,*p;size_t length;
    if(!input||input[0]!='/'||input[1]=='/')return 0;
    start=input;
    if(!strncmp(input,"/private/var/",13)||!strcmp(input,"/private/var"))start=input+8;
    length=strlen(start);if(length<2||length>=PATH_MAX)return 0;
    for(p=start+1;*p;){
        const char *end=strchr(p,'/');size_t n=end?(size_t)(end-p):strlen(p);
        if(!n||(n==1&&p[0]=='.')||(n==2&&p[0]=='.'&&p[1]=='.'))return 0;
        for(size_t i=0;i<n;i++)if((unsigned char)p[i]<32||(unsigned char)p[i]==127)return 0;
        if(!end)break;
        p=end+1;if(!*p)return 0;
    }
    memcpy(out,start,length+1);return 1;
}
static inline int madeira_stale_uuid(const char *text,size_t bytes)
{
    if(bytes!=36)return 0;
    for(size_t i=0;i<bytes;i++){
        unsigned char c=(unsigned char)text[i];
        if(i==8||i==13||i==18||i==23){if(c!='-')return 0;}
        else if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F')))return 0;
    }
    return 1;
}
static inline int madeira_stale_leaf(const char *leaf)
{
    size_t n;if(!leaf||(n=strlen(leaf))<5||n>240||leaf[0]=='.')return 0;
    for(size_t i=0;i<n;i++){
        unsigned char c=(unsigned char)leaf[i];
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='-'||c=='.'))return 0;
    }
    return leaf[n-4]=='.'&&(leaf[n-3]=='d'||leaf[n-3]=='D')&&
        (leaf[n-2]=='l'||leaf[n-2]=='L')&&(leaf[n-1]=='l'||leaf[n-1]=='L');
}
/* A historical link belongs to this exact bundle catalog and container root,
 * regardless of the old UUID. No Documents/foreign-farm link is inferred. */
static inline int madeira_stale_target_owned(const char *target,const char *bundle,const char *leaf)
{
    char current[PATH_MAX],old[PATH_MAX],expected[PATH_MAX];
    char *app,*uuid;size_t root,app_size;int n;
    if(!madeira_stale_leaf(leaf)||!madeira_stale_normalize(bundle,current)||
       !madeira_stale_normalize(target,old))return 0;
    app=strrchr(current,'/');if(!app||!(app_size=strlen(app+1))||app_size<5||strcmp(app+1+app_size-4,".app"))return 0;
    *app=0;uuid=strrchr(current,'/');
    if(!uuid||!madeira_stale_uuid(uuid+1,strlen(uuid+1)))return 0;
    root=(size_t)(uuid-current);
    if(strncmp(old,current,root)||old[root]!='/'||strlen(old+root+1)<37||
       !madeira_stale_uuid(old+root+1,36)||old[root+37]!='/')return 0;
    n=snprintf(expected,sizeof(expected),"/%s/x86_64-vcruntime/%s",app+1,leaf);
    return n>0&&(size_t)n<sizeof(expected)&&!strcmp(old+root+37,expected);
}
/* Every supplied path component is opened without following a link. Darwin's
 * OS-owned /var alias is the only normalized exception. */
static inline int madeira_stale_open_directory(const char *path)
{
    char normalized[PATH_MAX],*part,*end;int fd,next;
    if(!madeira_stale_normalize(path,normalized)){errno=EINVAL;return -1;}
#if defined(__APPLE__)
    if(!strncmp(normalized,"/var/",5)){
        fd=open("/private/var",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);part=normalized+5;
    }else
#endif
    {fd=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);part=normalized+1;}
    if(fd<0)return -1;
    for(;;){
        end=strchr(part,'/');if(end)*end=0;
        next=openat(fd,part,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);close(fd);
        if(next<0)return -1;
        fd=next;if(!end)return fd;part=end+1;
    }
}
/* Check absence without following any target-parent or target-leaf link.
 * ENOENT is proof of absence; permissions and other errors are not proof. */
static inline int madeira_stale_target_missing(const char *target)
{
    char path[PATH_MAX],leaf[256];char *last;struct stat st;int parent,result,error;
    if(!madeira_stale_normalize(target,path)||(last=strrchr(path,'/'))==NULL||
       !madeira_stale_leaf(last+1))return 0;
    memcpy(leaf,last+1,strlen(last+1)+1);*last=0;
    parent=madeira_stale_open_directory(path);
    if(parent<0)return errno==ENOENT;
    result=fstatat(parent,leaf,&st,AT_SYMLINK_NOFOLLOW);error=errno;close(parent);
    return result<0&&error==ENOENT;
}
static inline int madeira_stale_same_object(const struct stat *a,const struct stat *b)
{
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode&&
        a->st_size==b->st_size&&a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&a->st_nlink==b->st_nlink;
}
static inline int madeira_stale_same_before(const struct stat *a,const struct stat *b)
{
    if(!madeira_stale_same_object(a,b))return 0;
#if defined(__APPLE__)
    return a->st_mtimespec.tv_sec==b->st_mtimespec.tv_sec&&a->st_mtimespec.tv_nsec==b->st_mtimespec.tv_nsec&&
        a->st_ctimespec.tv_sec==b->st_ctimespec.tv_sec&&a->st_ctimespec.tv_nsec==b->st_ctimespec.tv_nsec;
#else
    return a->st_mtim.tv_sec==b->st_mtim.tv_sec&&a->st_mtim.tv_nsec==b->st_mtim.tv_nsec&&
        a->st_ctim.tv_sec==b->st_ctim.tv_sec&&a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
#endif
}
static inline int madeira_stale_same_directory(int parent,const char *name,int held)
{
    struct stat a,b;
    return !fstatat(parent,name,&a,AT_SYMLINK_NOFOLLOW)&&S_ISDIR(a.st_mode)&&!fstat(held,&b)&&
        a.st_dev==b.st_dev&&a.st_ino==b.st_ino;
}
static inline int madeira_stale_readlink(int fd,const char *name,char out[PATH_MAX])
{
    ssize_t n=readlinkat(fd,name,out,PATH_MAX-1);
    if(n<=0||n>=PATH_MAX-1)return 0;
    out[n]=0;return 1;
}
/* No POSIX rename()/unlink() fallback: neither can safely avoid overwriting a
 * concurrently installed file. Unsupported hosts leave the link untouched. */
static inline int madeira_stale_move_exclusive(int from,const char *old,int to,const char *name)
{
#if defined(__APPLE__)
    return renameatx_np(from,old,to,name,RENAME_EXCL);
#elif defined(__linux__) && defined(SYS_renameat2)
    return (int)syscall(SYS_renameat2,from,old,to,name,1u /* RENAME_NOREPLACE */);
#else
    (void)from;(void)old;(void)to;(void)name;errno=ENOTSUP;return -1;
#endif
}
static inline void madeira_stale_note(const char *folder,const char *leaf,const char *reason,
                                     const char *action,const char *result,int error,const char *quarantine)
{
    static unsigned logged;
    if(__atomic_fetch_add(&logged,1,__ATOMIC_RELAXED)>=16)return;
    fprintf(stderr,"[stale-runtime-link-v1] relative=windows/%s/%s reason=%s action=%s result=%s code=%d quarantine=%s\n",
        folder,leaf,reason,action,result,error,quarantine?quarantine:"-");
}
/* mkdtemp creates the only directory this invocation adopts. Bind it back to
 * the held prefix fd before moving anything, then retain all evidence. */
static inline int madeira_stale_quarantine(const char *prefix,int root,char name[80])
{
    char path[PATH_MAX];struct stat created,held;int fd,n;
    n=snprintf(path,sizeof(path),"%s/.madeira-stale-runtime-XXXXXX",prefix);
    if(n<0||(size_t)n>=sizeof(path)){errno=ENAMETOOLONG;return -1;}
    if(!mkdtemp(path))return -1;
    const char *leaf=strrchr(path,'/');if(!leaf){errno=EINVAL;return -1;}leaf++;
    if(lstat(path,&created)||!S_ISDIR(created.st_mode)||
       (fd=openat(root,leaf,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW))<0)return -1;
    if(fstat(fd,&held)||created.st_dev!=held.st_dev||created.st_ino!=held.st_ino||
       held.st_uid!=geteuid()||(held.st_mode&0777)!=0700){close(fd);errno=ESTALE;return -1;}
    if(strlen(leaf)>=80){close(fd);errno=ENAMETOOLONG;return -1;}
    memcpy(name,leaf,strlen(leaf)+1);return fd;
}
static inline unsigned madeira_repair_stale_runtime_links(const char *prefix,const char *bundle)
{
    static const char *const folders[]={"system32","sysx64"};
    int root=-1,drive=-1,windows=-1,bundle_fd=-1,catalog=-1,quarantine=-1;
    unsigned repaired=0;char quarantine_name[80]={0};
    root=madeira_stale_open_directory(prefix);bundle_fd=madeira_stale_open_directory(bundle);
    if(root<0||bundle_fd<0)goto done;
    drive=openat(root,"drive_c",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(drive<0)goto done;
    windows=openat(drive,"windows",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    catalog=openat(bundle_fd,"x86_64-vcruntime",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(windows<0||catalog<0)goto done;
    for(unsigned folder=0;folder<sizeof(folders)/sizeof(folders[0]);folder++){
        int farm=openat(windows,folders[folder],O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW),qfarm=-1;
        DIR *entries;struct dirent *entry;
        if(farm<0)continue;
        int enumeration=openat(catalog,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        if(enumeration<0){close(farm);continue;}
        entries=fdopendir(enumeration);if(!entries){close(enumeration);close(farm);continue;}
        while((entry=readdir(entries))){
            const char *leaf=entry->d_name;char target[PATH_MAX],again[PATH_MAX];
            struct stat source,check,current,current_check,moved;
            if(!madeira_stale_leaf(leaf)||fstatat(catalog,leaf,&current,AT_SYMLINK_NOFOLLOW)||
               !S_ISREG(current.st_mode)||current.st_size<=0||
               fstatat(farm,leaf,&source,AT_SYMLINK_NOFOLLOW)||!S_ISLNK(source.st_mode)||
               !madeira_stale_readlink(farm,leaf,target)||!madeira_stale_target_owned(target,bundle,leaf))continue;
            if(!madeira_stale_target_missing(target))continue;
            if(!madeira_stale_same_directory(root,"drive_c",drive)||
               !madeira_stale_same_directory(drive,"windows",windows)||
               !madeira_stale_same_directory(windows,folders[folder],farm)||
               !madeira_stale_same_directory(bundle_fd,"x86_64-vcruntime",catalog)||
               fstatat(catalog,leaf,&current_check,AT_SYMLINK_NOFOLLOW)||
               !madeira_stale_same_before(&current,&current_check)||
               fstatat(farm,leaf,&check,AT_SYMLINK_NOFOLLOW)||!madeira_stale_same_before(&source,&check)||
               !madeira_stale_readlink(farm,leaf,again)||strcmp(target,again)||
               !madeira_stale_target_missing(target))continue;
            if(quarantine<0)quarantine=madeira_stale_quarantine(prefix,root,quarantine_name);
            if(quarantine<0){madeira_stale_note(folders[folder],leaf,"owned-dangling","kept","quarantine-failed",errno,NULL);continue;}
            if(qfarm<0){
                if(mkdirat(quarantine,folders[folder],0700)||
                   (qfarm=openat(quarantine,folders[folder],O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW))<0){
                    madeira_stale_note(folders[folder],leaf,"owned-dangling","kept","quarantine-failed",errno,quarantine_name);continue;
                }
            }
            if(madeira_stale_move_exclusive(farm,leaf,qfarm,leaf)){
                madeira_stale_note(folders[folder],leaf,"owned-dangling","kept","move-failed",errno,quarantine_name);continue;
            }
            if(!fstatat(qfarm,leaf,&moved,AT_SYMLINK_NOFOLLOW)&&madeira_stale_same_object(&source,&moved)&&
               madeira_stale_readlink(qfarm,leaf,again)&&!strcmp(target,again)&&
               madeira_stale_target_missing(target)&&
               !fstatat(catalog,leaf,&current_check,AT_SYMLINK_NOFOLLOW)&&
               madeira_stale_same_before(&current,&current_check)&&
               madeira_stale_same_directory(bundle_fd,"x86_64-vcruntime",catalog)&&
               madeira_stale_same_directory(root,"drive_c",drive)&&
               madeira_stale_same_directory(drive,"windows",windows)&&
               madeira_stale_same_directory(windows,folders[folder],farm)){
                repaired++;madeira_stale_note(folders[folder],leaf,"owned-dangling","quarantined","ok",0,quarantine_name);
            }else{
                int error=errno;
                if(!madeira_stale_move_exclusive(qfarm,leaf,farm,leaf))
                    madeira_stale_note(folders[folder],leaf,"concurrent-change","restored","kept",0,quarantine_name);
                else madeira_stale_note(folders[folder],leaf,"concurrent-change","preserved","quarantine-retained",error,quarantine_name);
            }
        }
        closedir(entries);if(qfarm>=0)close(qfarm);close(farm);
    }
done:
    if(quarantine>=0)close(quarantine);
    if(catalog>=0)close(catalog);
    if(bundle_fd>=0)close(bundle_fd);
    if(windows>=0)close(windows);
    if(drive>=0)close(drive);
    if(root>=0)close(root);
    return repaired;
}
#endif
