/* Bounded metadata for CreateProcess failures before NtCreateUserProcess.
 * Never emit a command line, an argument, or an absolute private path. */
#ifndef MADEIRA_PROCESS_LOOKUP_TRACE_H
#define MADEIRA_PROCESS_LOOKUP_TRACE_H

static int madeira_lookup_prefix(const WCHAR *value,unsigned length,const WCHAR *prefix)
{
    unsigned i;
    for (i=0;prefix[i];i++)
    {
        unsigned ch;
        if (i>=length) return 0;
        ch=value[i];if (ch>='A' && ch<='Z') ch+='a'-'A';
        if (ch!=(unsigned)prefix[i]) return 0;
    }
    return 1;
}

static void madeira_process_image_lookup_failed(const WCHAR *command,DWORD error)
{
    /* A TLS counter lives in this thread's allocated TLS, not the native PE RX
     * copy. No new shared native-image atomic or LL/SC store is introduced. */
    static __thread unsigned reports;
    const WCHAR *start=command,*base;
    const char *kind="unavailable",*abi;
    char name[65]="unavailable";
    unsigned length=0,i,leaf;
    int quoted=0,valid=1;
    if (reports>=16) { SetLastError(error);return; }
    reports++;
    if (start)
    {
        while (*start==' ' || *start=='\t') start++;
        if (*start=='"') {quoted=1;start++;}
        while (length<512 && start[length] &&
               (quoted ? start[length]!='"' : start[length]!=' ' && start[length]!='\t')) length++;
        if (length && length<512 && (!quoted || start[length]=='"'))
        {
            base=start;
            for (i=0;i<length;i++) if (start[i]=='\\' || start[i]=='/') base=start+i+1;
            leaf=length-(unsigned)(base-start);
            if (!leaf || leaf>=sizeof(name)) valid=0;
            /* An arbitrary command token could itself be sensitive. Only
             * executable-shaped basenames are eligible for attribution. */
            if (valid && (leaf<5 ||
                (!madeira_lookup_prefix(base+leaf-4,4,L".exe") &&
                 !madeira_lookup_prefix(base+leaf-4,4,L".com")))) valid=0;
            for (i=0;valid && i<leaf;i++)
            {
                unsigned ch=base[i];
                if (!((ch>='a' && ch<='z') || (ch>='A' && ch<='Z') ||
                      (ch>='0' && ch<='9') || ch=='_' || ch=='-' || ch=='.')) valid=0;
            }
            if (valid)
            {
                for (i=0;i<leaf;i++) name[i]=(char)base[i];
                name[leaf]=0;
            }
            if (madeira_lookup_prefix(start,length,L"c:\\windows\\system32\\")) kind="system32";
            else if (madeira_lookup_prefix(start,length,L"c:\\windows\\syswow64\\")) kind="syswow64";
            else if (madeira_lookup_prefix(start,length,L"c:\\windows\\sysnative\\")) kind="sysnative";
            else if (madeira_lookup_prefix(start,length,L"c:\\windows\\sysx64\\")) kind="sysx64";
            else if (base==start) kind="bare";
            else kind="other";
        }
    }
#if defined(__arm64ec__)
    abi="arm64ec";
#elif defined(__aarch64__)
    abi="aarch64";
#elif defined(__i386__)
    abi="i386";
#else
    abi="other";
#endif
    ERR("[process-image-lookup-v1] phase=search error=%lu abi=%s path=%s name=%s limit=16-per-thread\n",
        error,abi,kind,name);
    SetLastError(error);
}
#endif
