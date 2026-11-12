#!/usr/bin/env python3
"""Execute pinned and staged Wine named-security bodies with owned API edges.

The native Windows integration companion exercises real registry descriptors.
This host check isolates routing, access rights, outputs, errors, and the source
transaction; it does not impersonate Steam or establish a VAC result.
"""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('registry_security_stage',
        ROOT / 'tools/build/stage-registry-security-views.py')
STAGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STAGER)


def function(text, signature):
    start = text.index(signature)
    end = text.index('{', start) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


PREAMBLE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
typedef uint32_t DWORD,SECURITY_INFORMATION;
typedef wchar_t WCHAR,*LPWSTR;
typedef void *HANDLE,*HKEY,*PSID,*PACL,*PSECURITY_DESCRIPTOR;
typedef enum { SE_UNKNOWN_OBJECT_TYPE=0,SE_FILE_OBJECT=1,SE_SERVICE=2,
 SE_REGISTRY_KEY=4,SE_REGISTRY_WOW64_32KEY=12,SE_REGISTRY_WOW64_64KEY=13 } SE_OBJECT_TYPE;
#define WINAPI
#define TRACE(...) ((void)0)
#define FIXME(...) ((void)0)
#define ERROR_SUCCESS 0
#define ERROR_INVALID_PARAMETER 87
#define ERROR_FILE_NOT_FOUND 2
#define ERROR_ACCESS_DENIED 5
#define ERROR_PRIVILEGE_NOT_HELD 1314
#define ERROR_INVALID_ACL 1336
#define WRITE_OWNER 0x80000
#define WRITE_DAC 0x40000
#define READ_CONTROL 0x20000
#define ACCESS_SYSTEM_SECURITY 0x1000000
#define KEY_WOW64_64KEY 0x100
#define KEY_WOW64_32KEY 0x200
#define OWNER_SECURITY_INFORMATION 1
#define GROUP_SECURITY_INFORMATION 2
#define DACL_SECURITY_INFORMATION 4
#define SACL_SECURITY_INFORMATION 8
#define PROTECTED_DACL_SECURITY_INFORMATION 0x80000000u
#define HKEY_CLASSES_ROOT ((HKEY)(uintptr_t)0x80000000)
#define HKEY_CURRENT_USER ((HKEY)(uintptr_t)0x80000001)
#define HKEY_LOCAL_MACHINE ((HKEY)(uintptr_t)0x80000002)
#define HKEY_USERS ((HKEY)(uintptr_t)0x80000003)
static unsigned opened,closed,set_calls,get_calls;
static DWORD open_error,set_error,get_error,opened_access,received_info;
static HKEY opened_parent;
static WCHAR opened_name[256];
static uintptr_t key_storage;
static unsigned view;
static PSID received_owner,received_group;
static PACL received_dacl,received_sacl;
static PSID owner_value=(void *)(uintptr_t)0x111,group_value=(void *)(uintptr_t)0x222;
static PACL dacl_value=(void *)(uintptr_t)0x333,sacl_value=(void *)(uintptr_t)0x444;
static PSECURITY_DESCRIPTOR descriptor_value=(void *)(uintptr_t)0x555;
static DWORD RegOpenKeyExW(HKEY parent,const WCHAR *name,DWORD options,DWORD access,HKEY *result) {
 assert(!options);opened++;opened_access=access;opened_parent=parent;
 assert(wcslen(name)<256);wcscpy(opened_name,name);
 if(open_error)return open_error;
 assert((access&(KEY_WOW64_64KEY|KEY_WOW64_32KEY))!=(KEY_WOW64_64KEY|KEY_WOW64_32KEY));
 view=(access&KEY_WOW64_64KEY)?64:(access&KEY_WOW64_32KEY)?32:0;
 *result=&key_storage;return 0;
}
static DWORD RegCloseKey(HKEY key) { assert(key==&key_storage);closed++;return 0; }
static DWORD SetSecurityInfo(HANDLE h,SE_OBJECT_TYPE type,SECURITY_INFORMATION info,
 PSID owner,PSID group,PACL dacl,PACL sacl) {
 assert(h==&key_storage&&type==SE_REGISTRY_KEY);set_calls++;received_info=info;
 received_owner=owner;received_group=group;received_dacl=dacl;received_sacl=sacl;
 return set_error;
}
static DWORD GetSecurityInfo(HANDLE h,SE_OBJECT_TYPE type,SECURITY_INFORMATION info,
 PSID *owner,PSID *group,PACL *dacl,PACL *sacl,PSECURITY_DESCRIPTOR *descriptor) {
 assert(h==&key_storage&&type==SE_REGISTRY_KEY);get_calls++;received_info=info;
 if(get_error)return get_error;
 if(owner)*owner=owner_value;if(group)*group=group_value;
 if(dacl)*dacl=dacl_value;if(sacl)*sacl=sacl_value;
 if(descriptor)*descriptor=descriptor_value;return 0;
}
static DWORD get_security_service(const WCHAR *name,DWORD access,HANDLE *handle) {
 (void)name;(void)access;(void)handle;abort();
}
static DWORD get_security_file(const WCHAR *name,DWORD access,HANDLE *handle) {
 (void)name;(void)access;(void)handle;abort();
}
static void CloseServiceHandle(HANDLE h) {(void)h;abort();}
static void CloseHandle(HANDLE h) {(void)h;abort();}
'''

MAIN = r'''
static void reset(void) {
 opened=closed=set_calls=get_calls=0;open_error=set_error=get_error=0;
 opened_access=received_info=0;opened_parent=NULL;opened_name[0]=0;view=999;
 received_owner=received_group=received_dacl=received_sacl=NULL;
}
int main(int argc,char **argv) {
 assert(argc==2);int staged=atoi(argv[1]);
 WCHAR name[]=L"MACHINE\\Software\\MadeiraOwnedRegistrySecurityTest";
 reset();DWORD rc=SetNamedSecurityInfoW(name,SE_REGISTRY_WOW64_64KEY,
  DACL_SECURITY_INFORMATION,NULL,NULL,dacl_value,NULL);
 if(!staged) {
  assert(rc==ERROR_SUCCESS&&!opened&&!set_calls&&!closed);
  PSECURITY_DESCRIPTOR descriptor=(void *)(uintptr_t)0xabc;
  rc=GetNamedSecurityInfoW(name,SE_REGISTRY_WOW64_64KEY,DACL_SECURITY_INFORMATION,
      NULL,NULL,NULL,NULL,&descriptor);
  assert(rc==ERROR_SUCCESS&&!opened&&!get_calls&&!descriptor);
  puts("PASS failing-before reproduced: pinned type13 returns success without opening, setting or querying the registry key");
  return 0;
 }
 assert(!rc&&opened==1&&closed==1&&set_calls==1&&view==64);
 const SE_OBJECT_TYPE types[]={SE_REGISTRY_KEY,SE_REGISTRY_WOW64_32KEY,SE_REGISTRY_WOW64_64KEY};
 const DWORD view_flags[]={0,KEY_WOW64_32KEY,KEY_WOW64_64KEY};
 for(unsigned t=0;t<3;t++)for(DWORD mask=1;mask<16;mask++) {
  reset();rc=SetNamedSecurityInfoW(name,types[t],mask,
      owner_value,group_value,dacl_value,sacl_value);
  DWORD access=((mask&3)?WRITE_OWNER:0)|((mask&4)?WRITE_DAC:0)|
      ((mask&8)?ACCESS_SYSTEM_SECURITY:0)|view_flags[t];
  assert(!rc&&opened==1&&set_calls==1&&closed==1&&opened_access==access);
  assert(opened_parent==HKEY_LOCAL_MACHINE&&!wcscmp(opened_name,L"Software\\MadeiraOwnedRegistrySecurityTest"));
  assert(received_info==mask&&received_owner==owner_value&&received_group==group_value&&
      received_dacl==dacl_value&&received_sacl==sacl_value);
  reset();PSID owner=NULL,group=NULL;PACL dacl=NULL,sacl=NULL;PSECURITY_DESCRIPTOR descriptor=NULL;
  rc=GetNamedSecurityInfoW(name,types[t],mask,&owner,&group,&dacl,&sacl,&descriptor);
  access=((mask&7)?READ_CONTROL:0)|((mask&8)?ACCESS_SYSTEM_SECURITY:0)|view_flags[t];
  assert(!rc&&opened==1&&get_calls==1&&closed==1&&opened_access==access);
  assert(received_info==mask&&owner==owner_value&&group==group_value&&dacl==dacl_value&&
      sacl==sacl_value&&descriptor==descriptor_value);
 }
 for(unsigned t=0;t<3;t++) {
  reset();open_error=ERROR_FILE_NOT_FOUND;
  rc=SetNamedSecurityInfoW(name,types[t],DACL_SECURITY_INFORMATION,NULL,NULL,NULL,NULL);
  assert(rc==ERROR_FILE_NOT_FOUND&&opened==1&&!set_calls&&!closed);
  reset();open_error=ERROR_ACCESS_DENIED;PSECURITY_DESCRIPTOR descriptor=(void *)(uintptr_t)0xabc;
  rc=GetNamedSecurityInfoW(name,types[t],DACL_SECURITY_INFORMATION,NULL,NULL,NULL,NULL,&descriptor);
  assert(rc==ERROR_ACCESS_DENIED&&opened==1&&!get_calls&&!closed&&descriptor==(void *)(uintptr_t)0xabc);
  reset();set_error=ERROR_PRIVILEGE_NOT_HELD;
  rc=SetNamedSecurityInfoW(name,types[t],SACL_SECURITY_INFORMATION,NULL,NULL,NULL,sacl_value);
  assert(rc==ERROR_PRIVILEGE_NOT_HELD&&set_calls==1&&closed==1);
  reset();set_error=ERROR_INVALID_ACL;
  rc=SetNamedSecurityInfoW(name,types[t],DACL_SECURITY_INFORMATION,NULL,NULL,dacl_value,NULL);
  assert(rc==ERROR_INVALID_ACL&&set_calls==1&&closed==1);
  reset();get_error=ERROR_ACCESS_DENIED;descriptor=(void *)(uintptr_t)0xabc;
  rc=GetNamedSecurityInfoW(name,types[t],DACL_SECURITY_INFORMATION,NULL,NULL,NULL,NULL,&descriptor);
  assert(rc==ERROR_ACCESS_DENIED&&get_calls==1&&closed==1&&descriptor==(void *)(uintptr_t)0xabc);
  reset();rc=SetNamedSecurityInfoW(NULL,types[t],DACL_SECURITY_INFORMATION,NULL,NULL,NULL,NULL);
  assert(rc==ERROR_INVALID_PARAMETER&&!opened);
  rc=GetNamedSecurityInfoW(name,types[t],DACL_SECURITY_INFORMATION,NULL,NULL,NULL,NULL,NULL);
  assert(rc==ERROR_INVALID_PARAMETER&&!opened);
  PSID owner=NULL;
  rc=GetNamedSecurityInfoW(name,types[t],DACL_SECURITY_INFORMATION,&owner,NULL,NULL,NULL,NULL);
  assert(rc==ERROR_INVALID_PARAMETER&&!opened);
 }
 reset();DWORD flags=DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION;
 rc=SetNamedSecurityInfoW(name,SE_REGISTRY_WOW64_64KEY,flags,NULL,NULL,NULL,NULL);
 assert(!rc&&received_info==flags&&opened_access==(WRITE_DAC|KEY_WOW64_64KEY));
 puts("PASS staged production named-security APIs: 32/64/default views, rights, unchanged descriptors, actual operation/errors, outputs and handle lifetime");
}
'''


with tempfile.TemporaryDirectory(prefix='madeira-registry-security-check-') as temporary:
    temp = Path(temporary)
    STAGER.stage(temp / 'staged', ROOT / 'wine')
    before = (ROOT / 'wine' / STAGER.SOURCE).read_bytes()
    for mode, source in ((0, ROOT / 'wine'), (1, temp / 'staged')):
        text = (source / STAGER.SOURCE).read_text()
        bodies = '\n'.join(function(text, signature) for signature in (
            'static DWORD get_security_regkey(', 'DWORD WINAPI SetNamedSecurityInfoW(',
            'DWORD WINAPI GetNamedSecurityInfoW('))
        c_file = temp / f'registry-{mode}.c'
        binary = temp / f'registry-{mode}'
        c_file.write_text(PREAMBLE + bodies + MAIN)
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-Wno-misleading-indentation', '-fsanitize=address,undefined',
                        str(c_file), '-o', str(binary)], check=True)
        subprocess.run([str(binary), str(mode)], check=True)
    owned_source = temp / 'owned-wine'
    (owned_source / STAGER.SOURCE).parent.mkdir(parents=True)
    shutil.copyfile(ROOT / 'wine' / STAGER.SOURCE, owned_source / STAGER.SOURCE)
    STAGER.apply(temp / 'transaction', owned_source)
    assert (owned_source / STAGER.SOURCE).read_bytes() != before
    STAGER.restore(temp / 'transaction')
    STAGER.restore(temp / 'transaction')
    assert (owned_source / STAGER.SOURCE).read_bytes() == before
    STAGER.apply(temp / 'tamper-transaction', owned_source)
    with (owned_source / STAGER.SOURCE).open('a') as output:
        output.write('\n/* concurrent unowned source mutation */\n')
    try:
        STAGER.restore(temp / 'tamper-transaction')
        raise AssertionError('source mutation was discarded')
    except ValueError:
        pass
    assert (ROOT / 'wine' / STAGER.SOURCE).read_bytes() == before
    print('PASS registry security stage: reviewed input/output hashes, transactional restoration, duplicate restore and refusal to overwrite unrelated changes')
