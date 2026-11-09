#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright 2026 125hz
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Review-only policy regression; compiles unchanged pinned function bodies.

Public Windows chain structures and constants are supplied to the real BASE
policy body. This tests policy mapping, not certificate parsing, chain building,
real WinVerifyTrust/HASH_ONLY behavior, trust stores, or any Valve subject.
"""
from pathlib import Path
import argparse
import os
import re
import shutil
import subprocess
import tempfile

OWN = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--source-root', type=Path, default=OWN)
args = parser.parse_args()
wine = args.source_root.resolve() / 'wine'
pinned = 'df1c5ea51e194937ac204bc3120922dc56a61bec'
assert subprocess.check_output(['git', '-C', str(wine), 'rev-parse', 'HEAD'], text=True).strip() == pinned
chain = (wine / 'dlls/crypt32/chain.c').read_text()
headers = (wine / 'include/wincrypt.h').read_text() + '\n' + (wine / 'include/winerror.h').read_text()

def function(source, marker):
    start = source.index(marker)
    end = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'

prefix = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t DWORD;
typedef int32_t LONG;
typedef int BOOL;
typedef const char *LPCSTR;
#define WINAPI
#define TRUE 1
#define NO_ERROR 0
#define _HRESULT_TYPEDEF_(x) ((DWORD)(x))
/* Only the public fields used by these pure policy functions are modeled.
 * No fake verifier/chain-building implementation supplies a policy result. */
typedef struct { DWORD dwErrorStatus, dwInfoStatus; } CERT_TRUST_STATUS;
typedef struct { CERT_TRUST_STATUS TrustStatus; } Element;
typedef struct { CERT_TRUST_STATUS TrustStatus; DWORD cElement; Element **rgpElement; } Simple;
typedef struct { CERT_TRUST_STATUS TrustStatus; DWORD cChain; Simple **rgpChain; } Context;
typedef const Context *PCCERT_CHAIN_CONTEXT;
typedef struct { DWORD cbSize, dwFlags; void *pvExtraPolicyPara; } CERT_CHAIN_POLICY_PARA, *PCERT_CHAIN_POLICY_PARA;
typedef struct { DWORD cbSize, dwError; LONG lChainIndex, lElementIndex; void *pvExtraPolicyStatus; } CERT_CHAIN_POLICY_STATUS, *PCERT_CHAIN_POLICY_STATUS;
'''
constants = (
    'CERT_TRUST_IS_NOT_SIGNATURE_VALID', 'CERT_TRUST_IS_CYCLIC',
    'CERT_TRUST_IS_UNTRUSTED_ROOT', 'CERT_TRUST_IS_NOT_TIME_VALID',
    'CERT_TRUST_IS_NOT_VALID_FOR_USAGE', 'CERT_TRUST_HAS_NOT_SUPPORTED_CRITICAL_EXT',
    'CERT_TRUST_IS_PARTIAL_CHAIN', 'CERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG',
    'CERT_CHAIN_POLICY_IGNORE_NOT_TIME_VALID_FLAG', 'CERT_CHAIN_POLICY_IGNORE_WRONG_USAGE_FLAG',
    'CERT_CHAIN_POLICY_IGNORE_NOT_SUPPORTED_CRITICAL_EXT_FLAG', 'TRUST_E_CERT_SIGNATURE',
    'CERT_E_CHAINING', 'CERT_E_UNTRUSTEDROOT', 'CERT_E_EXPIRED',
    'CERT_E_WRONG_USAGE', 'CERT_E_CRITICAL',
)
for name in constants:
    definition = re.search(r'^#define[ \t]+' + re.escape(name) + r'[ \t]+([^\n]+)', headers, re.M)
    assert definition, name
    prefix += '#define ' + name + ' ' + definition.group(1) + '\n'

harness = r'''
#define P CERT_TRUST_IS_PARTIAL_CHAIN
#define A CERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG
static unsigned tests;
static void check(const char *name, DWORD error, DWORD flags, int null_para,
                  unsigned partial_mask, DWORD expected, LONG chain_idx, LONG element_idx) {
    Element elements[3][2]; Element *element_ptrs[3][2];
    Simple simples[3]; Simple *chain_ptrs[3]; Context context;
    memset(elements,0,sizeof(elements)); memset(simples,0,sizeof(simples)); memset(&context,0,sizeof(context));
    for (unsigned i=0;i<3;i++) {
        for(unsigned j=0;j<2;j++) element_ptrs[i][j]=&elements[i][j];
        simples[i].TrustStatus.dwErrorStatus=(partial_mask&(1u<<i))?P:0;
        simples[i].cElement=2; simples[i].rgpElement=element_ptrs[i]; chain_ptrs[i]=&simples[i];
    }
    /* A real partial chain is chain-only: NO element gets its partial bit. */
    elements[2][1].TrustStatus.dwErrorStatus=error&~P;
    context.TrustStatus.dwErrorStatus=error; context.cChain=3; context.rgpChain=chain_ptrs;
    CERT_CHAIN_POLICY_PARA para={sizeof(para),flags,(void*)(uintptr_t)0x1234};
    struct { uint64_t before; CERT_CHAIN_POLICY_STATUS value; uint64_t after; } guarded;
    memset(&guarded,0x5a,sizeof(guarded));
    guarded.before=UINT64_C(0xfeed1234f00d5678); guarded.after=UINT64_C(0x89ab7654cdef3210);
    guarded.value.cbSize=sizeof(guarded.value); guarded.value.pvExtraPolicyStatus=(void*)(uintptr_t)0x5678;
    unsigned char original_elements[sizeof(elements)],original_simples[sizeof(simples)],original_context[sizeof(context)],original_para[sizeof(para)];
    memcpy(original_elements,elements,sizeof(elements)); memcpy(original_simples,simples,sizeof(simples));
    memcpy(original_context,&context,sizeof(context)); memcpy(original_para,&para,sizeof(para));
    BOOL result=verify_base_policy((LPCSTR)(uintptr_t)1,&context,null_para?NULL:&para,&guarded.value);
    if(result!=TRUE || guarded.value.dwError!=expected || guarded.value.lChainIndex!=chain_idx || guarded.value.lElementIndex!=element_idx) {
        fprintf(stderr,"%s candidate=%d got bool=%d error=%08x indices=%d/%d expected=%08x %d/%d\n",
                name,EXPECT_FIX,result,guarded.value.dwError,guarded.value.lChainIndex,guarded.value.lElementIndex,expected,chain_idx,element_idx);
        assert(0);
    }
    assert(guarded.before==UINT64_C(0xfeed1234f00d5678)&&guarded.after==UINT64_C(0x89ab7654cdef3210));
    assert(guarded.value.cbSize==sizeof(guarded.value)&&guarded.value.pvExtraPolicyStatus==(void*)(uintptr_t)0x5678);
    assert(!memcmp(original_elements,elements,sizeof(elements))&&!memcmp(original_simples,simples,sizeof(simples)));
    assert(!memcmp(original_context,&context,sizeof(context))&&!memcmp(original_para,&para,sizeof(para)));
    tests++;
}
static void partial(const char *name,DWORD other,DWORD flags,int null_para,unsigned mask) {
    DWORD expected=EXPECT_FIX?CERT_E_CHAINING:NO_ERROR;
    LONG idx=-1;
    if(EXPECT_FIX) for(unsigned i=0;i<3;i++) if(mask&(1u<<i)){idx=(LONG)i;break;}
    check(name,P|other,flags,null_para,mask,expected,idx,-1);
}
int main(void) {
    check("complete valid",0,0,0,0,NO_ERROR,-1,-1);
    check("complete valid NULL policy",0,0,1,0,NO_ERROR,-1,-1);
    partial("partial NULL policy",0,0,1,2);
    partial("partial explicit flags0",0,0,0,2);
    partial("first of two partial chains",0,0,0,6);
    partial("first chain partial",0,0,0,1);
    partial("last chain partial",0,0,0,4);
    partial("aggregate-only fallback",0,0,0,0);
    check("caller allows partial CA",P,A,0,2,NO_ERROR,-1,-1);
    check("caller allows untrusted root",CERT_TRUST_IS_UNTRUSTED_ROOT,A,0,0,NO_ERROR,-1,-1);
    check("caller allows CA with partial+root",P|CERT_TRUST_IS_UNTRUSTED_ROOT,A,0,2,NO_ERROR,-1,-1);
    const struct {DWORD bit,result;} errors[]={
        {CERT_TRUST_IS_NOT_SIGNATURE_VALID,TRUST_E_CERT_SIGNATURE},
        {CERT_TRUST_IS_CYCLIC,CERT_E_CHAINING},
        {CERT_TRUST_IS_UNTRUSTED_ROOT,CERT_E_UNTRUSTEDROOT},
        {CERT_TRUST_IS_NOT_TIME_VALID,CERT_E_EXPIRED},
        {CERT_TRUST_IS_NOT_VALID_FOR_USAGE,CERT_E_WRONG_USAGE},
        {CERT_TRUST_HAS_NOT_SUPPORTED_CRITICAL_EXT,CERT_E_CRITICAL},
    };
    for(unsigned i=0;i<sizeof(errors)/sizeof(errors[0]);i++) {
        LONG element=errors[i].bit==CERT_TRUST_IS_CYCLIC?-1:1;
        check("existing error unchanged",errors[i].bit,0,0,0,errors[i].result,2,element);
        check("existing error precedes partial",P|errors[i].bit,0,0,2,errors[i].result,2,element);
    }
    check("allow CA never ignores signature",P|CERT_TRUST_IS_NOT_SIGNATURE_VALID,A,0,2,TRUST_E_CERT_SIGNATURE,2,1);
    check("allow CA never ignores cycle",P|CERT_TRUST_IS_CYCLIC,A,0,2,CERT_E_CHAINING,2,-1);
    partial("ignored time still incomplete",CERT_TRUST_IS_NOT_TIME_VALID,CERT_CHAIN_POLICY_IGNORE_NOT_TIME_VALID_FLAG,0,2);
    partial("ignored usage still incomplete",CERT_TRUST_IS_NOT_VALID_FOR_USAGE,CERT_CHAIN_POLICY_IGNORE_WRONG_USAGE_FLAG,0,2);
    partial("ignored critical extension still incomplete",CERT_TRUST_HAS_NOT_SUPPORTED_CRITICAL_EXT,CERT_CHAIN_POLICY_IGNORE_NOT_SUPPORTED_CRITICAL_EXT_FLAG,0,2);
    for(unsigned i=0;i<sizeof(errors)/sizeof(errors[0]);i++) {
        DWORD rest=0; for(unsigned j=i;j<sizeof(errors)/sizeof(errors[0]);j++) rest|=errors[j].bit;
        check("mixed errors retain pinned priority",P|rest,0,0,2,errors[i].result,2,
              errors[i].bit==CERT_TRUST_IS_CYCLIC?-1:1);
    }
    DWORD all=0; for(unsigned i=0;i<sizeof(errors)/sizeof(errors[0]);i++) all|=errors[i].bit;
    check("all errors retain signature priority",P|all,0,0,2,TRUST_E_CERT_SIGNATURE,2,1);
    printf("PASS %u actual BASE policy cases (%s); status bounds/input immutability checked\n",
           tests,EXPECT_FIX?"review candidate":"pinned baseline, including reproduced false acceptance");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='madeira-partial-chain-review-') as temp:
    work=Path(temp)
    staged=work/'staged'; target=staged/'dlls/crypt32/chain.c'; target.parent.mkdir(parents=True)
    target.write_text(chain)
    patch=OWN/'build/crypto-unix/partial-chain-policy-review.patch'
    subprocess.run(['patch','--batch','--fuzz=0','-p1','-d',str(staged),'-i',str(patch)],check=True)
    fixed=target.read_text()
    before=function(chain,'static BOOL WINAPI verify_base_policy(')
    after=function(fixed,'static BOOL WINAPI verify_base_policy(')
    helper=function(chain,'static void find_element_with_error(')
    assert function(fixed,'static void find_element_with_error(')==helper
    assert function(chain,'static BOOL WINAPI verify_authenticode_policy(')==function(fixed,'static BOOL WINAPI verify_authenticode_policy(')
    assert function(chain,'static BOOL WINAPI verify_ssl_policy(')==function(fixed,'static BOOL WINAPI verify_ssl_policy(')
    assert before[:before.rindex('    return TRUE;')] == after[:after.index('    /* Review candidate:')]
    assert 'CERT_TRUST_IS_PARTIAL_CHAIN' not in before and after.count('CERT_TRUST_IS_PARTIAL_CHAIN')==2
    assert after.index('CERT_TRUST_IS_PARTIAL_CHAIN')>after.index('CERT_TRUST_HAS_NOT_SUPPORTED_CRITICAL_EXT')
    env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0:abort_on_error=1','UBSAN_OPTIONS':'halt_on_error=1'}
    for candidate,body in ((0,before),(1,after)):
        source=work/f'policy-{candidate}.c'; binary=work/f'policy-{candidate}'
        source.write_text(prefix+helper+body+harness)
        subprocess.run([os.environ.get('CC','cc'),'-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-parameter',
                        '-fsanitize=address,undefined','-fno-omit-frame-pointer',f'-DEXPECT_FIX={candidate}',str(source),'-o',str(binary)],check=True)
        subprocess.run([str(binary)],check=True,env=env,timeout=15)
print('PASS review overlay changes only BASE policy body; no production staging integration, full WinTrust or HASH_ONLY claim')
