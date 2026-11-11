#!/usr/bin/env python3
"""Run pinned/patched production crypt32 encoding and verification hash paths.

Only Win32 allocation/SEH/type and hash-provider boundaries are supplied by the
host harness. The SET/OID encoders and CSignedMsgData verification function are
extracted verbatim from Wine. OpenSSL performs real RSA verification against the
public certificates in ordinary, generated test messages. This tests signature
math, not certificate trust, Valve provenance, or VAC acceptance.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
WINE = ROOT / 'wine'
FIXTURES = ROOT / 'tests/integration/authenticode'


def run(args, **kwargs):
    result = subprocess.run([str(a) for a in args], capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError('command failed: %s\n%s\n%s' %
                           (args, result.stdout.decode(errors='replace'), result.stderr.decode(errors='replace')))
    return result


def function(source, name):
    # Require a function definition, never its earlier declaration.
    match = re.search(r'(?m)^[\w *]+\b' + re.escape(name) + r'\([^;{}]*\)\s*\{', source)
    if not match:
        raise AssertionError('missing production function ' + name)
    end = source.index('\n}', match.end()) + 2
    return source[match.start():end]


def span(data, start, end=None):
    end = len(data) if end is None else end
    assert start + 2 <= end
    tag, length = data[start:start + 2]
    pos = start + 2
    if length & 128:
        count = length & 127
        assert 0 < count <= 4 and pos + count <= end
        length = int.from_bytes(data[pos:pos + count], 'big')
        pos += count
    assert pos + length <= end
    return tag, pos, pos + length, start


def children(data, parent):
    pos, end = parent[1:3]
    result = []
    while pos < end:
        item = span(data, pos, end)
        result.append(item)
        pos = item[2]
    assert pos == end
    return result


def oid(data):
    assert data
    values = [data[0] // 40, data[0] % 40]
    value = 0
    for octet in data[1:]:
        value = (value << 7) | (octet & 127)
        if not octet & 128:
            values.append(value)
            value = 0
    assert not data[-1] & 128
    return '.'.join(map(str, values))


def inspect_message(data):
    outer = children(data, span(data, 0))
    signed = children(data, children(data, outer[1])[0])
    signer = children(data, children(data, signed[-1])[0])
    attrs = next(item for item in signer if item[0] == 0xa0)
    position = signer.index(attrs)
    signature = signer[position + 2]
    assert signature[0] == 4
    result = []
    for item in children(data, attrs):
        fields = children(data, item)
        assert fields[0][0] == 6 and fields[1][0] == 0x31
        values = [data[value[3]:value[2]] for value in children(data, fields[1])]
        result.append((oid(data[fields[0][1]:fields[0][2]]), values))
    raw_attrs = bytes([0x31]) + data[attrs[3] + 1:attrs[2]]
    return result, raw_attrs, data[signature[1]:signature[2]]


def vector(name):
    text = (FIXTURES / 'attribute-order-vectors.h').read_text()
    body = re.search(r'\b' + name + r'\[\]\s*=\s*\{(.*?)\};', text, re.S)
    assert body
    return bytes(int(item, 16) for item in re.findall(r'0x([0-9a-fA-F]{2})\b', body[1]))


SHIM = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
typedef uint8_t BYTE; typedef uint32_t DWORD; typedef int BOOL;
typedef char *LPSTR; typedef const char *LPCSTR; typedef void *LPVOID;
typedef BYTE *LPBYTE; typedef DWORD *PDWORD; typedef EVP_MD_CTX *HCRYPTHASH;
#define WINAPI
#define __cdecl
#define TRUE 1
#define FALSE 0
#define TRACE(...) ((void)0)
#define __TRY if (1)
#define __EXCEPT_PAGE_FAULT else
#define __ENDTRY
#define min(a,b) ((a)<(b)?(a):(b))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define ASN_SEQUENCE 0x30
#define ASN_OBJECTIDENTIFIER 0x06
#define ASN_CONSTRUCTOR 0x20
#define ASN_SETOF 0x11
#define X509_ASN_ENCODING 1
#define PKCS_ATTRIBUTES ((LPCSTR)22)
#define CRYPT_ENCODE_ALLOC_FLAG 0x8000
#define ERROR_MORE_DATA 234
#define CRYPT_E_ASN1_ERROR 0x80093100
#define E_INVALIDARG 0x80070057
#define STATUS_ACCESS_VIOLATION 0xc0000005
#define szOID_RSA_contentType "1.2.840.113549.1.9.3"
static DWORD last_error;
static int fail_alloc, fail_hash;
static FILE *hash_input;
static void SetLastError(DWORD value) { last_error=value; }
static DWORD GetLastError(void) { return last_error; }
static void *CryptMemAlloc(size_t size) { return fail_alloc ? NULL : malloc(size); }
static void CryptMemFree(void *value) { free(value); }
static void *LocalAlloc(DWORD flags, size_t size) { (void)flags; return CryptMemAlloc(size); }
static void LocalFree(void *value) { free(value); }
typedef struct { void *(*pfnAlloc)(size_t); void (*pfnFree)(void *); } CRYPT_ENCODE_PARA, *PCRYPT_ENCODE_PARA;
typedef struct { DWORD cbData; BYTE *pbData; } CRYPT_DER_BLOB, CRYPT_DATA_BLOB, CERT_BLOB, *PCERT_BLOB, CRL_BLOB, *PCRL_BLOB;
typedef struct { DWORD cBlob; CRYPT_DER_BLOB *rgBlob; } CRYPT_BLOB_ARRAY;
typedef struct { LPSTR pszObjId; DWORD cValue; CRYPT_DER_BLOB *rgValue; } CRYPT_ATTRIBUTE;
typedef struct { DWORD cAttr; CRYPT_ATTRIBUTE *rgAttr; } CRYPT_ATTRIBUTES;
typedef struct { LPSTR pszObjId; CRYPT_DATA_BLOB Parameters; } CRYPT_ALGORITHM_IDENTIFIER;
typedef struct { LPSTR pszObjId; CRYPT_DATA_BLOB Content; } CRYPT_CONTENT_INFO;
/* Signer identity fields are opaque to the extracted hash-input path. */
typedef struct { DWORD version; void *SignerId; CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
 CRYPT_ALGORITHM_IDENTIFIER HashEncryptionAlgorithm; CRYPT_DATA_BLOB EncryptedHash;
 CRYPT_ATTRIBUTES AuthAttrs, UnauthAttrs; } CMSG_CMS_SIGNER_INFO, *PCMSG_CMS_SIGNER_INFO;
typedef BOOL (WINAPI *CryptEncodeObjectExFunc)(DWORD,LPCSTR,const void *,DWORD,PCRYPT_ENCODE_PARA,BYTE *,DWORD *);
struct AsnEncodeSequenceItem { const void *pvStructInfo; CryptEncodeObjectExFunc encodeFunc; DWORD size; };
static BOOL CryptHashData(HCRYPTHASH hash, const BYTE *data, DWORD count, DWORD flags)
{
 (void)flags;
 if (fail_hash) return FALSE;
 if (EVP_DigestUpdate(hash,data,count)!=1) return FALSE;
 return fwrite(data,1,count,hash_input)==count;
}
'''


def harness(encode, msg, private, attributes):
    functions = [function(encode, name) for name in (
        'CRYPT_EncodeEnsureSpace', 'CRYPT_FreeSpace', 'CRYPT_EncodeLen',
        'CRYPT_AsnEncodeSequence', 'CRYPT_AsnEncodeOid', 'BLOBComp', 'CRYPT_DEREncodeSet')]
    descriptor = re.search(r'struct DERSetDescriptor\s*\{.*?\n};', encode, re.S)[0]
    functions += [descriptor, function(encode, 'CRYPT_DEREncodeItemsAsSet'),
                  function(encode, 'CRYPT_AsnEncodePKCSAttribute'),
                  function(encode, 'CRYPT_AsnEncodePKCSAttributes')]
    if 'BOOL CRYPT_AsnEncodePKCSAttributesUnsorted(' in encode:
        functions.append(function(encode, 'CRYPT_AsnEncodePKCSAttributesUnsorted'))
    declarations = []
    for number, (identifier, values) in enumerate(attributes):
        for index, value in enumerate(values):
            declarations.append('static BYTE value_%d_%d[]={%s};' %
                                (number, index, ','.join(str(b) for b in value)))
        declarations.append('static CRYPT_DER_BLOB values_%d[]={%s};' % (number, ','.join(
            '{sizeof(value_%d_%d),value_%d_%d}' % (number, i, number, i) for i in range(len(values)))))
    declarations.append('static CRYPT_ATTRIBUTE attributes[]={%s};' % ','.join(
        '{"%s",%d,values_%d}' % (identifier, len(values), i)
        for i, (identifier, values) in enumerate(attributes)))
    signed = re.search(r'typedef struct _CRYPT_SIGNED_INFO\s*\{.*?} CRYPT_SIGNED_INFO;', private, re.S)[0]
    handles = re.search(r'typedef struct _CSignerHandles\s*\{.*?} CSignedMsgData;', msg, re.S)[0]
    bridge = r'''
static BOOL CryptEncodeObjectEx(DWORD encoding,LPCSTR type,const void *info,DWORD flags,
 PCRYPT_ENCODE_PARA para,void *output,DWORD *size)
{
 if(type!=PKCS_ATTRIBUTES) abort();
 return CRYPT_AsnEncodePKCSAttributes(encoding,type,info,flags,para,output,size);
}
typedef enum { Sign, Verify } SignOrVerify;
/* Full signing is outside this harness; never fabricate its result. */
static BOOL CRYPT_AppendAttribute(CRYPT_ATTRIBUTES *attrs,const CRYPT_ATTRIBUTE *attr)
{ (void)attrs; (void)attr; abort(); }
static BOOL CSignedMsgData_AppendMessageDigestAttribute(CSignedMsgData *data,DWORD i)
{ (void)data; (void)i; abort(); }
'''
    main = r'''
int main(int argc,char **argv)
{
 CMSG_CMS_SIGNER_INFO signer={0}; CRYPT_SIGNED_INFO info={0};
 CSignerHandles handles={0}; CSignedMsgData message={&info,1,&handles};
 BYTE *encoded=NULL; DWORD count=0; BOOL ok;
 if(argc!=3) return 2;
 hash_input=fopen(argv[2],"wb"); if(!hash_input) return 3;
 signer.AuthAttrs.cAttr=ARRAY_SIZE(attributes); signer.AuthAttrs.rgAttr=attributes;
 info.cSignerInfo=1; info.rgSignerInfo=&signer;
 handles.authAttrHash=EVP_MD_CTX_new();
 if(!handles.authAttrHash || EVP_DigestInit_ex(handles.authAttrHash,EVP_sha256(),NULL)!=1) return 4;
 fail_alloc=!strcmp(argv[1],"fail-alloc"); fail_hash=!strcmp(argv[1],"fail-hash");
 if(!strcmp(argv[1],"public"))
 {
  ok=CRYPT_AsnEncodePKCSAttributes(1,PKCS_ATTRIBUTES,&signer.AuthAttrs,
       CRYPT_ENCODE_ALLOC_FLAG,NULL,(BYTE *)&encoded,&count);
  if(ok) ok=fwrite(encoded,1,count,hash_input)==count;
  LocalFree(encoded);
 }
 else ok=CSignedMsgData_UpdateAuthenticatedAttributes(&message,Verify);
 EVP_MD_CTX_free(handles.authAttrHash); if(fclose(hash_input)) return 5;
 return ok ? 0 : 23;
}
'''
    return '\n'.join([SHIM, *functions, signed, handles, bridge,
                      function(msg, 'CSignedMsgData_UpdateAuthenticatedAttributes'), *declarations, main])


def verify(public_key, signature, encoded, expected):
    result = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(public_key),
                             '-signature', str(signature), str(encoded)], capture_output=True)
    assert (result.returncode == 0) == expected, (expected, result.stdout, result.stderr)


def expect_error(callback):
    try:
        callback()
    except (ValueError, FileExistsError):
        return
    raise AssertionError('unsafe staging operation was accepted')


def crypto_flags():
    # Apple does not expose OpenSSL headers in its SDK. Use the installed host
    # library explicitly; this dependency never enters the iPhone application.
    if shutil.which('pkg-config'):
        result = subprocess.run(['pkg-config', '--cflags', '--libs', 'openssl'], capture_output=True, text=True)
        if not result.returncode:
            return shlex.split(result.stdout)
    for prefix in (Path('/opt/homebrew/opt/openssl@3'), Path('/usr/local/opt/openssl@3')):
        if (prefix / 'include/openssl/evp.h').is_file():
            return ['-I' + str(prefix / 'include'), '-L' + str(prefix / 'lib'), '-lcrypto']
    return ['-lcrypto']


def main():
    spec = importlib.util.spec_from_file_location('authattrs_stage', ROOT / 'tools/build/stage-crypt32-authattrs.py')
    stage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stage)
    with tempfile.TemporaryDirectory(prefix='authattrs-host-', dir=ROOT / 'build') as directory:
        temporary = Path(directory)
        corrected = temporary / 'corrected'
        stage.stage(corrected, WINE)  # Deliberately inside the real Git worktree.
        expect_error(lambda: stage.stage(corrected, WINE))
        originals = {name: (WINE / name).read_bytes() for name in stage.SOURCES}
        owned = temporary / 'owned-source'
        for name, data in originals.items():
            (owned / name).parent.mkdir(parents=True, exist_ok=True)
            (owned / name).write_bytes(data)
        transaction = temporary / 'transaction'
        stage.apply(transaction, owned)
        expect_error(lambda: stage.apply(transaction, owned))
        changed = owned / stage.SOURCES[0]
        changed.write_bytes(changed.read_bytes() + b'\n/* unrelated edit */\n')
        expect_error(lambda: stage.restore(transaction))
        changed.write_bytes((corrected / stage.SOURCES[0]).read_bytes())
        stage.restore(transaction)
        stage.restore(transaction)
        assert all((owned / name).read_bytes() == data for name, data in originals.items())
        symlink = owned / stage.SOURCES[1]
        symlink.unlink()
        symlink.symlink_to(WINE / stage.SOURCES[1])
        expect_error(lambda: stage.stage(temporary / 'symlink-stage', owned))

        provenance = json.loads((FIXTURES / 'attribute-order-provenance.json').read_text())
        messages = {'unsorted': vector('msgWithUnsortedAuthAttrs'),
                    'canonical': vector('madeiraCanonicalSignedAttrs')}
        for label, message in messages.items():
            record = provenance['upstream' if label == 'unsorted' else 'canonical']
            assert hashlib.sha256(message).hexdigest() == record['sha256']
            der = temporary / (label + '.der')
            der.write_bytes(message)
            certificates = run(['openssl', 'pkcs7', '-inform', 'DER', '-in', der, '-print_certs']).stdout
            assert certificates.count(b'BEGIN CERTIFICATE') == 1
            cert = temporary / (label + '.pem')
            cert.write_bytes(certificates)
            (temporary / (label + '.pub')).write_bytes(run(['openssl', 'x509', '-in', cert, '-pubkey', '-noout']).stdout)
        controls = 0
        for label, message in messages.items():
            attributes, original_attrs, signature = inspect_message(message)
            sig = temporary / (label + '.sig')
            sig.write_bytes(signature)
            key = temporary / (label + '.pub')
            original = temporary / (label + '.original')
            original.write_bytes(original_attrs)
            verify(key, sig, original, True)
            for variant, source_root in (('before', WINE), ('after', corrected)):
                encode = (source_root / 'dlls/crypt32/encode.c').read_text()
                msg = (source_root / 'dlls/crypt32/msg.c').read_text()
                private = (source_root / 'dlls/crypt32/crypt32_private.h').read_text()
                cfile = temporary / (label + '-' + variant + '.c')
                binary = cfile.with_suffix('')
                cfile.write_text(harness(encode, msg, private, attributes))
                run([os.environ.get('CC', 'cc'), '-std=c11', '-O1', '-g', '-Wall', '-Wextra',
                     '-Wno-unused-parameter', '-Wno-unused-function', '-fsanitize=address,undefined',
                     '-fno-omit-frame-pointer', cfile, *crypto_flags(), '-o', binary])
                output = temporary / (label + '-' + variant + '.attrs')
                run([binary, 'verify', output])
                # Real old source rejects the valid upstream non-DER-order signature.
                verify(key, sig, output, variant == 'after' or label == 'canonical')
                public = temporary / (label + '-' + variant + '.public')
                run([binary, 'public', public])
                assert public.read_bytes() == (temporary / (label + '-before.public')).read_bytes()
                if variant == 'before':
                    assert public.read_bytes() == output.read_bytes()
                verify(key, sig, public, label == 'canonical')
                for mode in ('fail-alloc', 'fail-hash'):
                    failed = temporary / (label + '-' + variant + '-' + mode)
                    result = subprocess.run([str(binary), mode, str(failed)], capture_output=True)
                    assert result.returncode == 23, (mode, result.stderr)
                    assert failed.stat().st_size == 0
                controls += 5
            after = temporary / (label + '-after.attrs')
            assert after.read_bytes() == original_attrs
            tampered = temporary / (label + '.tampered')
            payload = bytearray(after.read_bytes())
            payload[-1] ^= 1
            tampered.write_bytes(payload)
            verify(key, sig, tampered, False)
            tampered_sig = temporary / (label + '.tampered-sig')
            payload = bytearray(signature)
            payload[-1] ^= 1
            tampered_sig.write_bytes(payload)
            verify(key, tampered_sig, after, False)
            other = temporary / (('canonical' if label == 'unsorted' else 'unsorted') + '.pub')
            verify(other, sig, after, False)
            controls += 4
        assert all((WINE / name).read_bytes() == data for name, data in originals.items())
        print('PASS: old production verify falsely rejects valid unsorted RSA signature; patched accepts; canonical stays valid')
        print('PASS: DER signing encoder unchanged; attribute/signature/order tamper and wrong-key checks reject (%d controls)' % controls)
        print('PASS: production encoder/message paths under ASan/UBSan; allocation/hash failure propagation; guarded stage/apply/restore')
        print('UNMEASURED: Valve-authenticated content trust, iPhone Wine execution and VAC-secured server acceptance')


if __name__ == '__main__':
    main()
