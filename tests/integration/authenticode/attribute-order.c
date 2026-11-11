/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Ordinary crypt32 conformance probe. Uses only owned/public upstream test
 * messages; does not import a trusted certificate or inspect a game process.
 * The certificate here supplies a public key, never a publisher-trust verdict.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "attribute-order-vectors.h"

static unsigned checks, failures;

static void expect(const char *name, BOOL got, BOOL wanted)
{
    checks++;
    if (!!got != !!wanted)
    {
        failures++;
        printf("[authattrs] FAIL case=%s result=%u expected=%u error=%08lx\n",
               name, !!got, !!wanted, GetLastError());
    }
    else printf("[authattrs] PASS case=%s result=%u\n", name, !!got);
}

struct decoded
{
    HCRYPTMSG message;
    PCCERT_CONTEXT certificate;
};

static void close_message(struct decoded *value)
{
    if (value->certificate) CertFreeCertificateContext(value->certificate);
    if (value->message) CryptMsgClose(value->message);
    memset(value, 0, sizeof(*value));
}

static BOOL open_message(const BYTE *bytes, DWORD length, struct decoded *value)
{
    DWORD count = 0;
    BYTE *certificate = NULL;
    BOOL ok = FALSE;
    memset(value, 0, sizeof(*value));
    value->message = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    if (!value->message || !CryptMsgUpdate(value->message, bytes, length, TRUE) ||
        !CryptMsgGetParam(value->message, CMSG_CERT_PARAM, 0, NULL, &count) || !count)
        goto done;
    if (!(certificate = HeapAlloc(GetProcessHeap(), 0, count))) goto done;
    if (!CryptMsgGetParam(value->message, CMSG_CERT_PARAM, 0, certificate, &count)) goto done;
    value->certificate = CertCreateCertificateContext(X509_ASN_ENCODING, certificate, count);
    ok = value->certificate != NULL;
done:
    if (certificate) HeapFree(GetProcessHeap(), 0, certificate);
    if (!ok) close_message(value);
    return ok;
}

static BOOL verify(const BYTE *bytes, DWORD length)
{
    struct decoded value;
    BOOL result;
    DWORD error;
    if (!open_message(bytes, length, &value)) return FALSE;
    result = CryptMsgControl(value.message, 0, CMSG_CTRL_VERIFY_SIGNATURE,
                            value.certificate->pCertInfo);
    error = GetLastError();
    close_message(&value);
    SetLastError(error);
    return result;
}

/* Definite-length DER navigation only for the two checked-in fixtures. It is
 * used to mutate test data; the real decoder and verifier remain crypt32. */
struct span { const BYTE *start, *data, *end; unsigned tag; };

static BOOL next_span(const BYTE **cursor, const BYTE *end, struct span *out)
{
    const BYTE *p = *cursor;
    size_t length, count, i;
    if (p >= end) return FALSE;
    out->start = p;
    out->tag = *p++;
    if ((out->tag & 31) == 31 || p >= end) return FALSE;
    length = *p++;
    if (length & 128)
    {
        count = length & 127;
        if (!count || count > sizeof(length) || (size_t)(end - p) < count) return FALSE;
        length = 0;
        for (i = 0; i < count; i++)
        {
            if (length > ((size_t)-1 >> 8)) return FALSE;
            length = (length << 8) | *p++;
        }
    }
    if (length > (size_t)(end - p)) return FALSE;
    out->data = p;
    out->end = p + length;
    *cursor = out->end;
    return TRUE;
}

static BOOL layout(const BYTE *bytes, size_t length, struct span *attributes,
                   struct span *signature)
{
    const BYTE *p = bytes, *end = bytes + length;
    struct span node, signed_data, signer_set, signer;
    unsigned i;
    if (!next_span(&p, end, &node) || node.tag != 0x30 || p != end) return FALSE;
    p = node.data; end = node.end;
    if (!next_span(&p, end, &node) || node.tag != 0x06 ||
        !next_span(&p, end, &node) || node.tag != 0xa0 || p != end) return FALSE;
    p = node.data; end = node.end;
    if (!next_span(&p, end, &signed_data) || signed_data.tag != 0x30 || p != end) return FALSE;
    p = signed_data.data; end = signed_data.end;
    /* Version, digest algorithms and encapsulated content. */
    for (i = 0; i < 3; i++) if (!next_span(&p, end, &node)) return FALSE;
    do { if (!next_span(&p, end, &signer_set)) return FALSE; }
    while (signer_set.tag == 0xa0 || signer_set.tag == 0xa1);
    if (signer_set.tag != 0x31 || p != end) return FALSE;
    p = signer_set.data; end = signer_set.end;
    if (!next_span(&p, end, &signer) || signer.tag != 0x30 || p != end) return FALSE;
    p = signer.data; end = signer.end;
    /* Version, signer identity and digest algorithm. */
    for (i = 0; i < 3; i++) if (!next_span(&p, end, &node)) return FALSE;
    return next_span(&p, end, attributes) && attributes->tag == 0xa0 &&
           next_span(&p, end, &node) && node.tag == 0x30 &&
           next_span(&p, end, signature) && signature->tag == 0x04 &&
           signature->data < signature->end;
}

static int span_compare(const void *av, const void *bv)
{
    const struct span *a = av, *b = bv;
    size_t an = a->end - a->start, bn = b->end - b->start;
    int order = memcmp(a->start, b->start, an < bn ? an : bn);
    return order ? order : an < bn ? -1 : an > bn;
}

int main(void)
{
    struct span attributes, signature, pieces[16];
    struct decoded original = {0}, other = {0};
    CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA control = {0};
    BYTE changed[sizeof(msgWithUnsortedAuthAttrs)];
    const BYTE *p;
    size_t count = 0, i, offset;

    expect("upstream-valid-unsorted-rsa", verify(msgWithUnsortedAuthAttrs,
           sizeof(msgWithUnsortedAuthAttrs)), TRUE);
    expect("canonical-rsa", verify(madeiraCanonicalSignedAttrs,
           sizeof(madeiraCanonicalSignedAttrs)), TRUE);
    if (!layout(msgWithUnsortedAuthAttrs, sizeof(msgWithUnsortedAuthAttrs),
                &attributes, &signature))
    {
        printf("[authattrs] FAIL fixture-layout\n");
        return 2;
    }

    memcpy(changed, msgWithUnsortedAuthAttrs, sizeof(changed));
    changed[signature.data - msgWithUnsortedAuthAttrs] ^= 1;
    expect("tampered-rsa-signature", verify(changed, sizeof(changed)), FALSE);

    memcpy(changed, msgWithUnsortedAuthAttrs, sizeof(changed));
    /* Change one attribute value byte while retaining its ASN.1 structure. */
    changed[attributes.end - msgWithUnsortedAuthAttrs - 1] ^= 1;
    expect("tampered-authenticated-attribute", verify(changed, sizeof(changed)), FALSE);

    p = attributes.data;
    while (p < attributes.end && count < sizeof(pieces) / sizeof(pieces[0]))
    {
        if (!next_span(&p, attributes.end, &pieces[count++])) return 2;
    }
    if (p != attributes.end || count < 2) return 2;
    qsort(pieces, count, sizeof(pieces[0]), span_compare);
    memcpy(changed, msgWithUnsortedAuthAttrs, sizeof(changed));
    offset = attributes.data - msgWithUnsortedAuthAttrs;
    for (i = 0; i < count; i++)
    {
        size_t n = pieces[i].end - pieces[i].start;
        memcpy(changed + offset, pieces[i].start, n);
        offset += n;
    }
    if (!memcmp(changed, msgWithUnsortedAuthAttrs, sizeof(changed))) return 2;
    expect("reordered-without-resigning", verify(changed, sizeof(changed)), FALSE);

    if (!open_message(msgWithUnsortedAuthAttrs, sizeof(msgWithUnsortedAuthAttrs), &original) ||
        !open_message(madeiraCanonicalSignedAttrs, sizeof(madeiraCanonicalSignedAttrs), &other))
        return 2;
    control.cbSize = sizeof(control);
    control.dwSignerIndex = 0;
    control.dwSignerType = CMSG_VERIFY_SIGNER_PUBKEY;
    control.pvSigner = &other.certificate->pCertInfo->SubjectPublicKeyInfo;
    expect("wrong-public-key", CryptMsgControl(original.message, 0,
           CMSG_CTRL_VERIFY_SIGNATURE_EX, &control), FALSE);
    close_message(&other);
    close_message(&original);

    expect("truncated-message", verify(msgWithUnsortedAuthAttrs,
           sizeof(msgWithUnsortedAuthAttrs) - 1), FALSE);
    printf("[authattrs] %s checks=%u failures=%u trust=not-evaluated vac=not-evaluated\n",
           failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
