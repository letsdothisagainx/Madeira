# Signature-verification compatibility regression

Madeira pins Wine `df1c5ea51e194937ac204bc3120922dc56a61bec`. Its
`CSignedMsgData_UpdateAuthenticatedAttributes()` sorts decoded authenticated
attributes before hashing them for signature verification. This changes the
signed bytes of otherwise valid messages whose attributes were not in DER SET
order. Wine fixed the false rejection in
[`a358d7ecf13b420d7fa65d54fcad1f96003d7a48`](https://github.com/wine-mirror/wine/commit/a358d7ecf13b420d7fa65d54fcad1f96003d7a48).
The owned patch backports that fix; signing remains canonical, and signature
math, certificate chains, and publisher-trust decisions are not bypassed.

`attribute-order-provenance.json` identifies the upstream regression vector and
the independently generated canonical control. Neither test certificate is
installed as a trusted root. The native `attribute-order.c` probe calls real
Windows `CryptMsgControl()` and tests valid unsorted/canonical signatures,
signature/attribute/order tampering, the wrong public key, and truncation.
`.github/workflows/security-api-compat.yml` executes that Windows reference.

`tests/host/check-authenticode-attribute-order.py` runs the old and corrected
production Wine encoder and message hash paths under sanitizers, with real
OpenSSL SHA-256 and RSA verification. The old code must reject the valid
unsorted signature, while the corrected code must accept it and continue
rejecting tampering. This is distinct from executing a complete Wine process.

The companion mapped-filename regression corrects zero-capacity writes and
truncated return lengths in `GetMappedFileNameW()`. It preserves the exact
queried filename and module identity. Its production-function test checks old
failures, corrected behavior, query errors, canaries, and UTF-16 bytes.

`build/wine-pe/build-security-compat.sh` rebuilds the actual crypt32/kernelbase
DLLs in AArch64, ARM64EC, and I386 farms, including on warm caches. Source
overlays are reversible. Packaging requires changed-object to linked-code
proofs, the real verification call to the new encoder, exact recipe/source
hashes, correct PE architectures, and identical DLL bytes in the app and IPA.

These are confirmed ordinary Wine API defects. No available game diagnostic
identifies the file or signature that CS2 rejects, or proves that CS2 exercises
either defect. Local VPK consistency, Steam login, networking certificates, and
these regressions do not establish Valve trust or VAC acceptance. The required
device test remains a genuine VAC-secured server connection. No game files,
security decisions, JIT layout, Wine prefix, or Steam credentials are changed.
