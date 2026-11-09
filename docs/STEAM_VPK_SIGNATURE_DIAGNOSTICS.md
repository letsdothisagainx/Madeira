# VPK signature-container diagnostics

The d573d421 device capture reaches CS2's menu. Its bounded audit reads and
SHA-1 hashes 107,558,579 current file bytes; both directory VPKs match their
cached installed-depot references. Those references are not freshly
authenticated. The old `section-invalid` observations therefore do not prove
corrupt game content, an invalid cryptographic signature, or the cause of the
secure-server warning.

The diagnostic parser supported only the older inline signature layout. It
mistook a modern descriptor's first word `0x55AA1234` for a public-key length,
then rejected it as larger than its 16 KiB diagnostic limit and the declared
section. This is a confirmed false rejection for a supported format. The device
capture did not include the actual descriptor fields, so the exact structure
of those two installed VPKs must still be established by the next audit.

Independent public format references, pinned for reproducibility:

* [ValvePak Package.Read.cs](https://github.com/ValveResourceFormat/ValvePak/blob/037f25ef5ad3a4f1804d0715d16ee2bd78bd652a/ValvePak/ValvePak/Package.Read.cs#L532)
  reads `SignatureSectionSize == 20` plus the VPK magic as five little-endian
  words: magic, type, signed public-key length, signed signature length, and a
  reserved word. The key and signature immediately follow those 20 bytes and
  are **outside** the header's declared signature-section size.
* [ValvePak Package.Verify.cs](https://github.com/ValveResourceFormat/ValvePak/blob/037f25ef5ad3a4f1804d0715d16ee2bd78bd652a/ValvePak/ValvePak/Package.Verify.cs)
  defines the stored MD5 ranges and signature preimages. Type 1 verifies RSA
  PKCS#1 v1.5/SHA-256 over the 16-byte whole-file MD5, after recomputing and
  comparing that MD5. The classic inline layout verifies RSA PKCS#1
  v1.5/SHA-256 over the bytes preceding its signature section.
* [Source2Wiki VPK format](https://github.com/Source2Wiki/Source2Wiki/blob/734f9bcb84d293718feafb90b7be58315829c201/docs/FileFormats/vpk.md)
  independently describes the descriptor and separate key/signature payloads.

The public ValvePak signed-CS2 test fixture has Git blob
`5d31d10537994e41fb92dd655b73a0bfe4674e8b`, SHA-256
`8279de4e7c0a1d8b52d98b33efebac409ad13eb0b6ab8320b09e7d85b3a9d6b4`,
and size 10,698 bytes. Its signature starts at offset 9,616, with descriptor
`[0x55AA1234, 1, 550, 512, 0]`; key and signature end exactly at EOF.
An independent OpenSSL check confirms the mathematical signature. This
authenticates the example's bytes against the public repository reference;
it does **not** establish an independently trusted Valve signing key.

The corrected production auditor:

* Recognizes classic inline and known type-1 descriptor structures separately;
  bounds signed lengths, offsets and complete payloads against the current
  file. Empty descriptors report absence. Unknown versions, descriptor types,
  nonzero reserved words or unexplained trailers remain unsupported/unmeasured.
  Its 16 KiB key/signature cap is an audit resource limit, not a VPK format rule.
* Recomputes current tree, archive-hash-table and whole-file MD5s using the known
  v2 preimages. It never treats stored hash fields as proof without reading
  their current preimages. Numbered archive payloads are explicitly not read.
* On Apple platforms, strictly extracts an RSA PKCS#1 public key from DER
  SubjectPublicKeyInfo and uses Security.framework to check the mathematical
  signature. A result is `consistent-embedded-key`, `mismatch-embedded-key`, or
  an explicit unavailable/unmeasured reason. Modern descriptor type 0 is not
  accepted merely because the classic layout uses an internal type-0 label.
* Still rehashes the entire current directory VPK with SHA-1 for comparison
  with its exact cached depot reference. Current and reference SHA-1 values
  are separately labeled. A same-size mutation between audits is read again.
* Accounts for additional checksum/preimage reads within the existing byte
  budget, reserves capacity for the whole-file SHA-1 read, and checks the idle
  callback and deadline between blocks. No launch waits for this diagnostic.

All observations retain `key-provenance=embedded-untrusted`,
`trust=unmeasured`, and `vac=unclaimed`. A key embedded in the file cannot
independently authenticate its own authority. No archive is modified, signed,
repaired, or accepted on Steam's behalf, and no protected game hook is added.

`tests/host/check-steam-library.py` exercises the production Swift auditor with
owned RSA-signed fixtures, unsigned descriptors, malformed/truncated payloads,
unknown structures, same-size changes, checksum and RSA mismatches, and read
budgets. `MADEIRA_VPK_ONLY=1` limits execution to these audit cases;
`MADEIRA_VPK_INTEGRITY_BASELINE=<revision>` compiles that revision's actual
audit implementation to demonstrate the original rejection. The optional
`MADEIRA_VPK_PUBLIC_FIXTURE=<local-file>` integration input must match the
pinned SHA-256 above; it permits testing the real public example without
redistributing its contents in this repository. Native Apple Security tests
and on-device outcomes remain distinct.
