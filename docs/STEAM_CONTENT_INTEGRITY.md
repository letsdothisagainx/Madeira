# Installed Steam content and signature diagnostics

The November 9 capture reaches the real CS2 menu and shows a secure-server
warning about missing or invalid file signatures. It does not identify the
failing file or the trust API result. The genuine command line is
`cs2.exe -steam -condebug -joy`. The capture does not establish that a content
download defect, an unsigned compatibility module, Wine's trust implementation,
or a Valve-side requirement caused this warning.

Two independent content-producer defects were established in the source:

* A newly downloaded chunk passed its declared length and Adler-32 check without
  checking its manifest SHA-1. Adler-32 collisions with different SHA-1 values
  are easy to construct. The downloader now checks all three before writing
  bytes or journaling completion.
* Resume journals were treated as proof that the current bytes still matched.
  The downloader now rehashes those chunks against the freshly requested depot
  manifest before counting them complete. Matching chunks are reused; changed
  chunks use the normal authenticated content-download path. This applies to
  install, resume and explicit repair, not to every game launch.

The parser also retains the whole-file `sha_content` field. Its protobuf field
number is 5; field 4 is `sha_filename` and is not a content digest. This matches
the public protocol declarations in SteamKit commit
`a6f60da8450c628cd25fa7d1d8de78b7edfb543e`,
`SteamKit2/SteamKit2/Base/Generated/ContentManifest.cs` (field-number reference
only). Absent whole-file hashes remain unknown.

`SteamContentIntegrity.auditCS2` is a separate, read-only diagnostic. It selects
the exact depot GIDs in the installed AppID 730 record and checks a fixed list
of critical game-relative names against available cached manifests. It does not
substitute a newer manifest. The default bound is 11 candidate files, 384 MiB
hashed, and a six-second deadline checked between reads, with further unmeasured
files reported explicitly. A `shouldContinue` session gate is also checked
between reads; if Steam/Wine begins, the audit stops without a completed-hash
claim. It runs off the main actor and never gates launching Steam.
It never resizes, writes, deletes, repairs, downloads, or changes completion
state. It does not read arbitrary mod/account files, follow symlinks, or export
absolute paths, raw digests, account identifiers or content.

Cached manifest provenance is not freshly authenticated by this diagnostic.
Encrypted names without a depot key, absent references, customized executables,
concurrent modifications, I/O errors and budget limits remain unmeasured. A
`cache-hash-match` describes only comparison with that cached reference.
The PE certificate result describes security-directory bounds and presence;
it never means cryptographic signature validation succeeded. These bounded
container checks can still report metadata when no matching manifest hash is
available. The two fixed directory VPK names get a separate v2 signature-section
bounds/presence check, not PE checks or RSA validation. No numbered VPK archive
is diagnosed as unsigned. All exported findings state
`trust=unmeasured`; none asserts VAC eligibility.

`tests/host/check-steam-library.py` compiles the production Swift downloader,
manifest parser and read-only audit under AddressSanitizer. Its owned HTTP
fixture supplies an actual same-length, same-Adler/different-SHA-1 chunk and
changes a genuinely journaled chunk before resume. The unchanged production
downloader from the installed revision can be replayed with
`MADEIRA_STEAM_INTEGRITY_BASELINE=<revision>`; those two negative tests fail
against it. Audit fixtures cover file/hash mismatches, missing files, exact
depot-GID selection, symlinks, case differences, certificate-table bounds,
customized files, malformed cache headers, limits and privacy.

These corrections prevent new unverified writes and unsafe resume assumptions.
They do not prove the existing iPhone's 127 GiB installation is correct or
incorrect, repair it without verification, or resolve the secure-server warning
without a real failing filename/API result. The existing installation and
Steam account remain authoritative and untouched by the diagnostic.
