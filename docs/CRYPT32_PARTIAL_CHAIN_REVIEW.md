# Review-only Crypt32 partial-chain candidate

This candidate is based on Madeira `b6edc4d7bdd4329b79887b463439061b5ec8b33c`
and Wine `df1c5ea51e194937ac204bc3120922dc56a61bec`. It is **not
staged into Madeira, integrated, or shipping**. The patch, host fixture and
isolated workflow are material for review, not evidence of a device fix.

## Demonstrated gap and actual provider evidence

In the pinned `dlls/crypt32/chain.c`, `CRYPT_BuildSimpleChain` sets
`CERT_TRUST_IS_PARTIAL_CHAIN` on the simple chain when it cannot find an
issuer. `verify_base_policy` checks other errors but never checks that bit.
Consequently an otherwise clean partial chain can return API `TRUE` with
`CERT_CHAIN_POLICY_STATUS.dwError == 0`. API `TRUE` means the policy check
ran; callers must also inspect `dwError`.

The separate [real Wine 9 provider proof, run 42723486462](https://github.com/letsdothisagainx/Madeira/actions/runs/42723486462),
job `129523065310`, recorded both I386 and AMD64 original public signed fixtures
returning `WinVerifyTrust` status `00000000` while the actual provider chain
reported `chain-errors=00010000`. This happened with both ordinary
`WINTRUST_ACTION_GENERIC_VERIFY_V2` and the `WTD_HASH_ONLY_FLAG` variant.
Covered-byte mutations returned `80096010`; unsigned and truncated subjects
returned `800b0100`. The job **failed** its ordinary-policy rejection assertion;
it must not be reported as a passing full-trust proof. These observations concern
the packaged Ubuntu Wine 9 provider, not an execution of this candidate or the
iOS packaged provider. Subject PE fixtures remained data and were not executed.

## Narrow candidate behavior

The candidate appends one check after every existing BASE-policy error check.
Only when `dwError` is still zero, the aggregate chain status contains
`CERT_TRUST_IS_PARTIAL_CHAIN`, and the caller has not supplied
`CERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG`, it reports `CERT_E_CHAINING`.
It selects the first simple chain whose own trust status contains the partial
bit. `lElementIndex` retains its initialized value of `-1`. If only the aggregate
context carries the bit, both indices remain `-1`; this is a conservative
context-wide fallback, not a measured Windows result for inconsistent contexts.

All pre-existing error results, their selection order and their indices remain
unchanged. Existing caller ignore flags retain their behavior; the candidate
adds no flags or waivers. A time or usage error suppressed by its existing caller
flag can expose the previously unhandled partial-chain error. The function still
returns API `TRUE` and communicates policy rejection through `dwError`.
The added code only reads existing public chain structures and writes the existing
policy result. It allocates nothing and does not alter certificates, chain inputs,
provider state, trust stores, or process security configuration.

This placement deliberately preserves pinned Wine's existing precedence. It does
**not** establish Windows error priority when a partial chain also has expiration,
wrong-usage or another error. The documentation does not specify that ordering,
and existing cyclic-chain coverage is not a pure partial-chain oracle.

## Windows contract sources

- Microsoft defines `CERT_TRUST_IS_PARTIAL_CHAIN` as a chain-only error indicating
  an incomplete chain: [CERT_TRUST_STATUS](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_trust_status).
- BASE policy includes `CERT_E_CHAINING`; a simple-chain error uses the first
  affected chain index and element index `-1`, while a context-wide error uses
  `-1/-1`: [CertVerifyCertificateChainPolicy](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certverifycertificatechainpolicy)
  and [CERT_CHAIN_POLICY_STATUS](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_chain_policy_status).
- The native [policy flags documentation](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_chain_policy_para)
  describes `ALLOW_UNKNOWN_CA` as allowing untrusted roots. Microsoft's
  [.NET flag documentation](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509verificationflags)
  also explicitly includes partial chains. The actual
  [Windows implementation](https://github.com/dotnet/runtime/blob/main/src/libraries/System.Security.Cryptography/src/System/Security/Cryptography/X509Certificates/ChainPal.Windows.cs)
  forwards those flags unchanged to native BASE policy. A
  [Microsoft maintainer confirmation](https://github.com/dotnet/runtime/issues/49615#issuecomment-817947393)
  states that Windows controls partial-chain suppression under this flag.
  Respecting a flag already supplied by a caller does not justify enabling it
  for other callers.

## Test scope and integration blockers

Run the review fixture from the candidate checkout after initializing pinned Wine:

```sh
python3 tests/host/check-crypt32-partial-chain-review.py
```

The host regression compiles the actual pinned BASE-policy body and its candidate
against small C models of the public fields those functions use, with constants
read from the real pinned Wine headers. These are not full Windows ABI structures.
It verifies policy results, flags, indices, result-buffer bounds and input
immutability. It also checks that the entire pre-existing policy-body prefix is
byte-identical and that mixed errors retain pinned Wine's existing precedence.
The independent local invocation used the temporary fixture with
`--source-root /workspace/madeira-browser-build` and passed **35 baseline plus
35 candidate cases under AddressSanitizer and UndefinedBehaviorSanitizer**.
The isolated candidate CI result is still pending.

This fixture does not validate the Windows ABI, perform real signature
verification, build a real certificate chain, load a real WinTrust provider, or
establish publisher trust. Host fixture success is not an end-to-end trust result.
No result from a not-yet-completed candidate workflow should be inferred here.

The pinned production WinTrust sources show no `WTD_HASH_ONLY_FLAG` handling;
that flag appears in its test caller. The observed success in hash-only mode may
therefore share the ordinary partial-chain policy omission. A BASE-only correction
could change that accidental hash-only `S_OK` into `CERT_E_CHAINING` even when the
image digest is internally consistent. Microsoft's
[WINTRUST_DATA contract](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data)
distinguishes hash-only behavior from ordinary trust verification. This candidate
does not repair or redefine that separate provider behavior.

Before integration, measure the full provider with original, mutated, unsigned
and truncated owned subjects in ordinary and hash-only modes; obtain a real
Windows oracle for partial-chain flags, indices and mixed-error behavior; and
validate the exact built iOS provider. Actual Steam authentication and genuine
Steam file-verification results remain separate measurements. No root-store
changes, added trust exceptions, Valve/game modifications or VAC compatibility
claim are part of this candidate. No secure-server acceptance is demonstrated.
