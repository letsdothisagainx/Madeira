# Stock Wine Steam CEF argument fixture

This directory contains an isolated **test-only source candidate**. It never
changes the app, a Wine prefix, an official executable file, authentication,
certificate handling, sandbox settings, BRP, a DCHECK, or process-creation
results. Native child-denial gates are deliberately outside this argument-only
fixture; every child call goes through the genuine Windows API.

The official current tier0 pin supplied by the archive verification job is:

```
member: tier0_s64.dll
machine: 8664 (AMD64)
size: 887960
SHA256: 8559e6bd32eb3fddd95079633272866deb292211ec4f7e69aeb0ec48fdafef72
image size: 0030b000
KERNEL32.dll!CreateProcessW IAT RVA: 000a5358
KERNEL32.dll!CreateProcessA IAT RVA: 000a5190 (not changed)
```

The actual original code route is confirmed by `inspect_tier0.py` and recorded
in `tier0-route.json`: `CreateSimpleProcess` RVA `12440` calls
`CreateProcessUTF8` RVA `14090` at `124d9`; that function calls the genuine W
import at `141fe` (bytes `ff1554110900`, IAT RVA `a5358`). It has no A-import
call. Actual test logs must show both `exact tier0 CreateProcessW IAT installed`
and `browser-native-flags applied`; otherwise this fixture did not establish
matched effective arguments. No runtime success is inferred from a build.

`fixture_args.cpp` mirrors the **Steam branch** of
`build/ntdll-unix/process_ios.c` at lines 1894–1975. `sc_browser_cmdline` is a
different Social Club policy and must not be used for this purpose. The source
test compiles the actual native Steam block as its independent reference.

The appended existing native flags are:

```
--single-process --enable-logging --v=1 --log-severity=verbose
--no-proxy-server --winhttp-proxy-resolver --js-flags=--jitless
```

As in native Steam, `MADEIRA_JITLESS` beginning with `0` omits only the last
switch, existing arguments remain byte-for-byte, appended switches take normal
last-switch precedence, and the existing disable-features value receives only
`,SegmentationPlatform,OptimizationTargetPrediction,OptimizationHints`.
The native role parser is included unchanged. Browser launches alone change.
There is no new feature switch when the existing list is absent. Optional
native CDP observation is not enabled by this fixture.

Build and checks (the Python environment needs `pefile`):

```bash
python3 check_args.py
python3 check_forward.py
python3 check_iat.py
python3 check_official_map.py ./tier0_s64.dll
/workspace/Madeira/work/fex-callback-venv/bin/python build_fixture.py
```

The default DLL is disarmed. Neither an environment variable nor calling an
export can arm that build. An explicit experimental build needs the full raw
official DLL and independently checked full SHA256:

```bash
/workspace/Madeira/work/fex-callback-venv/bin/python build_pair.py \
  --provider-root /workspace/Madeira/work/htmlipc-dispatch \
  --tier0 ./official-input/tier0_s64.dll \
  --tier0-sha256 8559e6bd32eb3fddd95079633272866deb292211ec4f7e69aeb0ec48fdafef72 \
  --test-token 9fae48b18db64c8c90aa21602030599a \
  --map-source /workspace/Madeira/work/htmlipc-dispatch/runtime-shim/proven_map.cpp
```

`build_pair.py` only reads the supplied provider tree. It copies the required
source files below this directory, modifies that copy, and emits
`integration.patch`. The two built DLLs are:

- `ControlSameFlags/version.dll`: the VERSION forwarding shell and the same
  argument fixture; there is no stream provider or wire conversion.
- `SourceWireSameFlags/version.dll`: the existing source wire provider plus
  exactly the same argument fixture, pin, and test token.

Only the host test setup should stage these extra test DLLs into two new,
isolated Steam directories that do not already contain an official version.dll.
Use current official AMD64 CEF for the control, and the coherent official I386
CEF source-wire setup for the candidate. Supply
`MADEIRA_CEF_ARGS_TEST_TOKEN=9fae48b18db64c8c90aa21602030599a` only to those test
processes, and use the same `MADEIRA_JITLESS` value in both. Existing test source
VERSION native override behavior is retained. No prefix was staged here.

The experimental loader additionally requires main-image basename `Steam.exe`,
derives its directory with `GetModuleFileNameW`, requires the sibling
`tier0_s64.dll` path and full-file hash to match, retains a read-only file handle
that denies writes/deletion, and validates actual mapped PE headers, immutable
sections and executable bytes against the pinned raw image. It normalizes only
PE DIR64 relocations, Wine's documented ImageBase rewrite, and the loader IAT.
Each queried region must be committed `MEM_IMAGE` with the actual owner.
The caller module, hook and genuine API owners are pinned; the genuine pointer must resolve
through KERNEL32 to KERNEL32 or KERNELBASE. It will not patch an unresolved
pre-link thunk. Later DLL notifications allow another attempt after linking.
These notification callbacks are specifically Stock Wine test scaffolding;
host tests do not establish callback timing or loader-lock safety on Windows.
Require the installed status and applied-arguments marker from the real test.

The only modification is one aligned, nonexecutable, initially read-only IAT
slot, found by parsing the original named KERNEL32 import. The page follows
`PAGE_READONLY -> PAGE_READWRITE -> PAGE_READONLY`; no protection request can be
executable. Code pages and instructions are never changed. A failed restore
rolls back the original slot and retries read-only protection; incomplete
rollback remains an explicit error. Every hook invocation forwards all ten
CreateProcessW arguments, preserves the original signed 32-bit BOOL and exact
outgoing LastError, and restores incoming LastError before the genuine call.
Allocation or unsupported-path failures forward the original call unchanged.

The source is compiled with `-target x86_64-windows-msvc`. On AMD64,
[WINAPI uses Microsoft's x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention),
with RCX/RDX/R8/R9, stack arguments and shadow space. The hook declaration has
the exact ten parameter widths and pointer positions of
[CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw).
Opaque Windows structures are passed through without reinterpretation. This
guest AMD64 DLL is not a native iOS callback and supplies no cross-ISA calls.

`MadeiraCefFixtureStatus()` returns `0x10000` only after installation, otherwise
the `Error` enum. `MadeiraCefFixtureTransformed()` counts argument rewrites.
These are diagnostics, never BrowserReady, connected-stream, or login results.

Synthetic PE files under `build/` exist solely for tests and compilation checks;
they must never be staged as official files or distributed with the candidate.

The 349 native differential, 54 forwarding and 43 synthetic installer cases
pass with ASan/UBSan. The official-image mapping check also passes: all seven
real sections and 1,996 DIR64 relocations are modeled in an inert host buffer,
the actual installer accepts the full pinned image, changes only IAT bytes
`0xa5358..0xa535f`, and restores page `0xa5000` from RW to R. The original file
is unchanged. This check executes no PE instructions and proves no login.
