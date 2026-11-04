# Native Steam browser compatibility candidate

The current AMD64 Steam core is retained. Its official AMD64 Chromium allocator
requires fixed 16 GiB pools and temporary reservations that cannot complete in
the measured iPhone task map ending at `0xfc0000000`. Allocation success, fixed
addresses, versions and Chromium assertions are not fabricated.

This candidate uses a separately verified official I386 browser tree outside the
Steam installation. A source-built guest AMD64 DLL translates shared-memory
HTMLIPC frames while keeping the current controller, callback objects and stream
objects. The 152 command pairs and transitive protobuf schemas are pinned to the
inspected core and browser builds. BrowserCreate has an explicit field conversion;
other accepted payloads retain their original bytes. Unsupported operations fail
explicitly. This is not a claim that every current Steam feature is compatible.

The installer verifies the original chromehtml SHA-256, live immutable sections,
DIR64 relocations, metadata and protections. Wine's loader may rewrite only the
validated ImageBase field to the actual mapping base. The hooks modify data pages
with checked R-to-RW-to-R transitions; executable instructions and RWX mappings
are not introduced.

Native Wine preloads the source DLL through its ordinary guest PE loader. It reads
an exported DATA record tied to the current PID, PEB and owner lease before each
coherent helper-path and argv0 redirect. Native ARM64 never directly invokes an
AMD64 export. Missing readiness, wrong architecture and stale ownership fail
closed. Existing Steam restart and process-retirement behavior remains in place.

The app prepares a size/hash/architecture-verified cache before starting Wine.
It also selects the exact official I386 SDL3.dll from the matching frozen core
archive into the helper directory. The original AMD64 Steam SDL3.dll is kept;
the 78-file CEF/helper subset alone lacked this required delayed dependency.
Archive extraction, atomic completion, reuse and owned bridge installation have
focused tests. It does not replace Steam's core, authentication files, original
CEF tree, game manifests or CS2 files.

The official I386 CEF ZIP also contains one AMD64 diagnostic DLL,
`msdia140.dll` (2,245,784 bytes, SHA-256
`484dee047c0f2a6e556056ad994ef6a9b846a676a067883257c7122c46c97d66`).
The original cache verifier incorrectly required every PE in this package to be
I386, rejecting the first archive before Wine started. That member now has an
explicit name/size/hash/AMD64 pin, checked on extraction and cache reuse. The
browser executable, libcef, chrome_elf and SDL3 remain I386. Unknown AMD64 members
and altered files are rejected. CI exercises the production Swift with all three
genuine pinned archives, atomic completion, reuse and tamper rejection in
addition to the small malformed-archive and transaction fixtures.

Controller validation also accepts `PAGE_WRITECOPY` for the writable controller
object in the already verified image. Wine maps non-shared writable PE sections
with that logical protection; requiring only `PAGE_READWRITE` rejected that
legitimate mapping. This exception is restricted to that object, with the same
committed `MEM_IMAGE`, allocation-base and 42-entry vtable checks. Code, hook and
readonly-data validation retains its exact protections. Validation changes no
page permissions. Unexpected owners, private/reserved memory, failed queries,
changed vtables and executable/writable protections remain rejected. The first
controller mismatch emits a bounded numeric diagnostic after releasing the
registry lock.

Command 54 (`CMsgSetBrowserViewDomainRequestMapping`) is a passive global
registration, with replacement/removal semantics; it does not immediately map a
browser or serve files. Exact current SteamUI and web-resource inspection shows
startup registration enumerates custom screensaver directories and registers
`%s.steamscreensavers.host`. The ordinary shared UI separately installs its
existing per-browser `https://steamloopback.host` route with command 60. The one
`bBrowserViewDomainMapping` consumer in the pinned web package is the optional
custom Screensaver BrowserView, not the ordinary Library.

The connected adapter now implements registration as real generation-owned
state. Protobuf optional fields use last-value semantics; const-char strings
retain the genuine helper's first-NUL behavior. Replacements allocate before
committing, failed allocations retain prior entries, and retirement frees state
only after callbacks have drained. A complete registration is acknowledged only
after it commits. It is never forwarded as the legacy opcode 54 (which means
ClearHistory). Ordinary frames retain their original partial-write, backpressure
and ordering behavior. Unknown commands still fail explicitly.

This does not implement custom Screensaver routing. No global mapping is
converted into a blanket per-browser mapping or added to the old helper's file
policy. Commands 53 (SetBlockInput) and 108 (InputBlocked) remain unsupported.
The current helper's actual routed path depends on type 3, explicit opt-in,
empty existing mapping and the empty-POST pre-navigation branch, with different
file-access policy; silently emulating that path would be incorrect. Future
routing support must preserve those conditions and child/popup lifetimes.

Host tests, build success and IPC connection are distinct from UI validation.
The latest iPhone log identifies source `02c525c` and proves cache verification
and connection succeeded before rejection of command 54. The revised source
requires genuine login-frame testing, then authenticated Library navigation,
five-minute on-device responsiveness and normal CS2 process creation. No Steam
JavaScript, installed game, account data or authentication check is changed.
