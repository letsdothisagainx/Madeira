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

Host tests and a successful IPA build do not validate the iPhone runtime. The
isolated genuine Steam probe has loaded the I386 helper and CEF libraries after
the ImageBase correction, but has not yet verified a rendered login form. Native
startup, responsive authenticated Library navigation, five-minute stability and
CS2 process creation remain required device acceptance tests.
