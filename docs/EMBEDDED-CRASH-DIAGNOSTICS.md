# Embedded server startup crash diagnostics

This change starts from the reported successful IPA source commit
`db697bcab8c7c4b498e2fc25709d9d48bb7c3f8b`, retaining Wine at
`df1c5ea51e194937ac204bc3120922dc56a61bec`. The crash addresses and UUID
match are supplied forensic evidence; the original IPS/IPA were not available
for independent binary analysis in this checkout.

## Signal ownership

`WineServerBridge.m` starts `wineserver_main` on a pthread. Its
`main_ios.c` calls upstream `init_signals()`. When core dumps are disabled,
that installs the server's `do_sigsegv` process-wide, which prints a server
crash message and aborts regardless of the faulting thread.

The client startup in `loader_ios.c` allocates the first TEB and registers
its pthread TEB slot before `server_init_process()`. The latter creates its
reply/wait pipes before `server_init_process_done()` installs ntdll's
process-wide handlers via `signal_init_process()`. Thus a fault at the first
pipe can precede ntdll's handlers. FEXBridge's `ios_sigsegv_handler` is defined
but has no installation call in that file; it does not arbitrate this window.

The iOS server now compiles the pinned upstream `signal.c` through
`signal_ios.c`, which declines server SIGSEGV disposition changes. Both fresh
and cached archives replace `signal.o`. It leaves all other server handlers
unchanged and never installs a replacement fault handler. Before client
handlers exist, native faults retain the OS disposition. Afterwards ntdll's
existing foreign-thread path declines host faults to the OS. Guest/FEX
dispatch is unchanged. This removes a confirmed ownership conflict; it does
not establish a fix for the original memory fault.

## Pipe investigation

`init_thread_pipe()` passes a local `int reply_pipe[2]` and the current TEB's
`ntdll_thread_data.wait_fd[2]`, and obtains the alternate stack from the TEB
allocation. Neither array is a nullable allocated pipe buffer. These source
relationships do not prove their values were valid in the reported crash.
Alternate-stack registration errors now stop startup with a named error.

The iOS build force-includes macOS Wine's generated config, including
`HAVE_PIPE2`. Host feature detection is not a target availability guarantee.
iOS now uses Wine's existing `pipe` + `fcntl(FD_CLOEXEC)` path in server and
process code. No fork/exec atomicity guarantee is added: this is the existing
fallback and Madeira's embedded iOS runtime does not fork guest processes.
This is a conservative portability correction, not proof that a missing
`pipe2` symbol caused the observed fault. A `cbz` return instruction alone
cannot establish that cause.

For a diagnostic launch, set `MADEIRA_PIPE_TRACE=1` in the app's runtime
environment. Normal startup code logs the TEB, both output-buffer addresses,
alternate-stack address/size, and before/after pipe stages to stderr. It logs
no paths, game data or credentials and adds no signal-handler logging.
If another crash occurs, collect the new native IPS, launch log and exact
binary UUID. Check which stage completed and symbolicate the new fault.

## Dock packaging and validation

`tools/build-ipa.sh` builds Dock immediately after MinGW setup. Xcode already
copies `arm64ec-windows` as a folder resource. Packaging requires nonempty
staged and bundled `dockhost.exe` and `dock-notices.txt`, then compares both
final ZIP entries with the built app. The existing Dock build generates the
project, exception, GPL and statically linked runtime notices.

Host regression tests exercise real upstream `init_signals()` with the iOS
wrapper and both startup orders, standalone Wine behavior, native SIGSEGV
termination, and real pipe I/O/CLOEXEC with host `HAVE_PIPE2` enabled. Packaging
tests use synthetic Xcode products and verify the ZIP and missing-resource
failures. CI also runs Dock's native sanitizer suite. These host tests do not
validate the iOS executable or device behavior.

On-device validation remains Desktop, Steam, CS2, and subsequently official
VAC secure play. No bundle identifier, prefix migration, game installation,
save data or anti-cheat behavior is changed by this patch.
