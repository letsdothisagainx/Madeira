#!/usr/bin/env python3
"""Exercise upstream signal initialization with the production iOS wrapper,
and the production server_pipe with a macOS HAVE_PIPE2 deliberately defined."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
def function(text, name):
    start = text.index(name)
    end = text.index('{', start) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]

init = function((root / 'wine/server/signal.c').read_text(), 'void init_signals(void)')
stubs = r'''
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <unistd.h>
#include "wineserver_ios_signal.h"
struct handler { int unused; };
static struct handler object, *handler_sighup, *handler_sigterm, *handler_sigint, *handler_sigchld, *handler_sigio;
static void sighup_callback(void) {} static void sigterm_callback(void) {}
static void sigint_callback(void) {} static void sigchld_callback(void) {}
static void sigio_callback(void) {}
static struct handler *create_handler(void (*callback)(void)) { (void)callback; return &object; }
static void do_sigchld(int s) {} static void do_sighup(int s) {}
static void do_sigint(int s) {} static void do_sigalrm(int s) {}
static void do_sigterm(int s) {} static void do_sigsegv(int s) { abort(); }
static int core_dump_disabled(void) { return 1; }
static volatile sig_atomic_t received;
static void guest(int s) { received = s; }
'''
main = r'''
int main(void) {
    struct sigaction action = {0}, result;
    action.sa_handler = guest;
    /* Test both startup orders: default before ntdll, guest installed already. */
    assert(sigaction(SIGSEGV, &action, NULL) == 0);
    init_signals();
    assert(sigaction(SIGSEGV, NULL, &result) == 0);
#ifdef WINE_IOS
    assert(result.sa_handler == guest);
    raise(SIGSEGV); assert(received == SIGSEGV);
    /* Use the real API to simulate a fresh host process with default disposition. */
    action.sa_handler = SIG_DFL;
    assert((sigaction)(SIGSEGV, &action, NULL) == 0);
    init_signals();
    assert(sigaction(SIGSEGV, NULL, &result) == 0 && result.sa_handler == SIG_DFL);
    pid_t child = fork(); assert(child >= 0);
    if (!child) { struct rlimit r = {0,0}; setrlimit(RLIMIT_CORE, &r); raise(SIGSEGV); _exit(99); }
    int status;
    pid_t waited;
    /* Darwin can deliver SIGCHLD before waitpid returns the child status. */
    do { waited = waitpid(child, &status, 0); } while (waited == -1 && errno == EINTR);
    assert(waited == child);
    assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);
#else
    assert(result.sa_handler == do_sigsegv);
#endif
    assert(sigaction(SIGTERM, NULL, &result) == 0 && result.sa_handler == do_sigterm);
    return 0;
}
'''
# Install the guest handler before applying the wrapper (which intentionally
# declines any later server-side replacement).
main = main.replace('assert(sigaction(SIGSEGV, &action, NULL)', 'assert((sigaction)(SIGSEGV, &action, NULL)')
pipe = function((root / 'build/ntdll-unix/server_ios.c').read_text(), 'int server_pipe( int fd[2] )')
pipe_test = r'''
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#define HAVE_PIPE2 1
#define WINE_IOS 1
#define pipe2(...) this_must_not_link()
''' + pipe + r'''
int main(void) {
    int reply[2], wait[2];
    assert(server_pipe(reply) == 0 && server_pipe(wait) == 0);
    for (int i=0; i<2; i++) {
        assert(fcntl(reply[i], F_GETFD) & FD_CLOEXEC);
        assert(fcntl(wait[i], F_GETFD) & FD_CLOEXEC);
    }
    char c; assert(write(reply[1], "r", 1) == 1);
    assert(read(reply[0], &c, 1) == 1 && c == 'r');
    assert(write(wait[1], "w", 1) == 1);
    assert(read(wait[0], &c, 1) == 1 && c == 'w');
    for (int i=0; i<2; i++) { close(reply[i]); close(wait[i]); }
    return 0;
}
'''
with tempfile.TemporaryDirectory() as temp:
    t = Path(temp)
    for name, text, flags in [('embedded', stubs+init+main, ['-DWINE_IOS=1']),
                              ('standalone', stubs+init+main, []), ('pipes', pipe_test, [])]:
        src = t / (name+'.c'); src.write_text(text)
        exe = t / name
        subprocess.run([os.environ.get('CC','cc'), '-std=gnu11', '-Werror=implicit-function-declaration',
                        '-I'+str(root/'build/wineserver'), *flags, str(src), '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)
        print('PASS', name)
build = (root/'build/wineserver/build.sh').read_text()
assert '"signal_ios:signal_ios.c:signal.o"' in build and '"signal_ios.o:signal.o"' in build
assert '#include "signal.c"' in (root/'build/wineserver/signal_ios.c').read_text()
print('PASS signal.o replacement also covers cached base archives')
