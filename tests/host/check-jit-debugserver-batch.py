#!/usr/bin/env python3
"""Exercise Apple's real debugserver sparse-write batch on an owned child.

This is a bounded native protocol/byte-integrity and host timing test. It is
not a simulation of debugserver, an iOS CSM test, or a CS2/VAC acceptance test.
Linux explicitly skips; Apple CI can require the real tool with
--require-debugserver. No game, prefix, or authentication data is accessed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import tempfile
import time

PAGE = 0x4000
SIZE = 16 << 20
PAGES = SIZE // PAGE

CHILD = r'''
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#define BYTES ((mach_vm_size_t)16 << 20)
#define PAGE ((mach_vm_size_t)0x4000)
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "native debugserver child line %d: %s\n", __LINE__, #x); exit(2); } } while (0)
struct span { mach_vm_address_t source, rx; };
static mach_vm_address_t high_slot(void)
{
    /* Fixed, non-overwriting requests only. The second band is a host-test
     * alternative, never an iOS allocation policy or a claim about its map. */
    const mach_vm_address_t bands[][2] = {
        {UINT64_C(0x7c00000000), UINT64_C(0x8000000000)},
        {UINT64_C(0x10000000000), UINT64_C(0x10010000000)}
    };
    for (unsigned i = 0; i < sizeof(bands) / sizeof(bands[0]); ++i)
        for (mach_vm_address_t at = bands[i][0]; at + BYTES <= bands[i][1]; at += BYTES) {
            mach_vm_address_t result = at;
            kern_return_t status = mach_vm_allocate(mach_task_self(), &result, BYTES, VM_FLAGS_FIXED);
            if (status == KERN_SUCCESS) { CHECK(result == at); return result; }
            CHECK(status == KERN_NO_SPACE || status == KERN_INVALID_ADDRESS);
        }
    CHECK(0); return 0;
}
static struct span allocate(void)
{
    struct span s = {0}; vm_prot_t current = 0, maximum = 0;
    CHECK(mach_vm_allocate(mach_task_self(), &s.source, BYTES, VM_FLAGS_ANYWHERE) == KERN_SUCCESS);
    CHECK(mach_vm_protect(mach_task_self(), s.source, BYTES, FALSE,
                         VM_PROT_READ | VM_PROT_EXECUTE) == KERN_SUCCESS);
    s.rx = high_slot();
    CHECK(mach_vm_remap(mach_task_self(), &s.rx, BYTES, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                       mach_task_self(), s.source, FALSE, &current, &maximum,
                       VM_INHERIT_NONE) == KERN_SUCCESS);
    CHECK(current == (VM_PROT_READ | VM_PROT_EXECUTE));
    return s;
}
static void census(FILE *f, mach_vm_address_t start)
{
    mach_vm_address_t cursor = start, end = start + BYTES;
    unsigned count = 0;
    fputc('[', f);
    while (cursor < end) {
        mach_vm_address_t at = cursor; mach_vm_size_t size = 0;
        natural_t depth = 0; vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t n = VM_REGION_SUBMAP_INFO_COUNT_64;
        CHECK(mach_vm_region_recurse(mach_task_self(), &at, &size, &depth,
              (vm_region_recurse_info_t)&info, &n) == KERN_SUCCESS);
        CHECK(!info.is_submap && at <= cursor && size && at + size > cursor);
        mach_vm_address_t next = at + size < end ? at + size : end;
        fprintf(f, "%s{\"offset\":%llu,\"length\":%llu,\"object\":%u,\"backing\":%llu,\"protection\":%d}",
                count++ ? "," : "", (unsigned long long)(cursor - start),
                (unsigned long long)(next - cursor), info.object_id,
                (unsigned long long)(info.offset + cursor - at), info.protection);
        cursor = next;
        CHECK(count < 4096);
    }
    fputc(']', f);
}
int main(int argc, char **argv)
{
    CHECK(argc == 3);
    struct span serial = allocate(), batch = allocate();
    FILE *f = fopen(argv[1], "w"); CHECK(f);
    fprintf(f, "{\"serial\":%llu,\"batch\":%llu,\"bytes\":%llu,\"before\":{\"serialSource\":",
            (unsigned long long)serial.rx, (unsigned long long)batch.rx,
            (unsigned long long)BYTES);
    census(f, serial.source); fputs(",\"serialRX\":", f); census(f, serial.rx);
    fputs(",\"batchSource\":", f); census(f, batch.source);
    fputs(",\"batchRX\":", f); census(f, batch.rx); fputs("}}\n", f);
    CHECK(!fclose(f));
    raise(SIGSTOP);
    /* Read the actual inferior bytes, not debugserver's breakpoint-shadow
     * memory reader: every original byte and every neighbour must survive. */
    const volatile unsigned char *a = (const void *)(uintptr_t)serial.rx;
    const volatile unsigned char *b = (const void *)(uintptr_t)batch.rx;
    unsigned failures = 0;
    for (mach_vm_size_t i = 0; i < BYTES; ++i) {
        failures += a[i] != (i % PAGE ? 0 : 0x69);
        failures += b[i] != 0;
    }
    f = fopen(argv[2], "w"); CHECK(f);
    fprintf(f, "{\"failures\":%u,\"after\":{\"serialSource\":", failures);
    census(f, serial.source); fputs(",\"serialRX\":", f); census(f, serial.rx);
    fputs(",\"batchSource\":", f); census(f, batch.source);
    fputs(",\"batchRX\":", f); census(f, batch.rx); fputs("}}\n", f);
    CHECK(!fclose(f));
    CHECK(mach_vm_deallocate(mach_task_self(), serial.source, BYTES) == KERN_SUCCESS);
    CHECK(mach_vm_deallocate(mach_task_self(), serial.rx, BYTES) == KERN_SUCCESS);
    CHECK(mach_vm_deallocate(mach_task_self(), batch.source, BYTES) == KERN_SUCCESS);
    CHECK(mach_vm_deallocate(mach_task_self(), batch.rx, BYTES) == KERN_SUCCESS);
    return failures ? 1 : 0;
}
'''


def unescape(data):
    out = bytearray()
    i = 0
    while i < len(data):
        value = data[i]
        if value == 0x7d:
            i += 1
            if i == len(data):
                raise RuntimeError('truncated remote binary escape')
            value = data[i] ^ 0x20
        out.append(value)
        i += 1
    return bytes(out)


class Remote:
    def __init__(self, connection):
        self.connection = connection
        self.buffer = bytearray()
        self.no_ack = False
        self.commands = 0
        self.sent = 0
        self.stops = []

    def byte(self):
        if not self.buffer:
            block = self.connection.recv(65536)
            if not block:
                raise RuntimeError('debugserver closed its connection')
            self.buffer.extend(block)
        value = self.buffer[0]
        del self.buffer[0]
        return value

    def packet(self):
        while True:
            value = self.byte()
            if value in (0x24, 0x25):  # ordinary packet or notification
                break
            if value == 0x2d:
                raise RuntimeError('debugserver rejected packet checksum')
        payload = bytearray()
        while True:
            value = self.byte()
            if value == 0x23:
                break
            payload.append(value)
            if len(payload) > 1 << 20:
                raise RuntimeError('unbounded debugserver reply')
        checksum = bytes((self.byte(), self.byte()))
        # Apple's no-ack mode deliberately transmits #00 without computing
        # a checksum (RNBRemote::SendPacket). Before negotiation it is strict.
        if not self.no_ack and int(checksum, 16) != sum(payload) & 255:
            raise RuntimeError('debugserver reply checksum mismatch')
        if not self.no_ack:
            self.connection.sendall(b'+')
        return unescape(payload).decode('ascii')

    def request(self, text, stop=False):
        payload = text.encode('ascii')
        self.commands += 1
        self.sent += len(payload)
        self.connection.sendall(b'$' + payload + b'#' + f'{sum(payload) & 255:02x}'.encode())
        while True:
            reply = self.packet()
            if reply.startswith('O') and reply != 'OK' and len(reply) % 2 == 1:
                # Program console output is not a protocol result.
                continue
            if reply.startswith(('T', 'S')) and not stop:
                self.stops.append(reply)
                continue
            return reply


def supported(tool):
    if platform.system() != 'Darwin':
        return False, 'real Apple debugserver requires Darwin'
    if platform.machine() not in ('arm64', 'aarch64'):
        return False, 'owned software-breakpoint test requires an ARM64 Apple host'
    if not tool:
        return False, 'xcrun did not locate Apple debugserver'
    return True, ''


def census_summary(value):
    return {name: {'regions': len(rows), 'first': rows[:2], 'last': rows[-2:],
                   'sha256': hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()}
            for name, rows in value.items()}


def run_test(debugserver):
    with tempfile.TemporaryDirectory(prefix='madeira-real-debugserver-') as directory:
        root = Path(directory)
        source, binary = root / 'owned.c', root / 'owned'
        ready, result, logs = root / 'ready.json', root / 'result.json', root / 'debugserver.log'
        source.write_text(CHILD)
        subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', '-D_DARWIN_C_SOURCE',
                        '-Wall', '-Wextra', '-Werror', str(source), '-o', str(binary)],
                       check=True, timeout=60)
        entitlement = root / 'owned.entitlements'
        entitlement.write_text('<?xml version="1.0"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>')
        subprocess.run(['codesign', '--force', '--sign', '-', '--entitlements', str(entitlement),
                        str(binary)], check=True, timeout=30, capture_output=True)
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
        listener.close()
        with logs.open('wb') as stream:
            server = subprocess.Popen([str(debugserver), f'127.0.0.1:{port}', str(binary),
                                       str(ready), str(result)], stdout=stream, stderr=stream)
        connection = None
        try:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline and server.poll() is None:
                try:
                    connection = socket.create_connection(('127.0.0.1', port), timeout=1)
                    break
                except OSError:
                    time.sleep(.05)
            if connection is None:
                raise RuntimeError('owned debugserver did not accept a connection')
            connection.settimeout(20)
            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            remote = Remote(connection)
            features = remote.request('qSupported')
            if 'jMultiBreakpoint+' not in features.split(';'):
                raise RuntimeError('real debugserver does not advertise jMultiBreakpoint+: ' + features)
            sizes = [int(x.split('=', 1)[1], 16) for x in features.split(';') if x.startswith('PacketSize=')]
            maximum = sizes[0] if sizes else 4096
            if remote.request('QStartNoAckMode') == 'OK':
                remote.no_ack = True
            remote.request('?', stop=True)
            for _ in range(8):
                if ready.exists():
                    break
                reply = remote.request('c', stop=True)
                if reply.startswith(('W', 'X', 'E')):
                    raise RuntimeError('owned child could not reach its prepared stop: ' + reply)
            if not ready.exists():
                raise RuntimeError('owned child did not publish its bounded RX mappings')
            info = json.loads(ready.read_text())
            assert info['bytes'] == SIZE
            print('REAL_DEBUGSERVER features=' + features, flush=True)
            print('REAL_DEBUGSERVER before=' + json.dumps(census_summary(info['before']), separators=(',', ':')), flush=True)

            serial_start = time.monotonic()
            count = remote.commands
            for page in range(PAGES):
                assert remote.request(f'M{info["serial"] + page * PAGE:x},1:69') == 'OK'
            serial_elapsed, serial_calls = time.monotonic() - serial_start, remote.commands - count

            batch_start = time.monotonic()
            count = remote.commands
            page = 0
            while page < PAGES:
                requests = []
                while page < PAGES and len(requests) < 256:
                    address = info['batch'] + page * PAGE
                    extra = [f'Z0,{address:x},4', f'z0,{address:x},4']
                    candidate = 'jMultiBreakpoint:' + json.dumps({'breakpoint_requests': requests + extra}, separators=(',', ':'))
                    if len(candidate) > maximum:
                        break
                    requests.extend(extra)
                    page += 1
                assert requests, 'advertised packet capacity cannot hold one breakpoint pair'
                command = 'jMultiBreakpoint:' + json.dumps({'breakpoint_requests': requests}, separators=(',', ':'))
                reply = json.loads(remote.request(command))
                assert isinstance(reply, dict) and reply.get('results') == ['OK'] * len(requests), reply
            batch_elapsed, batch_calls = time.monotonic() - batch_start, remote.commands - count
            reply = remote.request('c', stop=True)
            assert reply.startswith('W00'), 'owned byte-integrity child failed: ' + reply
            assert result.exists(), 'owned child did not report direct memory checks'
            outcome = json.loads(result.read_text())
            assert outcome['failures'] == 0, outcome
            print('REAL_DEBUGSERVER after=' + json.dumps(census_summary(outcome['after']), separators=(',', ':')), flush=True)
            print(json.dumps({'scope': 'actual Apple debugserver; owned 16MiB RX mapping; host transport timing only',
                              'pages': PAGES, 'serialM': {'commands': serial_calls, 'milliseconds': round(serial_elapsed * 1000, 3)},
                              'pairedBreakpointBatch': {'commands': batch_calls, 'milliseconds': round(batch_elapsed * 1000, 3)},
                              'directInferiorByteFailures': 0, 'iosCSM': 'unmeasured', 'iphoneStartup': 'unmeasured'}, sort_keys=True), flush=True)
            print('PASS real debugserver: full-width sparse batch, every pair cleared, all owned bytes/neighbours intact; no game or iPhone claim', flush=True)
        except BaseException:
            if connection:
                try:
                    # If a breakpoint response is ambiguous, the owned test
                    # inferior is killed; never resume it with unknown state.
                    connection.sendall(b'$k#6b')
                except OSError:
                    pass
            print(logs.read_text(errors='replace')[-6000:], flush=True)
            raise
        finally:
            if connection:
                connection.close()
            if server.poll() is None:
                server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-debugserver', action='store_true')
    args = parser.parse_args()
    tool = None
    if platform.system() == 'Darwin':
        located = subprocess.run(['xcrun', '--find', 'debugserver'], capture_output=True, text=True)
        tool = Path(located.stdout.strip()) if located.returncode == 0 else None
        if not tool or not tool.is_file():
            selected = subprocess.run(['xcode-select', '-p'], capture_output=True, text=True, check=True)
            developer = Path(selected.stdout.strip())
            candidates = [developer.parent / 'SharedFrameworks/LLDB.framework/Resources/debugserver',
                          developer.parent / 'SharedFrameworks/LLDB.framework/Versions/A/Resources/debugserver',
                          developer / 'Library/PrivateFrameworks/LLDB.framework/Resources/debugserver']
            tool = next((p for p in candidates if p.is_file()), None)
        if tool and not tool.is_file():
            tool = None
    available, reason = supported(tool)
    if not available:
        if args.require_debugserver:
            raise SystemExit('FAIL real debugserver required: ' + reason)
        print('UNMEASURED real debugserver: ' + reason)
        return
    run_test(tool)


if __name__ == '__main__':
    main()
