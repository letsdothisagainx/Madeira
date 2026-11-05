#!/usr/bin/env python3
"""Real stock Chromium off/on check of the production observer's expressions.

Requires a local Chrome/Chromium executable and websockets==16.0 (Python>=3.10).
Uses synthetic page data, a loopback listener and disposable browser profiles.
This is a host noninterference regression, not a Steam CEF/iOS causal A/B.
The production Swift observer itself is exercised by the macOS host fixture.
"""
import argparse
import asyncio
import errno
import http.server
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import threading
import urllib.request
from urllib.parse import parse_qs, urlparse

import websockets

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--browser', default=os.environ.get('CHROME_BIN'))
args = parser.parse_args()
browser = args.browser or next((shutil.which(name) for name in (
    'google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser') if shutil.which(name)), None)
assert browser, 'Chrome/Chromium unavailable; provide --browser or CHROME_BIN'
source = (ROOT / 'app/Madeira/SteamLibraryDiagnostics.swift').read_text()
expressions = {name: source.split('static let ' + name + ' = #"""', 1)[1].split('"""#', 1)[0].strip()
               for name in ['snapshotExpression', 'uiMessageExpression']}
assert source.count('"throwOnSideEffect": true') == 2
reports = {}
ready = set()


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *unused):
        pass

    def do_GET(self):
        mode = parse_qs(urlparse(self.path).query).get('mode', ['off'])[0]
        guard = ("Object.defineProperty(globalThis,'appStore',{get(){getterCalls++;return stored},configurable:true});"
                 if mode == 'guard' else 'globalThis.appStore=stored;')
        body = ('''<!doctype html><body>Failed to load. A newer version of the Steam Client is required to run this application<script>
let heartbeat=0,nativeCalls=0,getterCalls=0;
const original=()=>{nativeCalls++;return Promise.resolve()};
globalThis.SteamClient={Apps:{GetAppOverview:original}};
const stored={m_bIsInitialized:true,m_mapApps:new Map([[730,{appid:730}]])};
''' + guard + '''
const globalsBefore=Object.keys(globalThis).sort();
setInterval(()=>{heartbeat++},10);
fetch('/ready?mode=''' + mode + '''',{method:'POST',body:'ready'});
setTimeout(()=>{fetch('/report?mode=''' + mode + '''',{method:'POST',body:JSON.stringify({heartbeat,nativeCalls,getterCalls,count:stored.m_mapApps.size,originalUnchanged:SteamClient.Apps.GetAppOverview===original,globalsUnchanged:JSON.stringify(globalsBefore)===JSON.stringify(Object.keys(globalThis).sort())})})},6500);
</script>''').encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        mode = parse_qs(urlparse(self.path).query)['mode'][0]
        size = int(self.headers.get('Content-Length', '0'))
        assert 0 < size < 2048
        body = self.rfile.read(size)
        if urlparse(self.path).path == '/ready':
            ready.add(mode)
        else:
            reports[mode] = json.loads(body)
        self.send_response(204)
        self.end_headers()


server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
# Loopback fixture requests always stay local; inherited external proxy settings
# remain intact for the browser and all unrelated traffic.
local_http = urllib.request.build_opener(urllib.request.ProxyHandler({}))


async def run(mode):
    with tempfile.TemporaryDirectory(prefix='madeira-observer-ab-') as profile:
        command = [browser, '--headless', '--no-sandbox', '--disable-gpu',
                   '--disable-background-networking', '--disable-component-update',
                   '--disable-default-apps', '--no-first-run', '--disable-background-timer-throttling',
                   '--disable-renderer-backgrounding', '--user-data-dir=' + profile]
        if mode != 'off':
            command += ['--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0']
        command += [f'http://127.0.0.1:{server.server_port}/?mode={mode}']
        # Own the entire fixture browser group, including asynchronous profile
        # writers. Waiting only for the main process can race directory cleanup.
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   start_new_session=True)
        outcomes = []
        try:
            for _ in range(200):
                if mode in ready:
                    break
                assert process.poll() is None, 'browser exited before fixture startup'
                await asyncio.sleep(.05)
            assert mode in ready, 'fixture did not initialize within ten seconds'
            if mode != 'off':
                info = Path(profile) / 'DevToolsActivePort'
                for _ in range(200):
                    if info.exists():
                        break
                    assert process.poll() is None, 'browser exited before inspector startup'
                    await asyncio.sleep(.05)
                assert info.exists(), 'inspector did not start within ten seconds'
                debug_port = int(info.read_text().splitlines()[0])
                targets = []
                for _ in range(100):
                    with local_http.open(f'http://127.0.0.1:{debug_port}/json/list', timeout=1) as reply:
                        targets = [target for target in json.load(reply)
                                   if target['type'] == 'page' and '?mode=' + mode in target['url']]
                    if targets:
                        break
                    await asyncio.sleep(.05)
                assert targets, 'fixture page not discovered'
                async with websockets.connect(targets[0]['webSocketDebuggerUrl'], max_size=2_000_000) as socket:
                    sequence = 0

                    async def cdp(method, params=None):
                        nonlocal sequence
                        sequence += 1
                        number = sequence
                        await socket.send(json.dumps({'id': number, 'method': method, 'params': params or {}}))
                        deadline = asyncio.get_running_loop().time() + 3
                        while True:
                            event = json.loads(await asyncio.wait_for(
                                socket.recv(), max(0, deadline - asyncio.get_running_loop().time())))
                            if event.get('id') == number:
                                assert 'error' not in event, event
                                return event.get('result', {})

                    for method in ['Runtime.enable', 'Page.enable', 'Log.enable', 'Network.enable']:
                        await cdp(method, {'maxPostDataSize': 0, 'maxTotalBufferSize': 1_048_576,
                                           'maxResourceBufferSize': 16_384} if method == 'Network.enable' else {})

                    async def evaluate(name):
                        result = await cdp('Runtime.evaluate', {
                            'expression': expressions[name], 'returnByValue': True,
                            'throwOnSideEffect': True, 'timeout': 500})
                        outcomes.append({'purpose': name, 'exception': bool(result.get('exceptionDetails')),
                                         'value': result.get('result', {}).get('value')})

                    for name in expressions:
                        await evaluate(name)
                    if mode == 'on':
                        await asyncio.sleep(5.1)
                        await evaluate('snapshotExpression')
                    for _ in range(200):
                        if mode in reports:
                            break
                        await asyncio.sleep(.05)
            else:
                for _ in range(300):
                    if mode in reports:
                        break
                    assert process.poll() is None, 'browser exited during observer-off run'
                    await asyncio.sleep(.05)
            assert mode in reports, mode + ': page heartbeat report unavailable'
            report = reports[mode]
            assert report['nativeCalls'] == report['getterCalls'] == 0, report
            assert report['count'] == 1 and report['originalUnchanged'] and report['globalsUnchanged'], report
            assert report['heartbeat'] >= 325, report  # detects a multi-second stall, tolerates a busy CI host
            if mode == 'on':
                stores = [query for query in outcomes if query['purpose'] == 'snapshotExpression']
                assert len(stores) == 2 and all(not query['exception'] for query in stores), outcomes
                assert all(query['value'] == {'store': True, 'ready': True, 'count': 1, 'cs2': True, 'apps': True}
                           for query in stores), outcomes
            elif mode == 'guard':
                assert outcomes[0]['exception'], 'side-effect check executed an accessor'
            print(json.dumps({'mode': mode, 'inspectorEnabled': mode != 'off',
                              'report': report, 'queries': outcomes}), flush=True)
        finally:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=3)
            # A renderer may outlive the primary process. This group was
            # created solely for this disposable profile, never a user browser.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            # SIGKILL delivery/profile I/O completion is asynchronous. Retry
            # only ENOTEMPTY on our uniquely owned directory, with a fixed cap.
            for attempt in range(10):
                try:
                    shutil.rmtree(profile)
                    break
                except FileNotFoundError:
                    break
                except OSError as error:
                    if error.errno != errno.ENOTEMPTY or attempt == 9:
                        raise
                    await asyncio.sleep(.1)


async def main():
    for mode in ['off', 'on', 'guard']:
        await run(mode)
    assert reports['on']['heartbeat'] >= reports['off']['heartbeat'] * .7, reports


try:
    print(subprocess.check_output([browser, '--version'], text=True).strip(), flush=True)
    asyncio.run(main())
finally:
    server.shutdown()
    server.server_close()
print('PASS stock Chromium observer-off/on: bounded heartbeat, unchanged synthetic page/API state, checked accessors; Steam CEF/iOS causal A/B remains untested')
