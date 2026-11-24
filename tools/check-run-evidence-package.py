#!/usr/bin/env python3
"""Read-only verification of actual linked observer and package identities."""
import argparse,plistlib,zipfile,json,hashlib
p=argparse.ArgumentParser();p.add_argument('--ipa',required=True);a=p.parse_args()
with zipfile.ZipFile(a.ipa) as z:
    info=plistlib.loads(z.read('Payload/Madeira.app/Info.plist'))
    image=z.read('Payload/Madeira.app/Madeira.debug.dylib')
    assert info['CFBundleIdentifier']=='com.willfaust.madeora'
    for marker in [b'[run-evidence-v1]',b'_madeira_evidence_poll',b'_ios_evidence_access',b'_madeira_evidence_frame',b'_madeira_evidence_host_io',b'_madeira_evidence_host_vm_events',b'_madeira_evidence_resource',b'resource-request-result',b'guest-process-exit',b'madeira-evidence-v1',b'_mach_vm_page_query',b'external-retire-no-killpages-v1',b'recorder-persistence',b'sampled-host-page-metadata',b'main-runtime-operations',b'main-PC-resolution',b'_ios_runtime_begin',b'_ios_native_rip_from_hostpc_budget',b'controller-discovery']:
        assert marker in image, 'missing linked evidence producer/consumer: '+repr(marker)
    for marker in [b'_winios_input_snapshot',b'_ios_thread_process_try_pid_identity',b'input-path-progress',b'resource-failures-first.jsonl',b'incident-first.jsonl']:
        assert marker in image, 'missing Run20 linked input/retention component: '+repr(marker)
    for marker in [b'launch-progress',b'source-freshness.json',b'_winios_launch_window_snapshot',b'_winios_reveal_session_view',b'no-CS2-process-start-observed',b'routeAgeNS']:
        assert marker in image, 'missing Run21 launch/freshness component: '+repr(marker)
    components=info['MadeiraEvidenceComponents'];assert components['schema']=='madeira-evidence-v1'
    assert len(components['FEX'])==len(components['wine'])==len(components['dxmt'])==40
    assert info['MadeiraEvidenceSymbolArtifact'].startswith('Madeira-native-symbols:')
    print(json.dumps({'schema':'madeira-evidence-package-v1','provenance':info['MadeiraNativeBuildProvenance'],'components':components,'symbols':info['MadeiraEvidenceSymbolArtifact'],'IPA_SHA256':hashlib.sha256(open(a.ipa,'rb').read()).hexdigest(),'linkedObserver':True},sort_keys=True))
