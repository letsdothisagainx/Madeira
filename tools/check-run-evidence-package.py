#!/usr/bin/env python3
"""Read-only verification of actual linked observer and package identities."""
import argparse,plistlib,zipfile,json,hashlib
p=argparse.ArgumentParser();p.add_argument('--ipa',required=True);a=p.parse_args()
with zipfile.ZipFile(a.ipa) as z:
    info=plistlib.loads(z.read('Payload/Madeira.app/Info.plist'))
    image=z.read('Payload/Madeira.app/Madeira.debug.dylib')
    assert info['CFBundleIdentifier']=='com.willfaust.madeora'
    for marker in [b'[run-evidence-v1]',b'_madeira_evidence_poll',b'_ios_evidence_access',b'_madeira_evidence_frame',b'_madeira_evidence_host_io',b'madeira-evidence-v1']:
        assert marker in image, 'missing linked evidence producer/consumer: '+repr(marker)
    components=info['MadeiraEvidenceComponents'];assert components['schema']=='madeira-evidence-v1'
    assert len(components['FEX'])==len(components['wine'])==len(components['dxmt'])==40
    assert info['MadeiraEvidenceSymbolArtifact'].startswith('Madeira-native-symbols:')
    print(json.dumps({'schema':'madeira-evidence-package-v1','provenance':info['MadeiraNativeBuildProvenance'],'components':components,'symbols':info['MadeiraEvidenceSymbolArtifact'],'IPA_SHA256':hashlib.sha256(open(a.ipa,'rb').read()).hexdigest(),'linkedObserver':True},sort_keys=True))
