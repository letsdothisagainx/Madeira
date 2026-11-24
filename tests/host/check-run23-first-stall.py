#!/usr/bin/env python3
"""Replay the actual tested/corrected store on ordinary recording data. No IO faults induced."""
from pathlib import Path
import os,shutil,subprocess,tempfile,argparse,hashlib
root=Path(__file__).resolve().parents[2];swift=os.getenv('SWIFTC') or shutil.which('swiftc')
p=argparse.ArgumentParser();p.add_argument('--require-swift',action='store_true');args=p.parse_args()
if not swift:
 if args.require_swift:raise SystemExit('Swift required for the actual first-stall replay')
 print('Swift fixture unavailable on this host; macOS requires it');raise SystemExit(0)
with tempfile.TemporaryDirectory() as d:
 p=Path(d)
 (p/'Stubs.swift').write_text('import Foundation\nenum SteamGameDiagnostics { static func openOwned(_ root: Int32, _ parts: [String]) -> Int32? { nil } }\n')
 (p/'Check.swift').write_text('''import Foundation
@main struct Check { static func main() throws {
 let root=URL(fileURLWithPath:CommandLine.arguments[1]);let store=try RunEvidenceStore(root:root)
 store.record("timeline",["event":"resource-failure-before-activation"]);store.incident("resource-admission-failure")
 let first=try Data(contentsOf:store.directory.appendingPathComponent("incident-first.jsonl"))
 store.record("timeline",["event":"remote-activated"]);store.record("thread-frame-memory",["event":"main-progress","fixture":"remote-first-stall"])
 store.incident("post-activation-frame-stall");store.incident("disconnect-timeout")
 let path=store.directory.appendingPathComponent("incident-post-activation-first.jsonl")
 let found=FileManager.default.fileExists(atPath:path.path)
 let expected=CommandLine.arguments[2]=="corrected"
 guard found==expected else{print("unexpected first-stall presence");exit(1)}
 let stillFirst=try Data(contentsOf:store.directory.appendingPathComponent("incident-first.jsonl"));guard first==stillFirst else{exit(1)}
 if expected {
  try store.checkpoint();let exported=try RunEvidenceStore.snapshotRun(store.directory,destination:root.appendingPathComponent("export"),hostRunning:true)
  guard exported["incident-post-activation-first.jsonl"] != nil else{exit(1)}
 }
 print(expected ? "corrected actual store: first stall exported; higher-priority first resource window preserved PASS" : "tested baseline reproduced: resource priority suppresses dedicated first stall")
}}''')
 baseline=(root/'tests/fixtures/run23-incident-949.swift').read_text()
 assert hashlib.sha256(baseline.encode()).hexdigest()=='96655c2bcc22cae09eb3a98cf65e3f8ca8b6db22dcbabe0713fc8016bc7da2e1'
 source=(root/'app/Madeira/RunEvidence.swift').read_text();start=source.index('    func incident(_ reason:String) {');end=source.index('    @discardableResult static func copy(',start)
 (p/'Baseline.swift').write_text(source[:start]+baseline+source[end:])
 for label,source in [('baseline',p/'Baseline.swift'),('corrected',root/'app/Madeira/RunEvidence.swift')]:
  subprocess.run([swift,'-swift-version','5',str(source),str(p/'Stubs.swift'),str(p/'Check.swift'),'-o',str(p/label)],check=True)
  subprocess.run([str(p/label),str(p/(label+'-data')),label],check=True)
