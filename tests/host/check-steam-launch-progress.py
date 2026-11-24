#!/usr/bin/env python3
"""Run21 public stage, freshness and input fixtures; no guest execution/faults."""
from pathlib import Path
import argparse,json,os,shutil,subprocess,tempfile
r=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--require-swift',action='store_true');a=p.parse_args()
lib=(r/'app/Madeira/Library.swift').read_text();native=(r/'app/Madeira/Winios/Winios.m').read_text();cef=(r/'app/Madeira/SteamLibraryDiagnostics.swift').read_text()
reveal=lib[lib.index('    func openSteamSession()'):lib.index('    private func sampleSteamLaunchWindows')]
assert 'LibraryKeyboard.hide();menu=false' in reveal and 'ownsInput:false' in reveal and 'winios_reveal_session_view()' in reveal
assert 'SteamLibraryDiagnostics' not in reveal and 'await' not in reveal and 'post_key' not in reveal
snapshot=native[native.index('int winios_launch_window_snapshot('):native.index('/* Explicit user handoff only.')]
assert 'pthread_mutex_trylock' in snapshot and 'g_layer_tickets' in snapshot and 'ios_thread_process_try_pid_identity' in snapshot
assert all(x not in snapshot for x in ['send_request','set_focus','fprintf','dispatch_sync','thread_suspend'])
assert 'winios_restore_born_minimized_enabled() && atomic_load(&g_census_on)!=3' in native
assert 'uiTotal<(attentionBudget>0 ? 24 : 16)' in cef and 'attentionBudget<4' in cef
assert 'nativeSteamAppID:nativeSteamClient ? effectiveProfile.steamAppID : nil' in (r/'app/Madeira/ContentView.swift').read_text()
print('user-directed real-view handoff independent of CEF; passive generation-checked try-only window census; total 24 UI queries; existing focus protections PASS')
swift=os.getenv('SWIFTC') or shutil.which('swiftc')
if not swift:
 if a.require_swift:raise SystemExit('Swift required')
 print('Swift fixture unavailable locally');raise SystemExit(0)
with tempfile.TemporaryDirectory() as d:
 t=Path(d)
 (t/'Stubs.swift').write_text('import Foundation\nenum LibraryError:Error{case message(String)}\n')
 writer=(r/'app/Madeira/SavesAndShortcuts.swift').read_text();writer=writer[writer.index('final class SaveZipWriter {'):writer.index('// MARK: - Zip reading')]
 (t/'Writer.swift').write_text('import Foundation\nimport zlib\n'+writer)
 (t/'module.modulemap').write_text('module zlib [system] { header "/usr/include/zlib.h" link "z" export * }\n' if os.uname().sysname!='Darwin' else 'module zlib [system] { header "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/zlib.h" link "z" export * }\n')
 # Use the selected SDK instead of assuming a CommandLineTools installation.
 if os.uname().sysname=='Darwin':
  sdk=subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip()
  (t/'module.modulemap').write_text(f'module zlib [system] {{ header "{sdk}/usr/include/zlib.h" link "z" export * }}\n')
 (t/'Check.swift').write_text(r'''import Foundation
@main struct Check {
 static func main() throws {
 let root=URL(fileURLWithPath:CommandLine.arguments[1]);let fm=FileManager.default
 let fixture=try JSONSerialization.jsonObject(with:Data(contentsOf:URL(fileURLWithPath:CommandLine.arguments[2]))) as! [String:Any]
 let tz=TimeZone(secondsFromGMT:-5*3600)!,start=SteamLaunchObservation.date("2026-11-24 09:00:10",timeZone:tz)!.timeIntervalSince1970
 var state=SteamLaunchState(appID:730,requestID:UUID().uuidString,requestedNS:100,requestedWall:start)
 var accepted=0
 for (i,line) in (fixture["steam"] as! [String]).enumerated(){if let o=SteamLaunchObservation.parse(line),state.apply(o,now:UInt64(1000+i),timeZone:tz){accepted+=1}}
 assert(accepted==6 && state.waiting && state.stage=="ShowInterstitials" && state.actionID=="1" && state.cs2Lifetime==nil)
 let row=state.fields(now:9000);assert(row["promptSubtype"] as? String=="unknown" && row["firstObservedCS2PresentationNS"] is NSNull)
 assert(row["stageBeganSourceTimestamp"] as? String=="2026-11-24 09:00:46")
 let secret="PRIVATE_ACCOUNT_PASSWORD_SENTINEL"
 let o=SteamLaunchObservation.parse("[2026-11-24 09:00:46] GameAction [AppID 730, ActionID 1] : LaunchApp waiting for user response to ShowInterstitials "+secret)!
 let encoded=try RunEvidenceSchema.json(["observation":o.stage,"state":row]);assert(!String(data:encoded,encoding:.utf8)!.contains(secret))
 assert(!state.apply(SteamLaunchObservation(appID:440,actionID:"2",stage:"Completed",waiting:false,continued:false,sourceTimestamp:"2026-11-24 09:00:50"),now:10,timeZone:tz))
 assert(!state.apply(SteamLaunchObservation.parse((fixture["steam"] as! [String])[0])!,now:20,timeZone:tz))
 let resume=SteamLaunchObservation.parse("[2026-11-24 09:00:50] GameAction [AppID 730, ActionID 1] : LaunchApp continues with user response")!
 assert(state.apply(resume,now:10000,timeZone:tz) && !state.waiting)
 state.cs2Lifetime="0x123-34";assert(!state.apply(o,now:10001,timeZone:tz))
 assert(SteamLaunchObservation.parse("untrusted "+(fixture["steam"] as! [String]).last!)==nil)
 var old=RunLogSource(initialIdentity:"1:20",initialBytes:100,initialNS:10,identity:"1:20",bytes:100,observedNS:10,modifiedWall:start-3600)
 var metadata:[String:Any]=["runID":"fixture-current","runStartWallUnix":start,"captureNS":"100","sources":["cs2-console":old.fields()]]
 var rel=RunDiagnostics.sourceRelationship("cs2-console",identity:"1:20",bytes:100,metadata:metadata)
 assert((rel["relationship"] as! String).hasPrefix("historical-content-only") && rel["runAppendedBytes"] as? UInt64==0)
 old.observe(identity:"1:20",bytes:180,now:20,modified:start+5);metadata["sources"]=["cs2-console":old.fields()]
 rel=RunDiagnostics.sourceRelationship("cs2-console",identity:"1:20",bytes:200,metadata:metadata)
 assert(rel["runAppendedBytes"] as? UInt64==100 && rel["bytesAfterStructuredObservation"] as? UInt64==20)
 old.observe(identity:"1:21",bytes:30,now:30,modified:start+6);metadata["sources"]=["cs2-console":old.fields()]
 assert(RunDiagnostics.sourceRelationship("cs2-console",identity:"1:21",bytes:30,metadata:metadata)["runAppendedBytes"] is NSNull)
 var truncated=RunLogSource(initialIdentity:"1:20",initialBytes:100,identity:"1:20",bytes:100)
 truncated.observe(identity:"1:20",bytes:5,now:100,modified:nil);assert(truncated.truncations==1)
 assert(RunDiagnostics.sourceRelationship("unknown",identity:"1",bytes:0,metadata:metadata)["runAppendedBytes"] is NSNull)
 var input=[UInt64](repeating:0,count:64);input[0]=1;input[1]=1_000_000;input[38]=100;input[23]=200;input[47]=999_000;input[48]=7;input[25]=500;input[31]=1;input[63]=1
 let ir=RunEvidenceSchema.input(input)!;assert(ir["physicalSlot0Samples"] as? UInt64==0 && ir["samplerInvocations"] as? UInt64==200 && ir["controllerStateAgeNS"] as? UInt64==1000 && ir["routeAgeNS"] as? UInt64==999900)
 assert(ir["physicalSourceAgeNS"] is NSNull && ir["effectiveSourceFlags"] as? UInt64==7)
 let store=try RunEvidenceStore(root:root.appendingPathComponent("store"));store.sourceFreshness(metadata);store.record("launch-progress",row);try store.checkpoint()
 let summary=try JSONSerialization.jsonObject(with:Data(contentsOf:store.directory.appendingPathComponent("run-summary.json"))) as! [String:Any]
 assert((summary["gameplayMetrics"] as! [String:String])["state"]=="unavailable")
 assert((summary["resourceFailureCoverage"] as! [String:Any])["state"] as? String=="game-workload-not-reached")
 let snap=try RunEvidenceStore.snapshotRun(store.directory,destination:root.appendingPathComponent("snapshot"),hostRunning:true)
 assert(snap["launch-progress.jsonl"] != nil && snap["source-freshness.json"] != nil)
 // Exercise real streaming export with immutable structured snapshot and a historical console.
 let docs=root.appendingPathComponent("docs"),console=docs.appendingPathComponent("wine/drive_c/Program Files (x86)/Steam/steamapps/common/Counter-Strike Global Offensive/game/csgo/console.log")
 try fm.createDirectory(at:console.deletingLastPathComponent(),withIntermediateDirectories:true)
 try Data("11/24 03:01:47 Historical CS2 row\n11/24 03:17:53 Old local session\n".utf8).write(to:console)
 let zip=try RunDiagnostics.export(documents:docs,temporaryDirectory:root,evidenceFiles:Dictionary(uniqueKeysWithValues:snap.map{("evidence/"+$0.key,$0.value)}),evidenceAvailability:"snapshot-included")
 assert(fm.fileExists(atPath:zip.path));try Data(zip.path.utf8).write(to:root.appendingPathComponent("zip-path"))
 print("Run21 exact public fixture: fresh ShowInterstitials wait, reused historical ActionID rejected, no current CS2; source byte generations/truncation/cutoff, input ages, unavailable workload and structured one-ZIP export PASS")
 }
}
''')
 subprocess.run([swift,'-swift-version','5','-I',str(t),str(r/'app/Madeira/CS2VACMarkers.swift'),str(r/'app/Madeira/SteamGameDiagnostics.swift'),str(r/'app/Madeira/RunDiagnostics.swift'),str(r/'app/Madeira/RunEvidence.swift'),str(t/'Stubs.swift'),str(t/'Writer.swift'),str(t/'Check.swift'),'-o',str(t/'check')],check=True)
 subprocess.run([str(t/'check'),str(t),str(r/'tests/fixtures/run21-steam-wait.json')],check=True)
 import zipfile
 with zipfile.ZipFile((t/'zip-path').read_text()) as z:
  assert 'evidence/launch-progress.jsonl' in z.namelist() and 'evidence/source-freshness.json' in z.namelist()
  manifest=json.loads(z.read('manifest.json'))
  row=next(s for s in manifest['sources'] if s['source']=='cs2-console')
  assert row['observedSourceTimestampRange']['last']=='11/24 03:17:53'
  assert 'runRelationship' in row
 print('actual ZIP preserves typed launch/source entries, source timestamp range, relationship and current structured cutoff PASS')
