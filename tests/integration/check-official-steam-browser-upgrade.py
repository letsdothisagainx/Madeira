#!/usr/bin/env python3
"""Real Swift pre-Wine upgrade: old debug.log -> verified rebuild -> quiet reuse.

Only the download transport is injected, returning fresh owned copies of actual
pinned archives. Core, sizes, hashes, ZIP parsing, architectures, ownership,
commit, retained-tree validation and subsequent reuse are production code.
No Steam account, installed games or Wine/iOS process is used by this harness.
The logging probe executes the staged native NtCreateFile body with real POSIX
file operations; it is a source-handler control, not an on-device claim.
"""
from pathlib import Path
import argparse,hashlib,importlib.util,os,re,shutil,struct,subprocess,tempfile,urllib.request,zipfile
ROOT=Path(__file__).resolve().parents[2]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--download-official',action='store_true')
args=parser.parse_args()
if not args.download_official:parser.error('--download-official required; no implicit network')
assert os.uname().sysname=='Darwin' and shutil.which('swiftc'),'macOS Swift/CryptoKit required'
source=(ROOT/'app/Madeira/SteamBrowserRuntime.swift').read_text()
packages=[(name,int(size.replace('_','')),digest) for name,size,digest in re.findall(
 r'Package\(file: "([A-Za-z0-9_.-]+)", bytes: ([0-9_]+),\s*sha256: "([0-9a-f]{64})"',source)]
assert len(packages)==3
core=('bins_win64.zip.1f91da2609327de9658146b01307e89a13cc1ef8',64_309_479,
      'f34b0d5924d0cca4c81775ed2fef0aee1ca060e2daa5c24270711267786c0236')
core_image_sha=re.search(r'coreSHA256: "([0-9a-f]{64})"',source).group(1)
cache=Path(os.environ['MADEIRA_VALVE_ARCHIVE_CACHE']);cache.mkdir(parents=True,exist_ok=True)
def digest_file(file):
 state=hashlib.sha256()
 with file.open('rb') as stream:
  while chunk:=stream.read(1024*1024):state.update(chunk)
 return state.hexdigest()
for name,size,digest in [*packages,core]:
 file=cache/name
 if not file.is_file():
  url='https://client-update.akamai.steamstatic.com/'+name
  with urllib.request.urlopen(urllib.request.Request(url,headers={'Accept-Encoding':'identity'}),timeout=90) as response:
   assert response.status==200 and response.url==url
   data=response.read(size+1)
  assert len(data)==size and hashlib.sha256(data).hexdigest()==digest
  file.write_bytes(data)
 assert file.stat().st_size==size and digest_file(file)==digest
spec=importlib.util.spec_from_file_location('official_archive',ROOT/'tests/integration/htmlipc/official_archive.py')
archive_policy=importlib.util.module_from_spec(spec);spec.loader.exec_module(archive_policy)
core_bytes=None
with zipfile.ZipFile(cache/core[0]) as archive:
 for entry,path in archive_policy.validated_members(archive):
  if path.as_posix().lower()=='bin/chromehtml.dll':
   assert core_bytes is None;core_bytes=archive.read(entry)
assert core_bytes and hashlib.sha256(core_bytes).hexdigest()==core_image_sha
nt=struct.unpack_from('<I',core_bytes,0x3c)[0];assert struct.unpack_from('<H',core_bytes,nt+4)[0]==0x8664
runtime=(ROOT/'app/Madeira/SteamRuntime.swift').read_text();first=runtime.index('enum SteamRuntimeFiles {');last=runtime.index('\n#if canImport(CryptoKit)',first)
files='import Foundation\nimport zlib\n'+runtime[first:last]
main=r'''
import Foundation
import CryptoKit
@main struct UpgradeProbe {
 @MainActor static func main() async throws {
  typealias B=SteamBrowserRuntimeFiles
  typealias F=SteamNativeBrowserLaunchFiles
  let fm=FileManager.default,base=URL(fileURLWithPath:CommandLine.arguments[1],isDirectory:true).resolvingSymlinksInPath()
  let drive=base.appendingPathComponent("drive_c",isDirectory:true)
  let steam=drive.appendingPathComponent("Program Files (x86)/Steam",isDirectory:true)
  try fm.createDirectory(at:drive.appendingPathComponent("windows/system32"),withIntermediateDirectories:true)
  try fm.createDirectory(at:steam.appendingPathComponent("bin"),withIntermediateDirectories:true)
  let core=steam.appendingPathComponent("bin/chromehtml.dll")
  try fm.copyItem(at:base.appendingPathComponent("core.dll"),to:core)
  let protected=["config/loginusers.vdf","userdata/account/config/localconfig.vdf","steamapps/appmanifest_730.acf","steamapps/common/Counter-Strike Global Offensive/game/bin/win64/cs2.exe"]
  for name in protected {let file=steam.appendingPathComponent(name);try fm.createDirectory(at:file.deletingLastPathComponent(),withIntermediateDirectories:true);try Data(("keep fixture:"+name).utf8).write(to:file)}
  let compat=try F.compatRoot(drive:drive,idle:{true})
  var calls:[String]=[],reports:[String]=[]
  func copyArchive(_ package:B.Package) throws -> URL {
   calls.append(package.file)
   let result=base.appendingPathComponent("transfer-"+UUID().uuidString+".zip")
   try fm.copyItem(at:base.appendingPathComponent(package.file),to:result)
   return result
  }
  func prepare(_ transport:@escaping (B.Package) async throws -> URL) async throws -> B.Prepared {
   try await SteamBrowserRuntime.prepare(cacheBase:compat,steamRoot:steam,chromeHTML:core,idle:{true},progress:{reports.append($0)},download:transport)
  }
  let first=try await prepare({try copyArchive($0)})
  assert(calls==B.official.packages.map(\.file) && !SteamBrowserRuntime.busy)
  let final=first.browserRoot.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
  let owner=final.deletingLastPathComponent()
  let manifestBytes=try Data(contentsOf:final.appendingPathComponent(B.completion))
  let manifest=try JSONDecoder().decode(B.Manifest.self,from:manifestBytes)
  assert(manifest.files.count==80)
  let legacyLog=first.browserRoot.appendingPathComponent("debug.log"),legacyBytes=Data("legacy helper log fixture\n".utf8)
  try legacyBytes.write(to:legacyLog)
  func retained() throws -> Set<String> {Set(try fm.contentsOfDirectory(atPath:owner.path).filter{$0.hasPrefix(".retained-")})}
  let interrupted=owner.appendingPathComponent(".stage-interrupted-before-upgrade",isDirectory:true)
  try fm.createDirectory(at:interrupted,withIntermediateDirectories:false)
  try Data("retain interrupted owner fixture".utf8).write(to:interrupted.appendingPathComponent("partial"))
  func stages() throws -> Set<String> {Set(try fm.contentsOfDirectory(atPath:owner.path).filter{$0.hasPrefix(".stage-")})}
  let beforeRetained=try retained(),beforeStages=try stages()
  func unchangedOld() throws {
   assert(try Data(contentsOf:legacyLog)==legacyBytes)
   assert(try Data(contentsOf:final.appendingPathComponent(B.completion))==manifestBytes)
   try B.validateTree(final,recipe:B.official,records:manifest.files,extraFiles:[B.completion,B.official.prefix+"debug.log"],digest:SteamBrowserRuntime.hash)
   assert(try retained()==beforeRetained && stages()==beforeStages)
   assert(!SteamBrowserRuntime.busy)
  }
  calls.removeAll();reports.removeAll()
  var failedRequests=0
  do {_=try await prepare({_ in failedRequests+=1;throw NSError(domain:NSURLErrorDomain,code:NSURLErrorNetworkConnectionLost)});fatalError("failed transport accepted")}catch{}
  assert(failedRequests==1);try unchangedOld()
  calls.removeAll();var cancellationRequests=0
  let cancelled=Task { @MainActor in
   try await prepare({package in
    cancellationRequests+=1
    if cancellationRequests==2 {withUnsafeCurrentTask{$0?.cancel()};throw CancellationError()}
    return try copyArchive(package)
   })
  }
  do {_=try await cancelled.value;fatalError("cancelled rebuild accepted")}catch is CancellationError{}catch{fatalError("unexpected cancellation error type")}
  assert(cancellationRequests==2);try unchangedOld()
  calls.removeAll()
  do {_=try await prepare({package in
    let file=try copyArchive(package),handle=try FileHandle(forUpdating:file);defer{try?handle.close()}
    let old=try handle.read(upToCount:1)![0];try handle.seek(toOffset:0);try handle.write(contentsOf:Data([old^1]));return file
   });fatalError("altered transport archive accepted")}catch let issue as B.ValidationIssue{assert(issue.reason == .archiveHash)}catch{fatalError("wrong altered-archive predicate")}
  assert(calls.count==1);try unchangedOld()
  calls.removeAll();reports.removeAll()
  let rebuilt=try await prepare({try copyArchive($0)})
  assert(calls==B.official.packages.map(\.file))
  assert(reports.contains{$0.contains("phase=reuse reason=unexpected-file") && $0.contains("relative="+B.official.prefix+"debug.log")})
  _=try B.validate(final,recipe:B.official,digest:SteamBrowserRuntime.hash)
  assert(!fm.fileExists(atPath:rebuilt.browserRoot.appendingPathComponent("debug.log").path))
  let newRetained=try retained().subtracting(beforeRetained);assert(newRetained.count==1)
  let old=owner.appendingPathComponent(newRetained.first!,isDirectory:true)
  assert(try Data(contentsOf:old.appendingPathComponent(B.official.prefix+"debug.log"))==legacyBytes)
  assert(try Data(contentsOf:old.appendingPathComponent(B.completion))==manifestBytes)
  try B.validateTree(old,recipe:B.official,records:manifest.files,extraFiles:[B.completion,B.official.prefix+"debug.log"],digest:SteamBrowserRuntime.hash)
  assert(F.prepareMutableLogs(drive:drive,idle:{true}))
  let output=compat.appendingPathComponent(F.logRootName+"/debug.log")
  let image=try F.windowsPath(rebuilt.helper,drive:drive),directory=try F.windowsPath(rebuilt.browserRoot,drive:drive)
  let process=Process();process.executableURL=base.appendingPathComponent("native-log-open")
  process.arguments=["write","\\??\\"+directory+"\\debug.log",image,directory]
  var env=ProcessInfo.processInfo.environment;env["MADEIRA_TEST_HOST_LOG"]=output.path;process.environment=env
  try process.run();process.waitUntilExit();assert(process.terminationStatus==0)
  assert(fm.fileExists(atPath:output.path))
  calls.removeAll();reports.removeAll()
  let reused=try await prepare({_ in fatalError("verified second launch attempted download")})
  assert(calls.isEmpty && reused.recipe==B.official.id)
  assert(reports.contains{$0.contains("phase=reuse") && $0.contains("action=verified records=80")})
  assert(!fm.fileExists(atPath:reused.browserRoot.appendingPathComponent("debug.log").path))
  _=try B.validate(final,recipe:B.official,digest:SteamBrowserRuntime.hash)
  for name in protected {assert(try Data(contentsOf:steam.appendingPathComponent(name))==Data(("keep fixture:"+name).utf8))}
  assert(try stages()==beforeStages)
  assert(try Data(contentsOf:interrupted.appendingPathComponent("partial"))==Data("retain interrupted owner fixture".utf8))
  print("PASS production prepare genuine upgrade: exact core+3 authentic archives, failures/cancellation/tamper preserve old 80-record cache; successful rebuild retains original log/tree; native source-handler log write stays outside; next launch performs zero downloads and strict reuse succeeds. No Wine/iOS session or CS2 launch claimed.")
 }
}
'''
main=main.replace('assert(try ','assert(try! ')
with tempfile.TemporaryDirectory(prefix='madeira-official-upgrade-') as folder:
 p=Path(folder)
 for name,_,_ in packages:os.link(cache/name,p/name)
 (p/'core.dll').write_bytes(core_bytes)
 fixture_spec=importlib.util.spec_from_file_location('native_log_open',ROOT/'tests/host/build-native-log-file-fixture.py')
 fixture=importlib.util.module_from_spec(fixture_spec);fixture_spec.loader.exec_module(fixture)
 fixture.build(p/'native-log-open')
 (p/'Files.swift').write_text(files)
 (p/'Browser.swift').write_text(source)
 (p/'Native.swift').write_text((ROOT/'app/Madeira/SteamNativeBrowserLaunch.swift').read_text())
 (p/'Update.swift').write_text((ROOT/'app/Madeira/SteamClientUpdate.swift').read_text().split('#if canImport(SwiftUI)',1)[0])
 (p/'main.swift').write_text(main)
 subprocess.run(['swiftc','-parse-as-library','-swift-version','5',*[str(p/name) for name in ['Files.swift','Browser.swift','Native.swift','Update.swift','main.swift']],'-o',str(p/'upgrade')],check=True)
 subprocess.run([str(p/'upgrade'),str(p)],check=True,timeout=300)
