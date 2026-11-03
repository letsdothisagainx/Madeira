#!/usr/bin/env python3
"""Run actual production Swift against all immutable official browser archives."""
import argparse, hashlib, json, os, shutil, struct, subprocess, tempfile, urllib.request, zipfile
from pathlib import Path
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RUNTIME = ROOT / 'app/Madeira/SteamRuntime.swift'
BROWSER = ROOT / 'app/Madeira/SteamBrowserRuntime.swift'
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--download-official', action='store_true', help='Allow fetching the three immutable public Valve archives')
args=parser.parse_args()
if not args.download_official:parser.error('--download-official is required; no network access is implicit')
cache = Path(os.environ['MADEIRA_VALVE_ARCHIVE_CACHE'])
cache.mkdir(parents=True, exist_ok=True)
packages = [
 ('bins_cef_win32.zip.1c1d9dc1d899e7c8d1cff9cb0fcc11b89e412b98',130079979,'fee14790d59463f31693ef95e10327824f5bdd95baf0aa8fae3b81aea98e794f'),
 ('bins_webhelpers_win32.zip.8a153ec2ee2090c19b25204806ffca2a7ba15bf2',2735010,'1ab3b3834172a644759860f65d853970ba1d8b65f30190aae774395d69136307'),
 ('bins_win32.zip.23e34a6d4b10596a44561a5100dac5585d2517da',59544006,'8b712b2a3412a9066b7725f4e1c5cef9a7ca5b187b6585a5b92d25d09df0ba62')]
for i,(name,size,sha) in enumerate(packages):
 path=cache/name
 if not path.is_file():
  url='https://client-update.akamai.steamstatic.com/'+name
  with urllib.request.urlopen(urllib.request.Request(url,headers={'Accept-Encoding':'identity'}),timeout=90) as response:
   print(json.dumps(dict(package=i+1,transport='python',status=response.status,length=response.headers.get('Content-Length'),encoding=response.headers.get('Content-Encoding'),exact_url=response.url==url)),flush=True)
   assert response.status==200 and response.url==url
   data=response.read(size+1)
  assert len(data)==size and hashlib.sha256(data).hexdigest()==sha
  path.write_bytes(data)
 data=path.read_bytes();assert len(data)==size and hashlib.sha256(data).hexdigest()==sha
 with zipfile.ZipFile(path) as archive:
  members=archive.infolist();non_i386=[]
  for member in members:
   if member.filename.lower().endswith(('.dll','.exe')):
    with archive.open(member) as source:header=source.read(65536)
    offset=struct.unpack_from('<I',header,0x3c)[0];machine=struct.unpack_from('<H',header,offset+4)[0]
    if machine!=0x014c:non_i386.append(dict(name=member.filename,machine=hex(machine),size=member.file_size,sha256=hashlib.sha256(archive.read(member)).hexdigest()))
  print(json.dumps(dict(package=i+1,pinned=True,count=len(members),largest=max(x.file_size for x in members),flags=sorted(set(x.flag_bits for x in members)),methods=sorted(set(x.compress_type for x in members)),non_i386=non_i386,directories=[dict(name=x.filename,size=x.file_size,compressed=x.compress_size) for x in members if x.is_dir()])),flush=True)
source=RUNTIME.read_text();start=source.index('enum SteamRuntimeFiles {');end=source.index('\n#if canImport(CryptoKit)',start)
files='import Foundation\nimport zlib\n'+source[start:end]
files=files.replace('func need(_ condition: Bool) throws { if !condition { throw Failure.invalidPackage } }','func need(_ condition: Bool, line: Int = #line) throws { if !condition { throw ArchiveProbeFailure(file: "ZIP", line: line) } }')
# Diagnostic copies only: expose the first failed guard while preserving its predicate.
browser=BROWSER.read_text().replace('throw Failure.invalid','throw ArchiveProbeFailure(file: "Cache", line: #line)')
browser=browser.replace('guard let http = response as? HTTPURLResponse, http.statusCode == 200, http.url == url,','print("URLSession response status=\\((response as? HTTPURLResponse)?.statusCode ?? -1) length=\\(response.expectedContentLength) encoding=\\((response as? HTTPURLResponse)?.value(forHTTPHeaderField: "Content-Encoding") ?? "none") exact-url=\\(response.url == url)")\n        guard let http = response as? HTTPURLResponse, http.statusCode == 200, http.url == url,')
main=r'''
import Darwin
func probeLog(_ message: String) { FileHandle.standardOutput.write(Data((message + "\n").utf8)) }
struct ArchiveProbeFailure: Error { let file: String; let line: Int }
@main struct RealArchiveProbe {
 @MainActor static func main() async throws {
  typealias F = SteamBrowserRuntimeFiles
  let fm=FileManager.default, base=URL(fileURLWithPath: CommandLine.arguments[1],isDirectory:true)
  let cacheBase=base.appendingPathComponent("compat",isDirectory:true), steam=base.appendingPathComponent("steam",isDirectory:true)
  try fm.createDirectory(at:cacheBase,withIntermediateDirectories:true)
  try fm.createDirectory(at:steam,withIntermediateDirectories:true)
  let owner=try F.ownerRoot(cacheBase:cacheBase,steamRoot:steam,idle:{true})
  let stage=owner.appendingPathComponent(".stage-real-official",isDirectory:true)
  try fm.createDirectory(at:stage,withIntermediateDirectories:false)
  var records:[F.FileRecord]=[], failures=0
  for (index, package) in F.official.packages.enumerated() {
   do {
    let data=try Data(contentsOf:base.appendingPathComponent(package.file),options:.mappedIfSafe)
    try F.appendArchive(data,package:package,recipe:F.official,stage:stage,records:&records,
      digest:{ SHA256.hash(data:$0).map{String(format:"%02x",$0)}.joined() },idle:{true})
    print("PASS actual Swift archive package=\(index+1) records=\(records.count)")
   } catch { failures += 1; print("FAIL actual Swift archive package=\(index+1) error=\(error)") }
  }
  do {
   let file=try await SteamBrowserDownload.download(F.official.packages[0]);defer{try?fm.removeItem(at:file)}
   let downloadedHash=try SteamBrowserRuntime.hash(file);assert(downloadedHash==F.official.packages[0].sha256)
   print("PASS actual URLSession first-package download: exact size and full SHA256")
  } catch { failures += 1; print("FAIL actual URLSession first-package download error=\(error)") }
  guard failures==0 else { exit(1) }
  try F.checkOfficialRecords(recipe:F.official,records:records)
  let final=owner.appendingPathComponent(F.official.id,isDirectory:true)
  _ = try F.commit(stage:stage,destination:final,recipe:F.official,records:records,
    digest:SteamBrowserRuntime.hash,idle:{true},recheckCore:{})
  _ = try F.validate(final,recipe:F.official,digest:SteamBrowserRuntime.hash)
  let marker=try Data(contentsOf:final.appendingPathComponent(F.official.prefix+F.official.marker.name))
  assert(marker==F.official.marker.bytes)
  let completion=try JSONDecoder().decode(F.Manifest.self,from:Data(contentsOf:final.appendingPathComponent(F.completion)))
  assert(completion.files.count==80 && completion.files.filter(\.generated).count==1)
  assert(!fm.fileExists(atPath:stage.path))
  let target=final.appendingPathComponent(F.official.prefix+"msdia140.dll")
  let original=try Data(contentsOf:target);var changed=original;changed[changed.count-1] ^= 1
  try changed.write(to:target)
  var refused=false
  do { _ = try F.validate(final,recipe:F.official,digest:SteamBrowserRuntime.hash) } catch { refused=true }
  assert(refused)
  try original.write(to:target)
  _ = try F.validate(final,recipe:F.official,digest:SteamBrowserRuntime.hash)
  print("PASS all 79 official members, architectures and key pins; atomic commit, 80-entry completed manifest, full-tree cache reuse and diagnostic-DLL tamper refusal")
 }
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-real-cache-') as temporary:
 p=Path(temporary)
 for name,_,_ in packages:os.link(cache/name,p/name)
 (p/'Files.swift').write_text(files)
 (p/'Browser.swift').write_text((browser+'\n'+main).replace('print(', 'probeLog('))
 subprocess.run([shutil.which('swiftc'),'-parse-as-library',str(p/'Files.swift'),str(p/'Browser.swift'),'-o',str(p/'probe')],check=True)
 subprocess.run([str(p/'probe'),str(p)],check=True)
