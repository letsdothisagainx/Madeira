#!/usr/bin/env python3
"""Run actual production Swift against all immutable official browser archives."""
import hashlib, json, os, shutil, struct, subprocess, tempfile, urllib.request, zipfile
from pathlib import Path
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RUNTIME = HERE / 'SteamRuntime.swift.candidate'
BROWSER = HERE / 'SteamBrowserRuntime.swift'
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
  members=archive.infolist();print(json.dumps(dict(package=i+1,pinned=True,count=len(members),largest=max(x.file_size for x in members),flags=sorted(set(x.flag_bits for x in members)),methods=sorted(set(x.compress_type for x in members)),directories=[dict(name=x.filename,size=x.file_size,compressed=x.compress_size) for x in members if x.is_dir()])),flush=True)
source=RUNTIME.read_text();start=source.index('enum SteamRuntimeFiles {');end=source.index('\n#if canImport(CryptoKit)',start)
files='import Foundation\nimport zlib\n'+source[start:end]
files=files.replace('func need(_ condition: Bool) throws { if !condition { throw Failure.invalidPackage } }','func need(_ condition: Bool, line: Int = #line) throws { if !condition { throw ArchiveProbeFailure(file: "ZIP", line: line) } }')
# Diagnostic copies only: expose the first failed guard while preserving its predicate.
browser=BROWSER.read_text().replace('throw Failure.invalid','throw ArchiveProbeFailure(file: "Cache", line: #line)')
browser=browser.replace('guard let http = response as? HTTPURLResponse, http.statusCode == 200, http.url == url,','print("URLSession response status=\\((response as? HTTPURLResponse)?.statusCode ?? -1) length=\\(response.expectedContentLength) encoding=\\((response as? HTTPURLResponse)?.value(forHTTPHeaderField: "Content-Encoding") ?? "none") exact-url=\\(response.url == url)")\n        guard let http = response as? HTTPURLResponse, http.statusCode == 200, http.url == url,')
main=r'''
struct ArchiveProbeFailure: Error { let file: String; let line: Int }
@main struct RealArchiveProbe {
 @MainActor static func main() async throws {
  typealias F = SteamBrowserRuntimeFiles
  let fm=FileManager.default, base=URL(fileURLWithPath: CommandLine.arguments[1],isDirectory:true)
  let stage=base.appendingPathComponent("extracted",isDirectory:true)
  try fm.createDirectory(at:stage,withIntermediateDirectories:true)
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
  guard failures==0 else { throw ArchiveProbeFailure(file:"completed-with-failures",line:failures) }
  try F.checkOfficialRecords(recipe:F.official,records:records)
  print("PASS all 79 official members, architectures and key pins")
 }
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-real-cache-') as temporary:
 p=Path(temporary)
 for name,_,_ in packages:os.link(cache/name,p/name)
 (p/'Files.swift').write_text(files)
 (p/'Browser.swift').write_text(browser+'\n'+main)
 subprocess.run([shutil.which('swiftc'),'-parse-as-library',str(p/'Files.swift'),str(p/'Browser.swift'),'-o',str(p/'probe')],check=True)
 subprocess.run([str(p/'probe'),str(p)],check=True)
