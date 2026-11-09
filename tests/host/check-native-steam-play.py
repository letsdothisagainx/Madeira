#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright 2026 125hz
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Compile actual native-client launch preparation with real VDF parsing on macOS."""
from pathlib import Path
import argparse,subprocess,tempfile,os
parser=argparse.ArgumentParser()
parser.add_argument("--emit-script-dir", type=Path)
parser.add_argument("--interpret", action="store_true", help="Execute the same production Swift fixture with the Swift interpreter")
args=parser.parse_args()
root=Path(__file__).resolve().parents[2]
s=(root/'app/Madeira/SteamRuntime.swift').read_text();helper=s[s.index('enum NativeSteamPlay {'):]
assert 'clientLaunchScript' in helper and 'clientArguments' in helper and '-applaunch' in helper
assert all(x not in helper for x in ['removeItem','refreshToken','credentialsForDock','writeHandoff','DockStartProgram.apply'])
content=(root/'app/Madeira/ContentView.swift').read_text();a=content.index('entry.steamStart == NativeSteamPlay.mode');b=content.index('if let appID = entry.steamAppID, !entry.startsSteamGameDirectly',a)
assert 'launchNativeSteam(entry, action: .play)' in content[a:b]
assert 'startDock(' not in content[a:b] and 'SteamSignIn' not in content[a:b]
launch=content[content.index('private func launchNativeSteam('):content.index('private func startLibraryEntry(')]
verify=content[content.index('private func verifySteamFiles('):content.index('private func launchNativeSteam(')]
assert 'entry.steamAppID == 730' in verify and 'launchNativeSteam(entry, action: .verifyFiles)' in verify
assert 'launch.steamAppID = nil' in launch and 'NativeSteamPlay.prepare(game, drive: MadeiraDock.drive, action: action)' in launch
assert 'then: { launchNativeSteam(entry, action: action) }' in launch
assert 'startLibraryEntry(launch, remember: false, preferences: entry, nativeSteamClient: true)' in launch
assert 'phase=requested mechanism=steam-validate result=unobserved completion=steam-ui' in launch
assert all(x not in launch for x in ['startDock(', 'SteamSignIn', 'library.save(', 'GameRecommendations.prepare'])
idle=content[content.index('private func nativeSteamPreparationIdle('):content.index('private func prepareNativeSteamBrowser(')]
assert all(x in idle for x in ['wine_process_is_running() == 0', 'wineserver_is_running() == 0', 'library.current == nil', '!SteamOwnedLibrary.shared.hasStorageWork'])
games=(root/'app/Madeira/SteamGames.swift').read_text()
assert 'if appID == 730, installed?.installed == true' in games and 'Button { verifyFiles(entry) }' in games
assert "Wait for Steam's result in its window" in games
if os.uname().sysname!='Darwin' and not args.interpret:
 print('PASS native launch source scope; Swift execution runs in macOS Actions');raise SystemExit(0)
dock=(root/'app/Madeira/MadeiraDock.swift').read_text()
def fn(marker):
 a=dock.index(marker);i=dock.index('{',a)+1;depth=1
 while depth:depth+=(dock[i]=='{')-(dock[i]=='}');i+=1
 return dock[a:i]
game=dock[dock.index('struct DockGame:'):dock.index('\n/// Madeira Dock:')]
code='import Foundation\n'+game+'\nenum DockError:Error{case message(String)}\nenum MadeiraDock{\n'+ '\n'.join(fn(x) for x in ['static func validAppID(', 'static func validFolderName(', 'static func game(manifest', 'static func libraryRelative('])+'\n}\n'+helper+r'''
@main struct Check {
 static func main() throws {
  let fm=FileManager.default,drive=fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  defer {try? fm.removeItem(at:drive)}
  let root=drive.appendingPathComponent("Program Files (x86)/Steam")
  let apps=root.appendingPathComponent("steamapps"),folder=apps.appendingPathComponent("common/Counter-Strike Global Offensive")
  try fm.createDirectory(at:folder.appendingPathComponent("game/bin/win64"),withIntermediateDirectories:true)
  try Data("game-fixture".utf8).write(to:folder.appendingPathComponent("game/bin/win64/cs2.exe"))
  let exe=root.appendingPathComponent("steam.exe"),login=root.appendingPathComponent("loginusers.vdf"),manifest=apps.appendingPathComponent("appmanifest_730.acf")
  try Data("genuine-fixture".utf8).write(to:exe);try Data("auth-fixture-must-stay".utf8).write(to:login)
  let data=Data(#"""
  "AppState" {"appid" "730" "StateFlags" "4" "installdir" "Counter-Strike Global Offensive"}
  """#.utf8);try data.write(to:manifest)
  let game=MadeiraDock.game(manifest:data,library:"Program Files (x86)/Steam/steamapps")!
  let other=DockGame(id:730,name:"CS2",installDir:game.installDir,library:"Other/steamapps",installed:true,customExecutables:false)
  assert(!NativeSteamPlay.libraryListed(other,root:"Program Files (x86)/Steam",drive:drive))
  let vdf=Data(#"""
  "libraryfolders" {"1" {"path" "C:\\Other"}}
  """#.utf8)
  try vdf.write(to:apps.appendingPathComponent("libraryfolders.vdf"))
  assert(NativeSteamPlay.libraryListed(other,root:"Program Files (x86)/Steam",drive:drive))
  let script=try NativeSteamPlay.prepare(game,drive:drive)
  let body=try String(contentsOf:drive.appendingPathComponent(script),encoding:.utf8)
  assert(body.contains("steam.exe\" \(NativeSteamPlay.clientArguments) -applaunch 730"))
  assert(body.contains(" -applaunch 730 -condebug\r\n"))
  let otherApp=NativeSteamPlay.clientLaunchScript(windowsDirectory:"C:\\Program Files (x86)\\Steam",appID:570)
  assert(otherApp.contains(" -applaunch 570") && !otherApp.contains("-condebug"))
  assert(!body.contains("-insecure") && !body.contains("-novac"))
  assert(body.contains("madeira-steam-service.exe") && body.contains("policy=steam-managed"))
  assert(!body.contains("exit /b %errorlevel%\r\ncd /d") && !body.contains("&&"))
  assert(body.hasSuffix("exit /b %errorlevel%\r\n"))
  let clientOnly=NativeSteamPlay.clientLaunchScript(windowsDirectory:"C:\\Program Files (x86)\\Steam")
  assert(!clientOnly.contains("-applaunch") && !clientOnly.contains("-condebug") && clientOnly.contains("policy=steam-managed"))
  let verifyScript=try NativeSteamPlay.prepare(game,drive:drive,action:.verifyFiles)
  let verifyBody=try String(contentsOf:drive.appendingPathComponent(verifyScript),encoding:.utf8)
  let verifyClient=verifyBody.components(separatedBy:"\r\n").first { $0.contains("steam.exe\"") }!
  assert(verifyClient == "\"C:\\Program Files (x86)\\Steam\\steam.exe\" \(NativeSteamPlay.clientArguments) steam://validate/730")
  assert(!verifyBody.contains("-applaunch") && !verifyBody.contains("-condebug") && !verifyBody.contains("cs2.exe"))
  assert(!verifyBody.contains("-insecure") && !verifyBody.contains("-novac") && !verifyBody.contains("-allow_third_party_software"))
  assert(verifyBody.contains("madeira-steam-service.exe") && verifyBody.contains("policy=steam-managed"))
  assert(verifyBody.hasSuffix("exit /b %errorlevel%\r\n"))
  assert(!verifyBody.contains("verification-complete") && !verifyBody.contains("result=success"))
  if CommandLine.arguments.count==2 {
   let output=URL(fileURLWithPath:CommandLine.arguments[1],isDirectory:true)
   try fm.createDirectory(at:output,withIntermediateDirectories:true)
   try clientOnly.write(to:output.appendingPathComponent("steam-client.cmd"),atomically:true,encoding:.utf8)
   try body.write(to:output.appendingPathComponent("steam-applaunch.cmd"),atomically:true,encoding:.utf8)
   try verifyBody.write(to:output.appendingPathComponent("steam-verify.cmd"),atomically:true,encoding:.utf8)
  }
  assert(try Data(contentsOf:manifest)==data);assert(try String(contentsOf:login,encoding:.utf8)=="auth-fixture-must-stay")
  let image=try String(contentsOf:folder.appendingPathComponent("game/bin/win64/cs2.exe"),encoding:.utf8);assert(image=="game-fixture")
  let clientImage=try String(contentsOf:exe,encoding:.utf8);assert(clientImage=="genuine-fixture")
  try fm.removeItem(at:manifest)
  do {_=try NativeSteamPlay.prepare(game,drive:drive);assertionFailure("missing manifest must reject")}catch{}
  do {_=try NativeSteamPlay.prepare(game,drive:drive,action:.verifyFiles);assertionFailure("verification with missing manifest must reject")}catch{}
  try data.write(to:manifest);try fm.removeItem(at:folder)
  do {_=try NativeSteamPlay.prepare(game,drive:drive);assertionFailure("missing install directory must reject")}catch{}
  print("PASS actual native Steam launch/verification: real appmanifest parser, exact validate URI without a game launch, optional service preparation and real client exit status; normal applaunch preserved; client/game/auth/manifest files unchanged and missing data rejected")
 }
}
'''
# Throwing expressions cannot be passed directly to assert's nonthrowing autoclosure.
code=code.replace('assert(try Data(contentsOf:manifest)==data);assert(try String(contentsOf:login,encoding:.utf8)=="auth-fixture-must-stay")','let unchanged=try Data(contentsOf:manifest);let auth=try String(contentsOf:login,encoding:.utf8);assert(unchanged==data);assert(auth=="auth-fixture-must-stay")')
with tempfile.TemporaryDirectory() as t:
 p=Path(t)/'check.swift';p.write_text(code);exe=Path(t)/'check'
 output_args=[str(args.emit_script_dir.resolve())] if args.emit_script_dir else []
 if args.interpret:
  p.write_text((root/'app/Madeira/SteamKeyValues.swift').read_text()+'\n'+code.replace('@main struct Check','struct Check')+'\ntry Check.main()\n')
  subprocess.run(['swift','-swift-version','5',str(p)]+output_args,check=True)
 else:
  subprocess.run(['swiftc','-parse-as-library','-swift-version','5',str(root/'app/Madeira/SteamKeyValues.swift'),str(p),'-o',str(exe)],check=True)
  subprocess.run([str(exe)]+output_args,check=True)
