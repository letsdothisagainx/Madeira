#!/usr/bin/env python3
"""Execute the production CS2 texture-profile merge and persisted entry fields.

The profile selector itself is extracted unchanged from Library.swift. Only
unrelated touch/gesture payload types and the device default resolution are
stand-ins. This does not launch Steam, render mipmaps or measure iPhone memory.
"""
from pathlib import Path
import argparse
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--require-swift', action='store_true')
args = parser.parse_args()
library = (ROOT / 'app/Madeira/Library.swift').read_text()
content = (ROOT / 'app/Madeira/ContentView.swift').read_text()
helper = library.split('// BEGIN CS2 TEXTURE MEMORY PROFILE\n', 1)[1].split('// END CS2 TEXTURE MEMORY PROFILE', 1)[0]
fields = library[library.index('struct LibraryEntry: Codable, Identifiable {'):library.index('    /// What MadeiraConfig.applyGame writes for this game:')]
assert 'var cs2TextureMemoryProfile: String?' in fields
assert 'CodingKeys' not in fields and 'init(from' not in fields
picker = library[library.index('@ViewBuilder private var compatibilityPage:'):library.index('private func compatLabel(')]
assert 'if entry.steamAppID == 730 {' in picker
assert 'Picker("Texture memory"' in picker
assert 'CS2TextureMemoryProfile.Mode.allCases' in picker
assert 'CS2TextureMemoryProfile.explanation' in picker
assert 'entry.cs2TextureMemoryProfile = $0 == "automatic" ? nil : $0' in picker
assert 'startLibraryEntry(launch, remember: false, preferences: entry, nativeSteamClient: true)' in content
assert 'let effectiveProfile = preferences ?? entry' in content
assert 'runWineFullSequence(profile: effectiveProfile,' in content
worker = content[content.index('private func runWineFullSequence('):content.index('private func startWineProcess(')]
assert worker.index('var dxmtOptions: [String] = []') < worker.index('getenv("MADEIRA_DXMT_EXTRA")') < worker.index('CS2TextureMemoryProfile.apply(') < worker.index('setenv("DXMT_CONFIG"')
assert 'saved: profile?.cs2TextureMemoryProfile' in worker
assert 'standalone: standaloneProbe' in worker
assert 'environmentAuto: customMipAuto' in worker
assert 'MadeiraConfig.gameValue("env.MADEIRA_MIP_CLAMP_AUTO")' in worker
assert 'MadeiraConfig.get("env.MADEIRA_MIP_CLAMP_AUTO")' in worker
assert 'getenv("MADEIRA_MIP_CLAMP_AUTO")' in worker
assert 'CS2TextureMemoryProfile.measuredBudget(' in worker
assert 'selected=\\(textureMemory.selected.rawValue)' in worker
assert 'applied=\\(textureMemory.applied ? 1 : 0)' in worker
print('PASS CS2 picker, optional persistence, genuine Steam original-profile handoff, final DXMT merge and standalone isolation source wiring')

swift = os.environ.get('SWIFTC') or shutil.which('swiftc')
if not swift:
    if args.require_swift:
        raise SystemExit('Swift compiler required for the production CS2 texture-profile tests')
    print('SKIP actual Swift execution: compiler unavailable; macOS CI must run --require-swift')
    raise SystemExit(0)

harness = r'''
let MiB = UInt64(1) << 20
let GiB = UInt64(1) << 30
func decision(_ saved: String? = nil, budget: UInt64? = 6 << 30,
              options: [String] = ["d3d11.preferredMaxFrameRate=60"], app: Int? = 730,
              env: String? = nil, standalone: Bool = false) -> CS2TextureMemoryProfile.Decision {
    CS2TextureMemoryProfile.apply(options: options, appID: app, saved: saved,
                                  budget: budget, environmentAuto: env, standalone: standalone)
}
let baseline = ["d3d11.preferredMaxFrameRate=60", "dxgi.customDeviceId=2544"]
let budgets: [UInt64?] = [nil, 0, 6 * GiB, 8 * GiB]
for budget in budgets {
    let d = decision(budget: budget, options: baseline)
    assert(d.applicable && d.applied && d.selected == .balanced)
    assert(d.options == baseline + ["d3d11.mipClampAuto=1"])
}
let roomy = decision(budget: 12 * GiB)
assert(roomy.selected == .full && roomy.options.last == "d3d11.mipClampAuto=0")
assert(decision("full").selected == .full && decision("full").options.last == "d3d11.mipClampAuto=0")
assert(decision("balanced", budget: 12 * GiB).options.last == "d3d11.mipClampAuto=1")
assert(decision("unknown-future-value").source == "automatic-budget")
let unrelatedApps: [Int?] = [nil, 570, 356400]
for app in unrelatedApps {
    let d = decision("balanced", options: baseline, app: app)
    assert(!d.applicable && !d.applied && d.options == baseline)
}
let probe = decision("balanced", options: [], standalone: true)
assert(!probe.applicable && probe.options.isEmpty)
assert(decision(options: [], app: 356400).options.isEmpty)
print("PASS production automatic/explicit profile selection, actual budget boundary and unrelated/probe launch isolation")

for option in ["d3d11.mipClampBC=0", "d3d11.mipClampBC=2", " d3d11.mipClampAuto = 0 ",
               "d3d11.mipClampAuto=1", "d3d11.mipClampAutoMB=1536"] {
    let custom = baseline + [option]
    for choice in ["balanced", "full", "automatic"] {
        let d = decision(choice, options: custom)
        assert(d.applicable && !d.applied && d.source == "custom-mip-settings" && d.options == custom)
    }
}
for env in ["0", "1", "off", " 0 "] {
    let d = decision(options: baseline, env: env)
    assert(!d.applied && d.options == baseline && d.source == "custom-mip-settings")
}
assert(decision(env: "  ").applied)
print("PASS existing explicit BC/automatic mip options and environment remain byte-for-byte authoritative; unrelated DXMT options/order preserved")

let suffix = "d3d11.mipClampAuto=1"
let allowedBase = "x=" + String(repeating: "a", count: 259 - suffix.utf16.count - 1 - 2)
let atLimit = decision(options: [allowedBase])
assert(atLimit.applied && atLimit.options.joined(separator: ";").utf16.count == 259)
let tooLong = [allowedBase + "a"]
let declined = decision(options: tooLong)
assert(!declined.applied && declined.source == "config-length-limit" && declined.options == tooLong)
let unicode = ["x=" + String(repeating: "😀", count: 125)]
assert(decision(options: unicode).source == "config-length-limit")
print("PASS DXMT UTF-16 259-character boundary; profile overflow never destroys existing options")

assert(CS2TextureMemoryProfile.measuredBudget(available: 5*GiB, footprint: GiB, installed: 8*GiB, valid: true) == 6*GiB)
assert(CS2TextureMemoryProfile.measuredBudget(available: 0, footprint: 6*GiB, installed: 8*GiB, valid: true) == 6*GiB)
assert(CS2TextureMemoryProfile.measuredBudget(available: 7*GiB, footprint: 2*GiB, installed: 8*GiB, valid: true) == nil)
assert(CS2TextureMemoryProfile.measuredBudget(available: UInt64.max, footprint: 1, installed: UInt64.max, valid: true) == nil)
assert(CS2TextureMemoryProfile.measuredBudget(available: GiB, footprint: 0, installed: 8*GiB, valid: true) == nil)
assert(CS2TextureMemoryProfile.measuredBudget(available: GiB, footprint: GiB, installed: 8*GiB, valid: false) == nil)
print("PASS real snapshot arithmetic validates measured process budget without inventing headroom or overflowing")

var entry = LibraryEntry(title: "CS2", relativePath: "Steam/steamapps/common/Counter-Strike Global Offensive", bits: 64)
entry.id = UUID(uuidString: "12345678-1234-5678-90AB-123456789ABC")!
entry.steamAppID = 730
entry.arguments = "-condebug -joy"
entry.controls = [TouchControl(marker: "preserved-touch")]
entry.zones = [GestureZone(marker: "preserved-zone")]
entry.controllerBinds = ["A": .jump]
entry.config = "dxmt = dxgi.customDeviceId=2544"
let encoder = JSONEncoder(), decoder = JSONDecoder()
let original = try encoder.encode(entry)
var legacy = try JSONSerialization.jsonObject(with: original) as! [String: Any]
legacy.removeValue(forKey: "cs2TextureMemoryProfile")
let decoded = try decoder.decode(LibraryEntry.self, from: JSONSerialization.data(withJSONObject: legacy))
assert(decoded.cs2TextureMemoryProfile == nil)
assert(decoded.id == entry.id && decoded.arguments == entry.arguments && decoded.config == entry.config)
assert(decoded.controls?.first?.marker == "preserved-touch" && decoded.zones?.first?.marker == "preserved-zone")
assert(decoded.controllerBinds?["A"] == .jump && decoded.steamAppID == 730)
for choice in ["balanced", "full"] {
    entry.cs2TextureMemoryProfile = choice
    let saved = try decoder.decode(LibraryEntry.self, from: encoder.encode(entry))
    assert(saved.cs2TextureMemoryProfile == choice && saved.id == decoded.id)
    assert(saved.controls?.first?.marker == "preserved-touch" && saved.controllerBinds?["A"] == .jump)
}
print("PASS actual persisted LibraryEntry stored fields: legacy missing mode, UUID, launch arguments, config and control payloads preserved; explicit choices round-trip")
'''
prelude = '''import Foundation
struct TouchControl: Codable { var marker: String }
struct GestureZone: Codable { var marker: String }
enum ControlAction: String, Codable { case jump }
enum ResolutionChoices { static let defaultValue = "800x450" }
'''
with tempfile.TemporaryDirectory(prefix='madeira-cs2-texture-profile-') as temporary:
    source = Path(temporary) / 'profile.swift'
    binary = Path(temporary) / 'profile'
    source.write_text(prelude + helper + fields + '\n}\n' + harness)
    subprocess.run([swift, '-swift-version', '5', str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('PASS actual Swift CS2 texture-profile implementation; native rendering/memory savings require iPhone validation')
