#!/usr/bin/env python3
"""Generate the dependency-free simulator host; verify literal D6 UI provenance."""
from pathlib import Path
import argparse
import base64
import hashlib
import io
import json
import subprocess
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def check_baseline():
    fixture = (HERE / 'fixtures/D6ExportViews.swift').read_text()
    metadata = json.loads((HERE / 'fixtures/provenance.json').read_text())
    for entry in metadata['views']:
        start = fixture.index('struct ' + entry['name'] + ':')
        end = fixture.index('\n}', start) + 2
        literal = fixture[start:end] + '\n'
        assert hashlib.sha256(literal.encode()).hexdigest() == entry['sha256'], entry['name']
        # A shallow CI checkout can lack D6. The checked-in body digest remains
        # required; when the actual object exists, additionally verify its bytes.
        original = subprocess.run(['git', 'show', metadata['sourceRevision'] + ':' + entry['source']],
                                  cwd=ROOT, text=True, capture_output=True)
        if original.returncode == 0:
            start = original.stdout.index('struct ' + entry['name'] + ':')
            end = original.stdout.index('\n}', start) + 2
            assert original.stdout[start:end] + '\n' == literal
    with zipfile.ZipFile(io.BytesIO(base64.b64decode((HERE / 'fixtures/archive.base64').read_text()))) as archive:
        assert archive.testzip() is None
        assert archive.namelist() == ['run.txt']
        assert archive.read('run.txt') == b'Owned run export UI fixture\n'
    source = ROOT / 'app/Madeira/RunExportPresentation.swift'
    assert source.is_file()
    assert 'struct RunExportButton: View' in source.read_text()
    print('PASS literal D6 UI digests, source-object comparison when available, and real ZIP/CRC fixture')


def generate():
    ids = {name: f'{index:024X}' for index, name in enumerate((
        'project', 'main', 'products', 'app', 'uitests', 'app_product', 'test_product',
        'host_file', 'production_file', 'baseline_file', 'tests_file', 'archive_file',
        'host_build', 'production_build', 'baseline_build', 'tests_build', 'archive_build',
        'app_sources', 'test_sources', 'app_frameworks', 'test_frameworks', 'resources',
        'dependency', 'proxy', 'project_configs', 'app_configs', 'test_configs',
        'project_debug', 'project_release', 'app_debug', 'app_release', 'test_debug', 'test_release'), 1)}
    def i(name): return ids[name]
    objects = []
    def obj(name, body): objects.append(f'\t\t{i(name)} = {{ {body} }};')
    def refs(names): return '(' + ', '.join(i(n) for n in names) + ')'
    for name, path, kind in (
        ('host_file', 'Host.swift', 'sourcecode.swift'),
        ('production_file', '../../app/Madeira/RunExportPresentation.swift', 'sourcecode.swift'),
        ('baseline_file', 'fixtures/D6ExportViews.swift', 'sourcecode.swift'),
        ('tests_file', 'ExportRunUITests.swift', 'sourcecode.swift'),
        ('archive_file', 'fixtures/archive.base64', 'text'),
    ):
        obj(name, f'isa = PBXFileReference; lastKnownFileType = {kind}; path = "{path}"; sourceTree = "<group>";')
    obj('app_product', 'isa = PBXFileReference; explicitFileType = wrapper.application; includeInIndex = 0; path = RunExportUIHost.app; sourceTree = BUILT_PRODUCTS_DIR;')
    obj('test_product', 'isa = PBXFileReference; explicitFileType = wrapper.cfbundle; includeInIndex = 0; path = RunExportUITests.xctest; sourceTree = BUILT_PRODUCTS_DIR;')
    for name, file in (('host_build', 'host_file'), ('production_build', 'production_file'),
                       ('baseline_build', 'baseline_file'), ('tests_build', 'tests_file'), ('archive_build', 'archive_file')):
        obj(name, f'isa = PBXBuildFile; fileRef = {i(file)};')
    obj('main', f'isa = PBXGroup; children = {refs(["host_file", "production_file", "baseline_file", "tests_file", "archive_file", "products"])}; sourceTree = "<group>";')
    obj('products', f'isa = PBXGroup; children = {refs(["app_product", "test_product"])}; name = Products; sourceTree = "<group>";')
    for name, files in (('app_sources', ['host_build', 'production_build', 'baseline_build']), ('test_sources', ['tests_build'])):
        obj(name, f'isa = PBXSourcesBuildPhase; buildActionMask = 2147483647; files = {refs(files)}; runOnlyForDeploymentPostprocessing = 0;')
    for name in ('app_frameworks', 'test_frameworks'):
        obj(name, 'isa = PBXFrameworksBuildPhase; buildActionMask = 2147483647; files = (); runOnlyForDeploymentPostprocessing = 0;')
    obj('resources', f'isa = PBXResourcesBuildPhase; buildActionMask = 2147483647; files = {refs(["archive_build"])}; runOnlyForDeploymentPostprocessing = 0;')
    obj('proxy', f'isa = PBXContainerItemProxy; containerPortal = {i("project")}; proxyType = 1; remoteGlobalIDString = {i("app")}; remoteInfo = RunExportUIHost;')
    obj('dependency', f'isa = PBXTargetDependency; target = {i("app")}; targetProxy = {i("proxy")};')
    obj('app', f'isa = PBXNativeTarget; buildConfigurationList = {i("app_configs")}; buildPhases = {refs(["app_sources", "app_frameworks", "resources"])}; buildRules = (); dependencies = (); name = RunExportUIHost; productName = RunExportUIHost; productReference = {i("app_product")}; productType = "com.apple.product-type.application";')
    obj('uitests', f'isa = PBXNativeTarget; buildConfigurationList = {i("test_configs")}; buildPhases = {refs(["test_sources", "test_frameworks"])}; buildRules = (); dependencies = {refs(["dependency"])}; name = RunExportUITests; productName = RunExportUITests; productReference = {i("test_product")}; productType = "com.apple.product-type.bundle.ui-testing";')
    common = '''CLANG_ENABLE_MODULES = YES; SDKROOT = iphoneos; IPHONEOS_DEPLOYMENT_TARGET = 18.0;
                SWIFT_VERSION = 5.0; SWIFT_OPTIMIZATION_LEVEL = "-Onone"; SWIFT_ACTIVE_COMPILATION_CONDITIONS = DEBUG;
                CODE_SIGNING_ALLOWED = NO; CODE_SIGNING_REQUIRED = NO; TARGETED_DEVICE_FAMILY = 1;
                SUPPORTED_PLATFORMS = "iphoneos iphonesimulator"; DEBUG_INFORMATION_FORMAT = dwarf;
                ONLY_ACTIVE_ARCH = YES; ENABLE_USER_SCRIPT_SANDBOXING = YES;'''
    for mode in ('debug', 'release'):
        label = mode.capitalize()
        obj('project_' + mode, f'isa = XCBuildConfiguration; buildSettings = {{ {common} }}; name = {label};')
        obj('app_' + mode, f'''isa = XCBuildConfiguration; buildSettings = {{ {common}
                PRODUCT_NAME = "$(TARGET_NAME)"; PRODUCT_BUNDLE_IDENTIFIER = com.madeira.tests.RunExportUIHost;
                GENERATE_INFOPLIST_FILE = NO; INFOPLIST_FILE = "Host-Info.plist"; ENABLE_TESTABILITY = YES;
                LD_RUNPATH_SEARCH_PATHS = "$(inherited) @executable_path/Frameworks";
                }}; name = {label};''')
        obj('test_' + mode, f'''isa = XCBuildConfiguration; buildSettings = {{ {common}
                PRODUCT_NAME = "$(TARGET_NAME)"; PRODUCT_BUNDLE_IDENTIFIER = com.madeira.tests.RunExportUITests;
                GENERATE_INFOPLIST_FILE = YES; TEST_TARGET_NAME = RunExportUIHost;
                FRAMEWORK_SEARCH_PATHS = ("$(inherited)", "$(PLATFORM_DIR)/Developer/Library/Frameworks");
                OTHER_LDFLAGS = ("$(inherited)", "-framework", XCTest);
                LD_RUNPATH_SEARCH_PATHS = "$(inherited) @executable_path/Frameworks @loader_path/Frameworks";
                }}; name = {label};''')
    for name, configs in (('project_configs', ['project_debug', 'project_release']), ('app_configs', ['app_debug', 'app_release']), ('test_configs', ['test_debug', 'test_release'])):
        obj(name, f'isa = XCConfigurationList; buildConfigurations = {refs(configs)}; defaultConfigurationIsVisible = 0; defaultConfigurationName = Debug;')
    obj('project', f'''isa = PBXProject; attributes = {{ LastUpgradeCheck = 2700; TargetAttributes = {{
            {i("app")} = {{ CreatedOnToolsVersion = 27.0; }};
            {i("uitests")} = {{ CreatedOnToolsVersion = 27.0; TestTargetID = {i("app")}; }}; }}; }};
            buildConfigurationList = {i("project_configs")}; compatibilityVersion = "Xcode 14.0";
            developmentRegion = en; hasScannedForEncodings = 0; knownRegions = (en, Base);
            mainGroup = {i("main")}; productRefGroup = {i("products")}; projectDirPath = ""; projectRoot = "";
            targets = {refs(["app", "uitests"])};''')
    project = HERE / 'RunExportUI.xcodeproj'
    project.mkdir(exist_ok=True)
    (project / 'project.pbxproj').write_text('// !$*UTF8*$!\n{\n\tarchiveVersion = 1;\n\tclasses = {};\n\tobjectVersion = 56;\n\tobjects = {\n' + '\n'.join(objects) + '\n\t};\n\trootObject = ' + i('project') + ';\n}\n')
    scheme = project / 'xcshareddata/xcschemes/RunExportUI.xcscheme'
    scheme.parent.mkdir(parents=True, exist_ok=True)
    def buildable(name, target, filename):
        return f'<BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{i(target)}" BuildableName="{filename}" BlueprintName="{name}" ReferencedContainer="container:RunExportUI.xcodeproj"/>'
    app = buildable('RunExportUIHost', 'app', 'RunExportUIHost.app')
    test = buildable('RunExportUITests', 'uitests', 'RunExportUITests.xctest')
    scheme.write_text(f'''<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="2700" version="1.7">
 <BuildAction parallelizeBuildables="YES" buildImplicitDependencies="YES"><BuildActionEntries>
  <BuildActionEntry buildForTesting="YES" buildForRunning="YES" buildForProfiling="YES" buildForArchiving="YES" buildForAnalyzing="YES">{app}</BuildActionEntry>
  <BuildActionEntry buildForTesting="YES" buildForRunning="NO" buildForProfiling="NO" buildForArchiving="NO" buildForAnalyzing="YES">{test}</BuildActionEntry>
 </BuildActionEntries></BuildAction>
 <TestAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" shouldUseLaunchSchemeArgsEnv="YES" codeCoverageEnabled="YES">
  <Testables><TestableReference skipped="NO">{test}</TestableReference></Testables><MacroExpansion>{app}</MacroExpansion>
 </TestAction>
 <LaunchAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" launchStyle="0" useCustomWorkingDirectory="NO" ignoresPersistentStateOnLaunch="NO" debugDocumentVersioning="YES" debugServiceExtension="internal" allowLocationSimulation="YES"><BuildableProductRunnable runnableDebuggingMode="0">{app}</BuildableProductRunnable></LaunchAction>
 <ProfileAction buildConfiguration="Release" shouldUseLaunchSchemeArgsEnv="YES" savedToolIdentifier="" useCustomWorkingDirectory="NO" debugDocumentVersioning="YES"><BuildableProductRunnable runnableDebuggingMode="0">{app}</BuildableProductRunnable></ProfileAction>
 <AnalyzeAction buildConfiguration="Debug"/><ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="YES"/>
</Scheme>
''')
    print('Generated RunExportUI.xcodeproj: unchanged production UIKit file + literal D6 negative baseline + owned host/UI tests')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Only validate checked-in fixture provenance')
    args = parser.parse_args()
    check_baseline()
    if not args.check: generate()
