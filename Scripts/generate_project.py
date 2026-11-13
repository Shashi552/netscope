#!/usr/bin/env python3
"""Dependency-free reproducible Xcode project generator. Run after adding Swift files."""
from pathlib import Path
import hashlib, json, plistlib
ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / 'NetScope.xcodeproj'
PROJECT.mkdir(exist_ok=True)
def ID(value): return hashlib.sha256(value.encode()).hexdigest()[:24].upper()
def q(value): return json.dumps(str(value))
objects = {}
def add(key, body):
    i = ID(key); objects[i] = body; return i
def ref(path, kind): return add('ref:'+path, f'isa = PBXFileReference; lastKnownFileType = {kind}; path = {q(path)}; sourceTree = "<group>";')
def build(path, r): return add('build:'+path, f'isa = PBXBuildFile; fileRef = {r};')
source_refs=[]; source_build=[]; test_refs=[]; test_build=[]
for path in sorted(ROOT.glob('Sources/**/*.swift')):
    rel=path.relative_to(ROOT).as_posix(); r=ref(rel,'sourcecode.swift'); source_refs.append(r); source_build.append(build(rel,r))
for path in sorted(ROOT.glob('Tests/**/*.swift')):
    rel=path.relative_to(ROOT).as_posix(); r=ref(rel,'sourcecode.swift'); test_refs.append(r); test_build.append(build(rel,r))
resources=[]; resource_refs=[]
for path,kind in [('Resources/Assets.xcassets','folder.assetcatalog'),('Resources/PrivacyInfo.xcprivacy','text.xml')]:
    r=ref(path,kind); resource_refs.append(r); resources.append(build(path,r))
appProduct=add('appProduct','isa = PBXFileReference; explicitFileType = wrapper.application; includeInIndex = 0; path = NetScope.app; sourceTree = BUILT_PRODUCTS_DIR;')
testProduct=add('testProduct','isa = PBXFileReference; explicitFileType = wrapper.cfbundle; includeInIndex = 0; path = NetScopeTests.xctest; sourceTree = BUILT_PRODUCTS_DIR;')
def arr(ids): return '('+','.join(ids)+',)'
productGroup=add('products',f'isa = PBXGroup; children = {arr([appProduct,testProduct])}; name = Products; sourceTree = "<group>";')
sourcesGroup=add('sources',f'isa = PBXGroup; children = {arr(source_refs)}; name = Sources; sourceTree = "<group>";')
testsGroup=add('tests',f'isa = PBXGroup; children = {arr(test_refs)}; name = Tests; sourceTree = "<group>";')
resourcesGroup=add('resources',f'isa = PBXGroup; children = {arr(resource_refs)}; name = Resources; sourceTree = "<group>";')
mainGroup=add('main',f'isa = PBXGroup; children = {arr([sourcesGroup,testsGroup,resourcesGroup,ref("Info.plist","text.plist.xml"),productGroup])}; sourceTree = "<group>";')
def phase(key,isa,files): return add(key,f'isa = {isa}; buildActionMask = 2147483647; files = {arr(files) if files else "()"}; runOnlyForDeploymentPostprocessing = 0;')
appSources=phase('appSources','PBXSourcesBuildPhase',source_build)
testSources=phase('testSources','PBXSourcesBuildPhase',test_build)
appResources=phase('appResources','PBXResourcesBuildPhase',resources)
appFrameworks=phase('appFrameworks','PBXFrameworksBuildPhase',[])
testFrameworks=phase('testFrameworks','PBXFrameworksBuildPhase',[])
def settings(dictionary): return '{' + ''.join(f'{k} = {q(v)};' for k,v in dictionary.items()) + '}'
def configs(key, common, release=None):
    ids=[]
    for name in ['Debug','Release']:
        values=dict(common)
        values.update({'SWIFT_OPTIMIZATION_LEVEL':'-Onone' if name=='Debug' else '-O','DEBUG_INFORMATION_FORMAT':'dwarf' if name=='Debug' else 'dwarf-with-dsym'})
        if name=='Debug': values['SWIFT_ACTIVE_COMPILATION_CONDITIONS']='DEBUG'; values['ENABLE_TESTABILITY']='YES'
        if name=='Release' and release: values.update(release)
        ids.append(add(key+name,f'isa = XCBuildConfiguration; buildSettings = {settings(values)}; name = {name};'))
    return add(key+'List',f'isa = XCConfigurationList; buildConfigurations = {arr(ids)}; defaultConfigurationIsVisible = 0; defaultConfigurationName = Release;')
common={'IPHONEOS_DEPLOYMENT_TARGET':'17.0','SWIFT_VERSION':'5.0','SDKROOT':'iphoneos','CLANG_ENABLE_MODULES':'YES','CLANG_ENABLE_OBJC_ARC':'YES','SWIFT_STRICT_CONCURRENCY':'targeted','GCC_C_LANGUAGE_STANDARD':'gnu17'}
projectConfig=configs('project',common)
appConfig=configs('app',{'PRODUCT_BUNDLE_IDENTIFIER':'app.netscope.iphone','PRODUCT_NAME':'$(TARGET_NAME)','INFOPLIST_FILE':'Info.plist','GENERATE_INFOPLIST_FILE':'NO','CODE_SIGN_STYLE':'Automatic','TARGETED_DEVICE_FAMILY':'1','ASSETCATALOG_COMPILER_APPICON_NAME':'AppIcon','MARKETING_VERSION':'0.2.2','CURRENT_PROJECT_VERSION':'3','LD_RUNPATH_SEARCH_PATHS':'$(inherited) @executable_path/Frameworks','SUPPORTED_PLATFORMS':'iphoneos iphonesimulator','SUPPORTS_MACCATALYST':'NO'})
testConfig=configs('test',{'PRODUCT_BUNDLE_IDENTIFIER':'app.netscope.iphone.tests','PRODUCT_NAME':'$(TARGET_NAME)','GENERATE_INFOPLIST_FILE':'YES','CODE_SIGN_STYLE':'Automatic','TARGETED_DEVICE_FAMILY':'1','TEST_HOST':'$(BUILT_PRODUCTS_DIR)/NetScope.app/NetScope','BUNDLE_LOADER':'$(TEST_HOST)','LD_RUNPATH_SEARCH_PATHS':'$(inherited) @executable_path/Frameworks @loader_path/Frameworks'})
appTarget=ID('appTarget'); testTarget=ID('testTarget'); projectID=ID('projectRoot')
proxy=add('proxy',f'isa = PBXContainerItemProxy; containerPortal = {projectID}; proxyType = 1; remoteGlobalIDString = {appTarget}; remoteInfo = NetScope;')
dependency=add('testDependency',f'isa = PBXTargetDependency; target = {appTarget}; targetProxy = {proxy};')
objects[appTarget]=f'isa = PBXNativeTarget; buildConfigurationList = {appConfig}; buildPhases = {arr([appSources,appFrameworks,appResources])}; buildRules = (); dependencies = (); name = NetScope; productName = NetScope; productReference = {appProduct}; productType = "com.apple.product-type.application";'
objects[testTarget]=f'isa = PBXNativeTarget; buildConfigurationList = {testConfig}; buildPhases = {arr([testSources,testFrameworks])}; buildRules = (); dependencies = {arr([dependency])}; name = NetScopeTests; productName = NetScopeTests; productReference = {testProduct}; productType = "com.apple.product-type.bundle.unit-test";'
objects[projectID]=f'isa = PBXProject; attributes = {{ LastUpgradeCheck = 1600; BuildIndependentTargetsInParallel = YES; TargetAttributes = {{ {appTarget} = {{ CreatedOnToolsVersion = 16.0; }}; {testTarget} = {{ CreatedOnToolsVersion = 16.0; TestTargetID = {appTarget}; }}; }}; }}; buildConfigurationList = {projectConfig}; compatibilityVersion = "Xcode 14.0"; developmentRegion = en; hasScannedForEncodings = 0; knownRegions = (en,Base); mainGroup = {mainGroup}; productRefGroup = {productGroup}; projectDirPath = ""; projectRoot = ""; targets = {arr([appTarget,testTarget])};'
text='// !$*UTF8*$!\n{ archiveVersion = 1; classes = {}; objectVersion = 56; objects = {\n'+''.join(f'{i} = {{ {v} }};\n' for i,v in objects.items())+f'}}; rootObject = {projectID}; }}\n'
(PROJECT/'project.pbxproj').write_text(text)
schemes=PROJECT/'xcshareddata/xcschemes'; schemes.mkdir(parents=True,exist_ok=True)
def br(i,name,product): return f'<BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{i}" BuildableName="{product}" BlueprintName="{name}" ReferencedContainer="container:NetScope.xcodeproj"/>'
scheme=f'''<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="1600" version="1.3">
<BuildAction parallelizeBuildables="YES" buildImplicitDependencies="YES"><BuildActionEntries><BuildActionEntry buildForTesting="YES" buildForRunning="YES" buildForProfiling="YES" buildForArchiving="YES" buildForAnalyzing="YES">{br(appTarget,'NetScope','NetScope.app')}</BuildActionEntry></BuildActionEntries></BuildAction>
<TestAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" shouldUseLaunchSchemeArgsEnv="YES"><Testables><TestableReference skipped="NO">{br(testTarget,'NetScopeTests','NetScopeTests.xctest')}</TestableReference></Testables></TestAction>
<LaunchAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" launchStyle="0" useCustomWorkingDirectory="NO" ignoresPersistentStateOnLaunch="NO" debugDocumentVersioning="YES" debugServiceExtension="internal" allowLocationSimulation="YES"><BuildableProductRunnable runnableDebuggingMode="0">{br(appTarget,'NetScope','NetScope.app')}</BuildableProductRunnable></LaunchAction>
<ProfileAction buildConfiguration="Release" shouldUseLaunchSchemeArgsEnv="YES" useCustomWorkingDirectory="NO" debugDocumentVersioning="YES"><BuildableProductRunnable runnableDebuggingMode="0">{br(appTarget,'NetScope','NetScope.app')}</BuildableProductRunnable></ProfileAction>
<AnalyzeAction buildConfiguration="Debug"/><ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="YES"/></Scheme>'''
(schemes/'NetScope.xcscheme').write_text(scheme)
print(f'Generated {PROJECT.name}: {len(source_refs)} app sources, {len(test_refs)} test sources')
