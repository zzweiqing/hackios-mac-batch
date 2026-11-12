#!/usr/bin/env python3
"""Build UniXNU's NativeAdrenoMetal.bundle (metal2vulkan bridge + Turnip) for iOS 17 against the A640 ABI.

Called by nabu_turnip_ci.py after Turnip is built in the pinned UniXNU checkout. Initializes only the two
submodules the plugin build reads at their pinned gitlinks, fetches the pinned metal2vulkan translator, then
runs UniXNU's own scripts/build-adreno-metal-plugin.py with the A640 board options. A build only proves
compilation, linking and signing: no GPU is exercised and nothing is installed.

worker_opt starts from the Actions 423593 nine-patch wallpaper baseline and adds only the
lowering-worker and fixed-head telemetry patches. It keeps the runtime QoS patch and deliberately
does not compile the separately tested, undeployed private shader-cache changes.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

# Gitlinks of UniXNU cd2dd1bd (checked against the checkout's tree before use).
SUBMODULES = {
    'drivers/AdrenoMetal': ('https://github.com/RigoLigoRLC/unixnu-adrenometal.git',
                            'baad47ca22b181bf0ef0d08412d3ed1f96945e16'),
    'kits/AdrenoPM4': ('https://github.com/UniXNU/AdrenoPM4.git', '282606b528b2595bc4274ea7490b62b323f35a5f'),
}
METAL2VULKAN = 'https://github.com/steelbrain/metal2vulkan.git'
RUST = '1.98.0'
# Nabu supplies the GOP wire; its scanout backend is opt-in at boot. QuartzCore addresses and replay remain A740-only.
BOARD_ARGUMENTS = ('--scanout-copy', 'on', '--quartzcore-display-state', 'off', '--turnip-replay', 'off')
# Built by build-adreno-metal-plugin.py but not deployed on nabu; listed in the report only.
# nabu patches to the pinned AdrenoMetal checkout (paths relative to the device tree), applied in order.
ADRENOMETAL_PATCHES = ('patches/adrenometal-shader-cache-optional.patch', 'patches/adrenometal-quartzcore-failures.patch',
                       'patches/adrenometal-nabu-scanout.patch', 'patches/adrenometal-nabu-problem-report.patch',
                       'patches/adrenometal-nabu-ci-kernels.patch')
FPS_PATCHES = ADRENOMETAL_PATCHES[:-1] + ('patches/adrenometal-nabu-source-cache.patch',)
MPS_CONTRACT_PATCH = 'patches/adrenometal-nabu-mps-contract.patch'
MPS_CONTRACT_UPSTREAM = '6d7f73437087c57ee54a41adceb1735daaea405e'
GPU_CORE_COUNT_PATCH = 'patches/adrenometal-nabu-gpu-core-count.patch'
WALLPAPER_PATCHES = FPS_PATCHES + (ADRENOMETAL_PATCHES[-1], 'patches/adrenometal-nabu-ci-function-identity.patch',
                                  MPS_CONTRACT_PATCH, GPU_CORE_COUNT_PATCH)
LOWERING_WORKER_PATCH = 'patches/adrenometal-nabu-lowering-worker.patch'
RUNTIME_TELEMETRY_PATCH = 'patches/adrenometal-nabu-runtime-telemetry.patch'
RUNTIME_WAIT_PHASES_PATCH = 'patches/metal2vulkan-nabu-wait-phases.patch'
WORKER_OBSERVATION_PATCHES = WALLPAPER_PATCHES + (LOWERING_WORKER_PATCH, RUNTIME_TELEMETRY_PATCH)
# A separate matched-pair experiment. Existing recipes keep their original mode
# and telemetry; these variants change only TU_DEBUG and add the same observer.
TURNIP_RENDER_MODES = ('sysmem', 'gmem')
RENDER_MODE_PATCH = 'patches/adrenometal-nabu-render-mode.patch'
RENDER_MODE_HEADER = 'platform/NabuTurnipRenderMode.h'
RENDER_MODE_PROVIDER = 'patches/mesa/turnip-render-mode-for-attachment-memory.patch'
WORKER_RUNTIME_UPSTREAM = '624bab3918de5b978e1101517abca2b4fa426565'
WAIT_PHASES_SOURCE = 'crates/metal2vulkan-runtime/src/command_buffer/mod.rs'
WAIT_PHASES_UPSTREAM_SOURCE_SHA256 = 'bbddb227a0a7cbbc450e5d2b200a9bd61ff841482bd6e64ba6c6ef9d737182bc'
WAIT_PHASES_BASELINE_SOURCE_SHA256 = '8518a82419d7b216085cb5fa216fe34b5835e5e3496eb10dd1fbdca2d79a4303'
WAIT_PHASES_SOURCE_SHA256 = 'e34bcb0749e6966fce29d843b4260f13b62ad416c4d1f463396077374be02e2e'
BASELINE_423593_SOURCE_SHA256 = {
    'NativeAdrenoMetalPlugin.mm': '538d662c52309be575c13f8df1ffa4e68ce9e13f3a03555a3be4337bdd558f3d',
    'bridge/NativeMetalObjects.rs': '2814eb99b0179461676715656ff2a33aaa90357825c7497925e4923d1f3278ed',
    'NativeBridgeMetalFrontend.mm': '0dac90bab205e74dcc07ff186995d037148384c3e59f88cea286c93b68886814',
}
WORKER_RUNTIME_SOURCES = {
    'crates/metal2vulkan/src/device/policy.rs':
        '1e07afdb2952046d13f593922fae6a27b6f26939912b6abf542645c60653a5e6',
    'crates/metal2vulkan-runtime/src/render/lowering_worker.rs':
        '7e7708155146b4d1d9d787e83aa47c86c04ef1f3ddd2362b66d945df2ba05a4e',
    'crates/metal2vulkan-runtime/src/render/deferral.rs':
        'ad0bffb3ffcba81f80d60b42a4e763d3f043c832c794c1c56a3ec4cc313a53d8',
    WAIT_PHASES_SOURCE: WAIT_PHASES_UPSTREAM_SOURCE_SHA256,
}
ASYNC_PATCH = 'patches/adrenometal-nabu-async-creation.patch'
ASYNC_PATCHES = ADRENOMETAL_PATCHES[:4] + (ASYNC_PATCH,)
COMPLETION_PATCH = 'patches/adrenometal-nabu-completion-wait.patch'
COMPLETION_PATCHES = ADRENOMETAL_PATCHES[:4] + (COMPLETION_PATCH,)
COMPLETION_OBSERVE_PATCH = 'patches/adrenometal-nabu-completion-observe.patch'
COMPLETION_OBSERVE_PATCHES = ADRENOMETAL_PATCHES[:4] + (COMPLETION_OBSERVE_PATCH,)
RUNTIME_QOS_PATCH = 'patches/metal2vulkan-nabu-ios-qos.patch'
RUNTIME_QOS_UPSTREAM = 'a0f0287be80a5d8aef5c6b97a6cab62129e152bd'
RUNTIME_SERIES_SHA256 = '35009afa0c0a344e6a9d2a31d562bdf43022b52d4f773d4769f9d82666bfbbf3'
RUNTIME_QOS_SOURCE_SHA256 = '2237c261d794ebd288eb0dce441272bb046314ae016be1a97ff4d1fc759ac572'
UNDEPLOYED = ('adrenoprobed', 'adrenoprobed-entitlements.plist', 'org.blu-sharky.adrenoprobed.plist',
              'com.apple.iomfb_fdr_loader.plist', 'com.apple.bluetoothd.plist')


def run(command, **kwargs):
    print('+ ' + ' '.join(map(str, command)), flush=True)
    return subprocess.run([str(c) for c in command], check=True, **kwargs)


def read(command):
    return subprocess.check_output([str(c) for c in command], text=True).strip()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fetch(path, url, commit, *, blob_filter=False):
    run(['git', 'init', '-q', path])
    run(['git', '-C', path, 'remote', 'add', 'origin', url])
    run(['git', '-C', path, 'fetch', '-q', '--depth', '1', *(['--filter=blob:none'] if blob_filter else []),
         'origin', commit])
    run(['git', '-C', path, 'checkout', '-q', commit])
    if read(['git', '-C', path, 'rev-parse', 'HEAD']) != commit:
        raise SystemExit('Pinned checkout differs: ' + str(path))


def board_arguments(turnip_render_mode=None):
    if turnip_render_mode is None:
        return BOARD_ARGUMENTS
    if turnip_render_mode not in TURNIP_RENDER_MODES:
        raise ValueError('Turnip render mode must be sysmem or gmem; both retain nocb')
    return BOARD_ARGUMENTS + ('--turnip-debug', turnip_render_mode + ',nocb')


def plugin_patches(fps_opt=False, async_fix=False, completion_fix=False, completion_observe=False,
                   wallpaper_fix=False, worker_opt=False, turnip_render_mode=None):
    board_arguments(turnip_render_mode)
    if turnip_render_mode is not None and not worker_opt:
        raise ValueError('Turnip render-mode comparison requires the worker observation recipe')
    if sum((fps_opt, async_fix, completion_fix, completion_observe)) > 1:
        raise ValueError('Keep the async creation, FPS, completion-wait and completion-observation experiments separate')
    if worker_opt:
        if not fps_opt or not wallpaper_fix:
            raise ValueError('The lowering-worker experiment requires the FPS/QoS wallpaper source recipe')
        if async_fix or completion_fix or completion_observe:
            raise ValueError('Keep the lowering-worker experiment separate from async and completion modes')
        return WORKER_OBSERVATION_PATCHES + ((RENDER_MODE_PATCH,) if turnip_render_mode is not None else ())
    if wallpaper_fix:
        if not fps_opt:
            raise ValueError('Wallpaper CoreImage support requires the FPS/QoS profile')
        return WALLPAPER_PATCHES
    if async_fix:
        return ASYNC_PATCHES
    if completion_fix:
        return COMPLETION_PATCHES
    if completion_observe:
        return COMPLETION_OBSERVE_PATCHES
    # The FPS experiment starts from the four-patch, desktop-capable plugin.
    # Preserve the separate CoreImage experiment instead of mixing its changes in.
    return FPS_PATCHES if fps_opt else ADRENOMETAL_PATCHES


def mps_contract_source(frontend):
    def section(start, end):
        if frontend.count(start) != 1:
            raise ValueError('MPS contract source drift: ' + start)
        tail = frontend.split(start, 1)[1]
        if end not in tail:
            raise ValueError('MPS contract source lacks terminator: ' + end)
        return start + tail.split(end, 1)[0]

    dictionary = section('static char kUserDictionaryKey;\n', '- (instancetype)init')
    alignment = section('- (NSUInteger)minimumTextureBufferAlignmentForPixelFormat:', '- (uint64_t)registryID')
    protocols = section('  static const char *const conformances[][2]={\n', '\n}\n objc_registerClassPair')
    pairs = re.findall(r'\{"(NB\w+)","(MTL\w+)"\}', protocols)
    expected = (
        ('NBBuffer', 'MTLBuffer'), ('NBTexture', 'MTLTexture'), ('NBLibrary', 'MTLLibrary'),
        ('NBFunction', 'MTLFunction'), ('NBComputePipeline', 'MTLComputePipelineState'),
        ('NBRenderPipeline', 'MTLRenderPipelineState'), ('NBSampler', 'MTLSamplerState'),
        ('NBDepthStencil', 'MTLDepthStencilState'), ('NBEvent', 'MTLEvent'), ('NBSharedEvent', 'MTLSharedEvent'),
        ('NBFence', 'MTLFence'), ('NBQueue', 'MTLCommandQueue'), ('NBCommandBuffer', 'MTLCommandBuffer'),
        ('NBEncoder', 'MTLCommandEncoder'), ('NBComputeEncoder', 'MTLComputeCommandEncoder'),
        ('NBRenderEncoder', 'MTLRenderCommandEncoder'), ('NBBlitEncoder', 'MTLBlitCommandEncoder'),
        ('NBHeap', 'MTLHeap'), ('NBBinaryArchive', 'MTLBinaryArchive'),
    )
    if tuple(pairs) != expected or '- (id)userDictionary' not in dictionary or \
            '- (NSUInteger)iosurfaceReadOnlyTextureAlignmentBytes' not in alignment:
        raise ValueError('MPS contract methods or protocol set changed')
    for name, _ in pairs:
        parent = 'NBEvent' if name == 'NBSharedEvent' else 'NBEncoder' if name in (
            'NBComputeEncoder', 'NBRenderEncoder', 'NBBlitEncoder') else 'NBObject'
        declarations = re.findall(r'^@interface\s+' + name + r'\s*:\s*(\w+)\b', frontend, re.MULTILINE)
        implementations = re.findall(r'^@implementation\s+' + name + r'\s*(?:\{|$)', frontend, re.MULTILINE)
        if declarations != [parent] or len(implementations) != 1:
            raise ValueError('MPS production class declaration or implementation changed: ' + name)
    declarations = '\n'.join('@interface %s : NSObject\n@end\n@implementation %s\n@end' % (name, name)
                             for name, _ in pairs if name != 'NBCommandBuffer')
    protocol_objects = ','.join('@protocol(%s)' % protocol for _, protocol in pairs)
    class_objects = ','.join('[%s class]' % name for name, _ in pairs)
    return MPS_CONTRACT_HARNESS.replace('__CLASSES__', declarations).replace(
        '__DICTIONARY__', dictionary).replace('__ALIGNMENT__', alignment).replace(
        '__PROTOCOL_INSTALL__', protocols).replace('__PROTOCOLS__', protocol_objects).replace(
        '__CLASS_OBJECTS__', class_objects)


MPS_CONTRACT_HARNESS = r'''
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <dispatch/dispatch.h>
#include <cstdio>
#include <cstdlib>

static void require(bool condition,const char *why) {
 if(!condition){fprintf(stderr,"FAIL %s\n",why);exit(2);}
}
__CLASSES__
@interface NBCommandBuffer : NSObject
- (id)userDictionary;
@end
@implementation NBCommandBuffer
__DICTIONARY__
@end
@interface NBDeviceMethods : NSObject
@property(nonatomic) NSUInteger requestedFormat;
- (NSUInteger)minimumLinearTextureAlignmentForPixelFormat:(NSUInteger)format;
- (NSUInteger)minimumTextureBufferAlignmentForPixelFormat:(NSUInteger)format;
- (NSUInteger)iosurfaceReadOnlyTextureAlignmentBytes;
@end
@implementation NBDeviceMethods
- (NSUInteger)minimumLinearTextureAlignmentForPixelFormat:(NSUInteger)format {
 self.requestedFormat=format;return format==MTLPixelFormatRGBA16Float?512:256;
}
__ALIGNMENT__
@end
static void installProtocols() {
__PROTOCOL_INSTALL__
}
int main() {
 @autoreleasepool {
  Protocol *protocols[]={__PROTOCOLS__};
  Class classes[]={__CLASS_OBJECTS__};
  NSMutableArray *instances=[NSMutableArray array];
  const size_t count=sizeof(classes)/sizeof(classes[0]);
  require(count==19,"closed protocol set");
  for(size_t index=0;index<count;++index) {
   require(protocols[index]!=nil,"Metal protocol available");
   require(!class_conformsToProtocol(classes[index],protocols[index]),"negative conformance control");
   id instance=[classes[index] new];[instances addObject:instance];
   require(![instance conformsToProtocol:protocols[index]],"existing object negative control");
  }
  installProtocols();
  for(size_t index=0;index<count;++index) {
   require([[classes[index] new] conformsToProtocol:protocols[index]],"object protocol installed");
   require([instances[index] conformsToProtocol:protocols[index]],"existing object protocol installed");
  }
  NBCommandBuffer *first=[NBCommandBuffer new],*second=[NBCommandBuffer new];
  NSMutableDictionary *dictionary=[first userDictionary];
  require([dictionary isKindOfClass:[NSMutableDictionary class]],"mutable dictionary");
  dictionary[@"MPS-state"]=@37;
  require([first userDictionary]==dictionary,"stable dictionary identity");
  require([[first userDictionary][@"MPS-state"] isEqual:@37],"state retained");
  require([second userDictionary]!=dictionary && [[second userDictionary] count]==0,"per-buffer isolation");
  dispatch_apply(64,dispatch_get_global_queue(QOS_CLASS_DEFAULT,0),^(size_t index) {
   (void)index;require([first userDictionary]==dictionary,"concurrent identity");
  });
  NBCommandBuffer *cold=[NBCommandBuffer new];
  NSMutableArray *identities=[NSMutableArray array];
  dispatch_apply(64,dispatch_get_global_queue(QOS_CLASS_DEFAULT,0),^(size_t index) {
   (void)index;id identity=[cold userDictionary];
   @synchronized(identities){[identities addObject:identity];}
  });
  for(id identity in identities)require(identity==[cold userDictionary],"concurrent first initialization");
  NBDeviceMethods *device=[NBDeviceMethods new];
  require([device minimumTextureBufferAlignmentForPixelFormat:MTLPixelFormatBGRA8Unorm]==256,"buffer alignment forwarded");
  require(device.requestedFormat==MTLPixelFormatBGRA8Unorm,"buffer format preserved");
  require([device iosurfaceReadOnlyTextureAlignmentBytes]==512,"IOSurface alignment forwarded");
  require(device.requestedFormat==MTLPixelFormatRGBA16Float,"IOSurface format preserved");
  puts("MPS_OBJECT_CONTRACT_OK protocols=19 dictionary=stable-isolated alignment=forwarded gpu=not-exercised");
 }
 return 0;
}
'''


def qualify_mps_contract(frontend, output, env):
    if sys.platform != 'darwin' or env.get('GITHUB_ACTIONS') != 'true':
        raise SystemExit('MPS Foundation/Metal qualification runs only in macOS GitHub Actions')
    source = mps_contract_source(frontend.read_text())
    output.mkdir()
    harness = output / 'mps-contract.mm'
    harness.write_text(source)
    binary = output / 'mps-contract'
    with (output / 'compile.log').open('w') as log:
        run(['xcrun', '--sdk', 'macosx', 'clang++', '-std=c++17', '-fobjc-arc',
             '-framework', 'Foundation', '-framework', 'Metal', harness, '-o', binary],
            env=env, stdout=log, stderr=subprocess.STDOUT)
    result = subprocess.run([str(binary)], env=env, text=True, capture_output=True, timeout=30)
    (output / 'run.log').write_text(result.stdout + result.stderr)
    expected = 'MPS_OBJECT_CONTRACT_OK protocols=19 dictionary=stable-isolated alignment=forwarded gpu=not-exercised'
    if result.returncode or result.stdout.strip() != expected:
        raise SystemExit('MPS object contract qualification failed; see ' + str(output / 'run.log'))
    return dict(upstream_commit=MPS_CONTRACT_UPSTREAM, frontend_sha256=sha(frontend),
                harness_sha256=sha(harness), metal_protocols=19, command_buffer_dictionary=True,
                iosurface_alignment_forwarded=True, texture_buffer_alignment_forwarded=True,
                host_foundation_metal_qualified=True, qualification_scope='protocol-registration-shim',
                gpu_core_count_changed=False,
                gpu_exercised=False, runtime_qualified=False)


def qualify_gpu_core_count(bridge, output, env):
    bridge = Path(bridge)
    helper = bridge / 'NabuGpuCoreCount.rs'
    source = bridge / 'NativeMetalObjects.rs'
    text = source.read_text()
    binding = '''        let reported = device.private().count(c).value();
        return if selector == "gpuCoreCount" {
            nabu_gpu_core_count::answer(reported, p.vendor_id, p.device_id)
        } else {
            reported
        }.ok_or_else(none);'''
    if text.count('include!("NabuGpuCoreCount.rs");') != 1 or text.count(binding) != 1:
        raise ValueError('GPU core-count fallback is not bound to the real Vulkan identity and runtime answer')
    output.mkdir()
    archived = output / helper.name
    shutil.copyfile(helper, archived)
    shutil.copyfile(source, output / source.name)
    binary = output / ('gpu-core-count.exe' if sys.platform == 'win32' else 'gpu-core-count')
    with (output / 'compile.log').open('w') as log:
        run(['rustc', '+' + RUST, '--edition=2024', '--test', archived, '-o', binary],
            env=env, stdout=log, stderr=subprocess.STDOUT)
    result = subprocess.run([str(binary), '--test-threads=1'], env=env, text=True,
                            capture_output=True, timeout=30)
    (output / 'run.log').write_text(result.stdout + result.stderr)
    if result.returncode or '4 passed; 0 failed;' not in result.stdout:
        raise SystemExit('GPU core-count production Rust qualification failed')
    return dict(helper_sha256=sha(helper), bridge_sha256=sha(source), production_rust_tests=4,
                vendor_id='0x5143', device_id='0x06040001', fallback_sp_cores=2,
                topology_source='Mesa 85fda3b36405bcaea8bffc64aa4f2651dc90770d GPUId(640) num_sp_cores=2',
                reported_answer_has_priority=True, gpu_exercised=False, runtime_qualified=False)


def prepare_runtime_qos(metal, device, *, wait_phases=False):
    directory = metal / 'bridge/patches'
    series = directory / 'series'
    patch = directory / Path(RUNTIME_QOS_PATCH).name
    if sha(series) != RUNTIME_SERIES_SHA256 or patch.exists():
        raise SystemExit('Runtime patch series differs from the pinned baseline')
    original = series.read_bytes()
    if wait_phases:
        phases = directory / Path(RUNTIME_WAIT_PHASES_PATCH).name
        if phases.exists():
            raise SystemExit('Runtime wait-phase patch already exists in the baseline')
        shutil.copyfile(device / RUNTIME_WAIT_PHASES_PATCH, phases)
        original += phases.name.encode() + b'\n'
    shutil.copyfile(device / RUNTIME_QOS_PATCH, patch)
    series.write_bytes(original + patch.name.encode() + b'\n')


def collect_runtime_qos(root, device, output, *, wait_phases=False):
    directory = root / 'drivers/AdrenoMetal/bridge/patches'
    series = directory / 'series'
    patch = directory / Path(RUNTIME_QOS_PATCH).name
    expected = (device / RUNTIME_QOS_PATCH).read_bytes()
    lines = series.read_bytes().splitlines(keepends=True)
    tail = [patch.name.encode() + b'\n']
    if wait_phases:
        phases = directory / Path(RUNTIME_WAIT_PHASES_PATCH).name
        if phases.read_bytes() != (device / RUNTIME_WAIT_PHASES_PATCH).read_bytes():
            raise SystemExit('Compiled runtime wait-phase patch differs from its input')
        tail.insert(0, phases.name.encode() + b'\n')
    if (lines[-len(tail):] != tail or
            hashlib.sha256(b''.join(lines[:-len(tail)])).hexdigest() != RUNTIME_SERIES_SHA256 or
            patch.read_bytes() != expected):
        raise SystemExit('Compiled runtime patch series differs from the nabu QoS input')
    source = root / '.cache/gpu-reference/metal2vulkan/crates/metal2vulkan-runtime/src/exit_guard.rs'
    if sha(source) != RUNTIME_QOS_SOURCE_SHA256:
        raise SystemExit('Compiled iOS QoS source differs from the replayed upstream implementation')
    runtime = root / '.cache/gpu-reference/metal2vulkan'
    run(['git', '-C', runtime, 'apply', '--reverse', '--check', patch])
    archive = output / 'runtime-qos-source'
    archive.mkdir()
    for path in (series, patch, source):
        shutil.copyfile(path, archive / path.name)
    return dict(upstream_repository='https://github.com/UniXNU/AdrenoMetal',
                upstream_commit=RUNTIME_QOS_UPSTREAM,
                upstream_patch='bridge/patches/0023-quality-of-service-on-ios.patch',
                patch_sha256=sha(patch), baseline_series_sha256=RUNTIME_SERIES_SHA256,
                series_sha256=sha(series), source_sha256=sha(source),
                target='aarch64-apple-ios', runtime_qualified=False)


def collect_runtime_wait_phases(root, device, output):
    runtime = root / '.cache/gpu-reference/metal2vulkan'
    source = runtime / WAIT_PHASES_SOURCE
    patch = root / 'drivers/AdrenoMetal/bridge/patches' / Path(RUNTIME_WAIT_PHASES_PATCH).name
    if patch.read_bytes() != (device / RUNTIME_WAIT_PHASES_PATCH).read_bytes():
        raise SystemExit('Compiled runtime wait-phase patch differs from its input')
    if sha(source) != WAIT_PHASES_SOURCE_SHA256:
        raise SystemExit('Compiled runtime wait-phase source differs from the exact replay')
    run(['git', '-C', runtime, 'apply', '--reverse', '--check', patch])
    archive = output / 'runtime-wait-phases-source'
    archive.mkdir()
    shutil.copyfile(source, archive / 'command_buffer-mod.rs')
    shutil.copyfile(patch, archive / patch.name)
    return dict(compiled=True, patch_sha256=sha(patch),
                upstream_source_sha256=WAIT_PHASES_UPSTREAM_SOURCE_SHA256,
                baseline_source_sha256=WAIT_PHASES_BASELINE_SOURCE_SHA256,
                source_sha256=sha(source), source_path=WAIT_PHASES_SOURCE,
                unit='us', head_row='J phase-us s<count> settle<us> post<us> c<count> settle<us> post<us>',
                counter_reads='independent process-wide cumulative values',
                samples='accepted untimed calls including post-entry errors and repeated calls',
                excluded='refusals before phase entry and timed completion waits',
                post='original submission progress, scheduled handlers or completion gate, and completion trails',
                runtime_qualified=False)


def verify_lowering_worker_runtime(source):
    source = Path(source)
    observed = {}
    for relative, expected in WORKER_RUNTIME_SOURCES.items():
        path = source / relative
        if not path.is_file():
            raise ValueError('Lowering-worker runtime source is missing: ' + relative)
        digest = sha(path)
        if digest != expected:
            raise ValueError('Lowering-worker runtime source differs from pin: ' + relative)
        observed[relative] = digest
    policy = (source / 'crates/metal2vulkan/src/device/policy.rs').read_text()
    worker = (source / 'crates/metal2vulkan-runtime/src/render/lowering_worker.rs').read_text()
    deferral = (source / 'crates/metal2vulkan-runtime/src/render/deferral.rs').read_text()
    if 'pub render_lowering: RenderLoweringPolicy' not in policy or '    Worker,' not in policy:
        raise ValueError('Pinned runtime does not expose RenderLoweringPolicy::Worker')
    if 'struct LoweringWorker' not in worker or 'ENDS_IN_FLIGHT' not in worker:
        raise ValueError('Pinned runtime lowering worker implementation differs')
    if 'RenderLoweringPolicy::Worker' not in deferral:
        raise ValueError('Pinned runtime deferral path does not select Worker')
    return observed


def verify_423593_source(metal):
    metal = Path(metal)
    observed = {}
    for relative, expected in BASELINE_423593_SOURCE_SHA256.items():
        path = metal / relative
        if not path.is_file():
            raise ValueError('423593 source baseline file is missing: ' + relative)
        digest = sha(path)
        if digest != expected:
            raise ValueError('Source differs from the 423593 nine-patch baseline: ' + relative)
        observed[relative] = digest
    return observed


def prepare_private_shader_cache(metal, device):
    patch = device / 'patches/adrenometal-nabu-private-shader-cache.patch'
    header = device / 'platform/NabuPrivateShaderCache.h'
    target = metal / header.name
    if target.exists() or target.is_symlink() or not header.is_file() or header.is_symlink():
        raise ValueError('Private cache helper input or target differs')
    run(['git', '-C', metal, 'apply', '--check', patch])
    run(['git', '-C', metal, 'apply', patch])
    shutil.copyfile(header, target)
    return dict(patch_sha256=sha(patch), helper_sha256=sha(target),
                frontend_sha256=sha(metal / 'NativeBridgeMetalFrontend.mm'),
                smoke_sha256=sha(metal / 'NativeTurnipSmoke.h'),
                policy='private cache root/ir3; owner probe caches only when ngpu owner matches its runtime UID',
                shared_uid_cache=False, runtime_qualified=False)


def prepare(root, device, fps_opt=False, async_fix=False, completion_fix=False, completion_observe=False,
            wallpaper_fix=False, worker_opt=False, turnip_render_mode=None):
    selected = plugin_patches(fps_opt, async_fix, completion_fix, completion_observe, wallpaper_fix, worker_opt,
                              turnip_render_mode)
    for path, (url, commit) in SUBMODULES.items():
        entry = read(['git', '-C', root, 'ls-tree', 'HEAD', path]).split()
        if entry[:3] != ['160000', 'commit', commit]:
            raise SystemExit('UniXNU gitlink differs from the recorded pin: ' + path)
        target = root / path
        if target.exists() and any(target.iterdir()):
            raise SystemExit('Submodule path is not empty: ' + path)
        fetch(target, url, commit)
    metal = root / 'drivers/AdrenoMetal'
    for patch in selected:
        if worker_opt and patch == LOWERING_WORKER_PATCH:
            verify_423593_source(metal)
        if patch == ASYNC_PATCH:
            shutil.copyfile(metal / 'NativeBridgeMetalFrontend.mm', metal / 'NabuAsyncCreation.baseline.mm')
        run(['git', '-C', metal, 'apply', '--check', device / patch])
        run(['git', '-C', metal, 'apply', device / patch])
    shutil.copyfile(device / 'platform/NabuGpuScanoutWire.h', metal / 'NabuGpuScanoutWire.h')
    shutil.copyfile(device / 'platform/NabuGpuProblemStream.h', metal / 'NabuGpuProblemStream.h')
    if turnip_render_mode is not None:
        header = device / RENDER_MODE_HEADER
        target = metal / header.name
        if not header.is_file() or header.is_symlink() or target.exists() or target.is_symlink():
            raise ValueError('Render-mode observer helper input or target differs')
        shutil.copyfile(header, target)
    if fps_opt:
        shutil.copyfile(device / 'platform/NabuScanoutSourceCache.h', metal / 'NabuScanoutSourceCache.h')
        prepare_runtime_qos(metal, device, wait_phases=worker_opt)
        if not worker_opt:
            prepare_private_shader_cache(metal, device)
    pins = json.loads((root / 'scripts/data/gpu-metal-vulkan-inputs.json').read_text())
    translator = pins['translator']['commit']
    if pins['translator']['repository'].rstrip('/') + '.git' != METAL2VULKAN:
        raise SystemExit('Translator repository differs from the recorded pin')
    source = root / '.cache/gpu-reference/metal2vulkan'
    source.parent.mkdir(parents=True, exist_ok=True)
    fetch(source, METAL2VULKAN, translator, blob_filter=True)
    if worker_opt:
        if translator != WORKER_RUNTIME_UPSTREAM:
            raise SystemExit('Lowering-worker runtime pin differs: ' + translator)
        verify_lowering_worker_runtime(source)
    return translator


def bundle_files(bundle):
    files = []
    for path in sorted(bundle.rglob('*')):
        if path.is_symlink():
            raise SystemExit('Linked file in the plugin bundle: ' + str(path))
        if path.is_file():
            files.append({'path': path.relative_to(bundle.parent).as_posix(), 'bytes': path.stat().st_size,
                          'sha256': sha(path), 'mode': oct(path.stat().st_mode & 0o7777)})
    return files


def collect_render_mode(root, device, output, selected):
    """Bind the selected observer to the actual, exported eight-word provider.

    Only selected experiments depend on this symbol. No GPU runs on the host;
    mode selection and a linked observer are not evidence of executed GMEM work.
    """
    board_arguments(selected)
    metal = root / 'drivers/AdrenoMetal'
    header = metal / Path(RENDER_MODE_HEADER).name
    if header.read_bytes() != (device / RENDER_MODE_HEADER).read_bytes():
        raise ValueError('Compiled render-mode helper differs from its input')
    library = root / 'build/adreno-metal-plugin/NativeAdrenoMetal.bundle/libvulkan_freedreno.dylib'
    symbols = read(['xcrun', 'nm', '-gU', library])
    if sum(line.split()[-1:] == ['_tu_render_mode_stats'] for line in symbols.splitlines()) != 1:
        raise ValueError('Built Turnip does not export exactly one tu_render_mode_stats provider')
    provider = root / '.cache/mesa-work/src/freedreno/vulkan/tu_cmd_buffer.cc'
    text = provider.read_text()
    if ('static uint64_t tu_render_mode_counts[8];' not in text or
            'tu_render_mode_stats(uint64_t out[8])' not in text or
            'out[i] = p_atomic_read(&tu_render_mode_counts[i]);' not in text):
        raise ValueError('Turnip render-mode provider differs from the recorded eight-word ABI')
    archive = output / 'render-mode-source'
    archive.mkdir()
    sources = (header, metal / 'NativeAdrenoMetalConfig.h', metal / 'NativeAdrenoMetalPlugin.mm',
               metal / 'NativeBridgeMetalFrontend.mm', provider, root / RENDER_MODE_PROVIDER,
               device / RENDER_MODE_PATCH)
    for path in sources:
        shutil.copyfile(path, archive / path.name)
    return dict(compiled=True, requested=selected, turnip_debug=selected + ',nocb',
                inherited_debug_overridden=True, concurrent_binning=False,
                provider_symbol='tu_render_mode_stats', provider_words=8,
                source_sha256={path.name: sha(path) for path in sources},
                head_rows=['S-pid', 'RM1-render-mode', 'J-runtime-phases'],
                pipeline_row='retained after head rows; not in the installed writer first-three snapshot',
                counters='independent process-wide recorded passes, not completed work or frames',
                count_encoding='hexadecimal', mode_codes={'s': 'sysmem,nocb', 'g': 'gmem,nocb', '?': 'unexpected'},
                missing_provider='explicit unavailable row, never zero counters',
                gpu_exercised=False, runtime_qualified=False)


def build(root, device, output, env, fps_opt=False, async_fix=False, completion_fix=False, completion_observe=False,
          wallpaper_fix=False, worker_opt=False, turnip_render_mode=None):
    """Returns the report's plugin section; the build's own return code is plugin['plugin_returncode']."""
    root, device, output = Path(root), Path(device).resolve(), Path(output)
    abi = device / 'gpu/upstream/Adreno6xx'
    output.mkdir(parents=True)
    report = {'adrenometal_commit': SUBMODULES['drivers/AdrenoMetal'][1],
              'adrenopm4_commit': SUBMODULES['kits/AdrenoPM4'][1], 'rust_toolchain': RUST,
              'abi_header_sha256': sha(abi / 'NativeAdrenoABI.h'), 'gpu_exercised': False, 'runtime_qualified': False}
    selected = plugin_patches(fps_opt, async_fix, completion_fix, completion_observe, wallpaper_fix, worker_opt,
                              turnip_render_mode)
    report['metal2vulkan_commit'] = prepare(root, device, fps_opt, async_fix, completion_fix, completion_observe,
                                            wallpaper_fix, worker_opt, turnip_render_mode)
    report['adrenometal_patches'] = {patch: sha(device / patch)
                                   for patch in selected}
    report['fps_opt'] = fps_opt
    report['async_fix'] = async_fix
    report['completion_fix'] = completion_fix
    report['completion_observe'] = completion_observe
    report['wallpaper_fix'] = wallpaper_fix
    report['worker_opt'] = worker_opt
    report['turnip_render_mode'] = turnip_render_mode
    if turnip_render_mode is not None:
        report['render_mode'] = dict(compiled=False, requested=turnip_render_mode,
            turnip_debug=turnip_render_mode + ',nocb', patch_sha256=sha(device / RENDER_MODE_PATCH),
            helper_sha256=sha(device / RENDER_MODE_HEADER), runtime_qualified=False)
    report['baseline_recipe'] = ('423593-adrenometal-nine-patch-no-private-cache' if worker_opt else
                                 'wallpaper-current' if wallpaper_fix else 'default-mode')
    report['runtime_telemetry'] = {
        'compiled': RUNTIME_TELEMETRY_PATCH in selected,
        'patch_sha256': sha(device / RUNTIME_TELEMETRY_PATCH),
        'head_rows': ['S-pid', 'RM1-render-mode' if turnip_render_mode is not None else 'V-pipeline',
                      'J-runtime-phases'],
        'wait_stages': {'runtime': 'runtime wait call including queued lowering settlement',
                        'handlers': 'frontend dispatch group wait',
                        'original_wait_totals_retained': True,
                         'original_split_row': 'replaces the later redundant completed-wait row',
                        'counter_reads': 'independent cumulative values'},
        'runtime_qualified': False,
    }
    report['lowering_worker'] = {
        'compiled': LOWERING_WORKER_PATCH in selected,
        'default_enabled': False,
        'gate': 'readable kern.bootargs + exact nabu-metal-worker=1 + process backboardd',
        'status_codes': {'1': 'other-process', '2': 'bootargs-read-failed', '3': 'bootargs-too-large',
                         '4': 'bootarg-disabled', '5': 'enabled'},
        'patch_sha256': sha(device / LOWERING_WORKER_PATCH),
        'runtime_pin': WORKER_RUNTIME_UPSTREAM,
        'baseline_sources_sha256': BASELINE_423593_SOURCE_SHA256,
        'baseline_reference': {
            'run_id': 42359337632,
            'head_sha': 'ac643d4c2396dfd24cf4c7d3e4848c04a44ffa09',
            'addon_sha256': '2b42f3051d4b1415a7ab28038bb2d0ba3ab9874cef1ec0f8b3f2ab467fa71359',
            'plugin_sha256': 'f3c57031f4a724c73a3b5618a133c4f395853b309ddab64206291ac2d34fa1b3',
            'turnip_sha256': '202e425a68e625de63a0e096c81e4d006eed8aaa7529dbfc93bc4f02d16180ab',
            'byte_identity_expected': False,
        },
        'private_shader_cache_compiled': False,
        'runtime_qualified': False,
    }
    report['runtime_qos_compiled'] = fps_opt
    report['private_shader_cache'] = {
        'compiled': fps_opt and not worker_opt,
        'excluded_by_worker_opt': worker_opt,
        'runtime_qualified': False,
    }
    if worker_opt:
        report['runtime_wait_phases'] = dict(compiled=False,
            patch_sha256=sha(device / RUNTIME_WAIT_PHASES_PATCH),
            upstream_source_sha256=WAIT_PHASES_UPSTREAM_SOURCE_SHA256,
            baseline_source_sha256=WAIT_PHASES_BASELINE_SOURCE_SHA256,
            source_sha256=None, runtime_qualified=False)
        metal = root / 'drivers/AdrenoMetal'
        report['lowering_worker']['sources_sha256'] = {
            relative: sha(metal / relative)
            for relative in BASELINE_423593_SOURCE_SHA256
        }
        report['lowering_worker']['runtime_sources_sha256'] = verify_lowering_worker_runtime(
            root / '.cache/gpu-reference/metal2vulkan')
    if completion_observe:
        from nabu_metal_completion_observation import qualify
        source_output = output / 'completion-observe-source'
        source_output.mkdir()
        metal = root / 'drivers/AdrenoMetal'
        report['completion_observation'] = qualify(
            metal / 'NativeBridgeMetalFrontend.mm', source_output, device / COMPLETION_OBSERVE_PATCH)
        report['completion_observation_helper_sha256'] = sha(
            Path(__file__).with_name('nabu_metal_completion_observation.py'))
    if async_fix:
        from nabu_metal_async_qualification import qualify
        source_output = output / 'async-source'
        source_output.mkdir()
        metal = root / 'drivers/AdrenoMetal'
        baseline = source_output / 'NativeBridgeMetalFrontend.baseline.mm'
        fixed = source_output / 'NativeBridgeMetalFrontend.mm'
        shutil.copyfile(metal / 'NabuAsyncCreation.baseline.mm', baseline)
        shutil.copyfile(metal / 'NativeBridgeMetalFrontend.mm', fixed)
        report['async_creation'] = qualify(baseline, fixed, output / 'async-qualification', env)
        report['async_qualification_sha256'] = sha(Path(__file__).with_name('nabu_metal_async_qualification.py'))
    if fps_opt:
        report['scanout_source_cache'] = {
            'version': 1, 'slots': 8, 'slot_identity': 'NGPSwap.reserved',
            'kernel_maps_must_not_evict': True, 'gpu_completion_required': True,
            'coreimage_patch_applied': wallpaper_fix,
            'header_sha256': sha(device / 'platform/NabuScanoutSourceCache.h'),
            'runtime_qualified': False,
        }
        sources = ('GpuScanoutPresenter.h', 'GpuScanoutClient.h', 'NativeMetalBridgePhase.h',
                   'NabuScanoutSourceCache.h')
        source_output = output / 'fps-source'
        source_output.mkdir()
        for name in sources:
            shutil.copyfile(root / 'drivers/AdrenoMetal' / name, source_output / name)
        report['fps_source_sha256'] = {name: sha(source_output / name) for name in sources}
    if wallpaper_fix:
        source_output = output / 'wallpaper-source'
        source_output.mkdir()
        frontend = root / 'drivers/AdrenoMetal/NativeBridgeMetalFrontend.mm'
        shutil.copyfile(frontend, source_output / frontend.name)
        report['wallpaper_source_sha256'] = {frontend.name: sha(frontend)}
        report['mps_object_contract'] = qualify_mps_contract(frontend, output / 'mps-contract', env)
        report['mps_object_contract']['patch_sha256'] = sha(device / MPS_CONTRACT_PATCH)
        report['gpu_core_count'] = qualify_gpu_core_count(root / 'drivers/AdrenoMetal/bridge',
                                                        output / 'gpu-core-count', env)
        report['gpu_core_count']['patch_sha256'] = sha(device / GPU_CORE_COUNT_PATCH)
        report['wallpaper_support'] = dict(extern_function_names=True, ci_kernel_functions=True,
            stitched_libraries=True, function_bitcode_identity=True, runtime_qualified=False)
    report['scanout_wire_sha256'] = sha(device / 'platform/NabuGpuScanoutWire.h')
    report['problem_stream_sha256'] = sha(device / 'platform/NabuGpuProblemStream.h')
    report['rust_version'] = read(['rustc', '+' + RUST, '--version'])
    compiler = shutil.which('glslangValidator', path=env['PATH'])
    if not compiler:
        raise SystemExit('glslangValidator is required for the bundled shaders')
    arguments = ['--gpu-abi-dir', str(abi), *board_arguments(turnip_render_mode), '--shader-compiler', compiler]
    report['arguments'] = arguments
    log = output / 'build-adreno-metal-plugin.log'
    with log.open('w') as stream:
        result = subprocess.run(['python3', root / 'scripts/build-adreno-metal-plugin.py', *arguments], cwd=root,
                                env=env, stdout=stream, stderr=subprocess.STDOUT)
    report['plugin_returncode'] = result.returncode
    bridge_log = root / 'build/adreno-metal-bridge/build-ios.log'
    if bridge_log.is_file():
        shutil.copyfile(bridge_log, output / 'bridge-build-ios.log')
    built = root / 'build/adreno-metal-plugin'
    bundle = built / 'NativeAdrenoMetal.bundle'
    report['bundle_built'] = result.returncode == 0 and (bundle / 'NativeAdrenoMetal').is_file()
    if report['bundle_built']:
        if fps_opt:
            report['runtime_qos'] = collect_runtime_qos(root, device, output, wait_phases=worker_opt)
        if worker_opt:
            report['runtime_wait_phases'] = collect_runtime_wait_phases(root, device, output)
        if turnip_render_mode is not None:
            report['render_mode'].update(collect_render_mode(root, device, output, turnip_render_mode))
        if fps_opt and not worker_opt:
            metal = root / 'drivers/AdrenoMetal'
            helper = metal / 'NabuPrivateShaderCache.h'
            if helper.read_bytes() != (device / 'platform/NabuPrivateShaderCache.h').read_bytes():
                raise ValueError('Built private cache helper differs from its input')
            report['private_shader_cache'] = dict(helper_sha256=sha(helper),
                patch_sha256=sha(device / 'patches/adrenometal-nabu-private-shader-cache.patch'),
                frontend_sha256=sha(metal / 'NativeBridgeMetalFrontend.mm'),
                smoke_sha256=sha(metal / 'NativeTurnipSmoke.h'), compiled=True, shared_uid_cache=False,
                runtime_qualified=False)
            cache_source = output / 'cache-source'
            cache_source.mkdir()
            for name in ('NabuPrivateShaderCache.h', 'NativeBridgeMetalFrontend.mm',
                         'NativeTurnipSmoke.h', 'NativeAdrenoMetalConfig.h'):
                shutil.copyfile(metal / name, cache_source / name)
            report['private_shader_cache']['config_sha256'] = sha(metal / 'NativeAdrenoMetalConfig.h')
        shutil.copytree(bundle, output / bundle.name, symlinks=True)
        shutil.copyfile(built / 'trust.json', output / 'trust.json')
        trust = json.loads((built / 'trust.json').read_text())
        report.update(bundle_files=bundle_files(output / bundle.name), cdhash=trust['cdhash'],
                      turnip_cdhash=trust['turnip_cdhash'], executable_bytes=trust['executable_bytes'],
                      executable_file=read(['file', bundle / 'NativeAdrenoMetal']),
                      undeployed={name: sha(built / name) for name in UNDEPLOYED if (built / name).is_file()})
    (output / 'plugin-report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report
