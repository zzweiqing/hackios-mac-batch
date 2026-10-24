#!/usr/bin/env python3
"""Apply the narrow G0 fix to an exact upstream checkout before tree assembly."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tomllib

UPSTREAM = '245aca1a9ec5b730b1cad80fade295800d2981f1'
PATCH = 'patches/xnu/offline-component-load-probes.patch'
PATCH_SHA256 = '1f228c5c6d8387b13cd8e0964ddeb56c858a5dae16478f3ed2baae8a2e4da1e9'
INPUT_SHA256 = 'fce1ea205e571c3850e150404fc04f255f1192ba19c68e12497c19b8f87d8994'
PROFILES = ('nabu_bootstrap_defconfig', 'nabu_qemu_storage_defconfig', 'nabu_qemu_root_defconfig')
OWNER_POLICY = {'release': 'nabu-owner-os-21h16-v1', 'asset': 'os-policy.tar.gz',
                'sha256': '478b9adc9dd57d98a007eb1fa04fd07ff62c1bf2bdec6087fa3997ed11c01452'}
SYSTEMOS_POLICY = {'release': 'nabu-owner-systemos-21h16-v1', 'asset': 'systemos-policy.tar.gz',
                   'sha256': 'e56a28b5921f33ee8d5125ac700bd3564e2f1d73208bfa7bd6aa007ec7f130c3'}
# Original j171ap/21H16 security initializer, before the declared prelink slide.
AMFI_INIT = 'com.apple.driver.AppleMobileFileIntegrity=0xfffffff005b70ae0'
ROOT_COMPONENTS = ['com.apple.filesystems.apfs',
                   'com.apple.AppleFSCompression.AppleFSCompressionTypeZlib',
                   'com.apple.driver.AppleMobileFileIntegrity']

# Native console only: no BootProgress archives or system policy changes.
NABU_TEXT_PATCH = (
    '--- a/pexpert/arm/pe_init.c\n'
    '+++ b/pexpert/arm/pe_init.c\n'
    '@@ -525,7 +525,9 @@\n'
    ' \t */\n'
    ' \tcheck_for_panic_log();\n'
    ' \n'
    '-\tif (PE_state.video.v_display) {\n'
    '+\tint nabu_source_text = 0;\n'
    '+\tPE_parse_boot_argn("nabu-source-text", &nabu_source_text, sizeof(nabu_source_text));\n'
    '+\tif (PE_state.video.v_display && !nabu_source_text) {\n'
    ' \t\tPE_initialize_console(&PE_state.video, kPEGraphicsMode);\n'
    ' \t} else {\n'
    ' \t\tPE_initialize_console(&PE_state.video, kPETextMode);\n'
    '--- a/iokit/bsddev/IOKitBSDInit.cpp\n'
    '+++ b/iokit/bsddev/IOKitBSDInit.cpp\n'
    '@@ -43,6 +43,11 @@\n'
    ' #include <vm/pmap.h>\n'
    ' #include <vm/vm_map.h>\n'
    ' #include <pexpert/pexpert.h>\n'
    '+\n'
    '+extern "C" {\n'
    '+extern volatile uint32_t armdt_platform_configured, armcpu_gic_ready;\n'
    '+extern volatile uint64_t armcpu_timer_interrupts;\n'
    '+}\n'
    ' #include <kern/clock.h>\n'
    ' #if CONFIG_KDP_INTERACTIVE_DEBUGGING\n'
    ' #include <kern/debug.h>\n'
    '@@ -690,6 +695,15 @@\n'
    ' \tstatic int          mountAttempts = 0;\n'
    ' \n'
    ' \tint xchar, dchar;\n'
    '+\tint nabu_source_text = 0;\n'
    '+\tPE_parse_boot_argn("nabu-source-text", &nabu_source_text, sizeof(nabu_source_text));\n'
    '+\tif (nabu_source_text) {\n'
    '+\t\tPE_initialize_console(NULL, kPETextScreen);\n'
    '+\t\tPE_initialize_console(NULL, kPEEnableScreen);\n'
    '+\t\tIOLog("NABU SOURCE V2 ROOT_SEARCH platform=%u gic=%u timer=%llu\\n",\n'
    '+\t\t    armdt_platform_configured, armcpu_gic_ready,\n'
    '+\t\t    (unsigned long long)armcpu_timer_interrupts);\n'
    '+\t}\n'
    ' \n'
    ' \t// stall here for anyone matching on the IOBSD resource to finish (filesystems)\n'
    ' \tmatching = IOService::serviceMatching(gIOResourcesKey);\n'
    '@@ -897,6 +911,10 @@\n'
    ' #if !XNU_TARGET_OS_OSX || !defined(__arm64__)\n'
    ' \t\t\tPE_display_icon( 0, "noroot");\n'
    ' \t\t\tIOLog( "Still waiting for root device\\n" );\n'
    '+\t\t\tif (nabu_source_text) {\n'
    '+\t\t\t\tIOLog("NABU SOURCE V2 ROOT_WAIT timer=%llu\\n",\n'
    '+\t\t\t\t    (unsigned long long)armcpu_timer_interrupts);\n'
    '+\t\t\t}\n'
    ' #endif\n'
    ' \n'
    ' \t\t\tif (!debugInfoPrintedOnce) {\n'
)


def select_storage_profile(device, upstream, owner_root=False):
    path = device / 'board.toml'
    text = path.read_text(encoding='utf-8')
    profile = 'nabu_qemu_root_defconfig' if owner_root else 'nabu_qemu_storage_defconfig'
    text = text.replace('defconfig = "nabu_bootstrap_defconfig"', f'defconfig = "{profile}"')
    builders = ('  "build-nabu-owner-root.py",\n' if owner_root else '') + '  "build-nabu-virtio.py",'
    text = text.replace('  "build-libpthread-kernel.py",',
                        '  "build-libpthread-kernel.py",\n' + builders)
    if owner_root:
        text = text.replace('roots = ["com.apple.filesystems.apfs"]',
                            f'roots = {json.dumps(ROOT_COMPONENTS)}\n'
                            f'early_security_init = "{AMFI_INIT}"')
    path.write_text(text, encoding='utf-8')
    # VirtIO imports IOStorageFamily and SHA256, not NativeAES. Keep the real
    # original-crypto prerequisite rather than the old sheng feature coupling.
    build = upstream / 'scripts/build-xnu-4k-baseline.sh'
    text = build.read_text(encoding='utf-8')
    text = text.replace(
        'if [ "${XNU_NATIVE_AES:-0}" != 1 ]; then\n'
        "    echo 'NativeVirtioBlock currently requires the qualified NativeAES/original-storage prelink baseline' >&2",
        'if [ "$CRYPTO_BOOTSTRAP_MODE" != prelinked ] || [ "${XNU_SOURCE_CORECRYPTO14:-0}" != 1 ]; then\n'
        "    echo 'NativeVirtioBlock requires the original crypto/storage prelink closure' >&2")
    if owner_root:
        # Root binding consumes the real verifier/transport, not the optional
        # crypto diagnostic and its four sample blocks.
        text = text.replace('if [ "$OWNER_ROOT_AUDIT" = 1 ] && [ "$OWNER_ROOT_PROBE" != 1 ]; then',
                            'if [ "$OWNER_ROOT_AUDIT" = 1 ] && [ "${XNU_NATIVE_VIRTIO_BLOCK:-0}" != 1 ]; then')
        text = text.replace('if [ "$OWNER_ROOT_PROBE" = 1 ] && {',
                            'if { [ "$OWNER_ROOT_PROBE" = 1 ] || [ "${XNU_OWNER_ROOT_AUDIT:-0}" = 1 ]; } && {')
        text = text.replace('  if [ "$OWNER_ROOT_PROBE" = 1 ]; then\n    VERIFIED_ROOT_ARCHIVE=',
                            '  if [ "$OWNER_ROOT_PROBE" = 1 ] || [ "$OWNER_ROOT_AUDIT" = 1 ]; then\n    VERIFIED_ROOT_ARCHIVE=')
        text = text.replace('  "$OWNER_ROOT_PROBE" "${XNU_VERIFIED_ROOT_ARCHIVE:',
                            '  "$((OWNER_ROOT_PROBE | OWNER_ROOT_AUDIT))" "${XNU_VERIFIED_ROOT_ARCHIVE:')
    build.write_text(text, encoding='utf-8')
    if owner_root:
        # The native PMGR subclass binds to this exact original kext. Decode the
        # same private input before archive compilation; prelink reuses it.
        kernel = upstream / 'scripts/unixnu/kernel.py'
        text = kernel.read_text(encoding='utf-8')
        text = text.replace('    build_archives(ctx, env)\n',
                            "    env['UNIXNU_KERNELCACHE'] = str(ipsw.kernelcache(ctx, ipsw.Ipsw(ctx)))\n"
                            '    build_archives(ctx, env)\n', 1)
        kernel.write_text(text, encoding='utf-8')


def fixed_patch(data):
    if hashlib.sha256(data).hexdigest() != PATCH_SHA256:
        raise ValueError('Unexpected upstream display patch; refuse fuzzy rewriting')
    text = data.decode('utf-8')
    start = '+\tint legacy_register = 0;\n'
    end = '+\tint client_probe = 0;\n'
    hunk = '@@ -478,5 +478,88 @@'
    if any(text.count(marker) != 1 for marker in (start, end, hunk)):
        raise ValueError('Expected unique display-hook block and hunk')
    text = text.replace(hunk, '@@ -478,5 +478,90 @@', 1)
    text = text.replace(start, '+#if defined(XNU_NATIVE_LEGACY_DISPLAY) && XNU_NATIVE_LEGACY_DISPLAY\n' + start, 1)
    return text.replace(end, '+#endif\n' + end, 1).encode('utf-8')


def validate_profile(device):
    board = tomllib.loads((device / 'board.toml').read_text(encoding='utf-8'))
    name = board['kernel']['defconfig']
    if name not in PROFILES or board['ipsw']['build'] != '21H16':
        raise ValueError('Only the explicit nabu/21H16 profiles are supported')
    owner_root = name == 'nabu_qemu_root_defconfig'
    roots = ROOT_COMPONENTS if owner_root else ['com.apple.filesystems.apfs']
    if board['kernel']['prelink']['roots'] != roots:
        raise ValueError('Profile requires its declared original-component closure')
    if board['kernel']['prelink'].get('early_security_init') != (AMFI_INIT if owner_root else None):
        raise ValueError('Profile requires its declared original security initializer')
    config = (device / 'configs' / name).read_text(encoding='utf-8')
    disabled_features = ['BOOT_PROGRESS', 'NATIVE_UFS', 'NATIVE_AES',
                         'SOURCE_MOCKFS', 'NATIVE_LEGACY_DISPLAY', 'SHENG_PMGR']
    if name == 'nabu_bootstrap_defconfig':
        disabled_features.append('NATIVE_VIRTIO_BLOCK')
    for disabled in disabled_features:
        if f'CONFIG_XNU_{disabled}=n' not in config.splitlines():
            raise ValueError(f'G0 must leave {disabled} disabled')
    expected = ['build-corecrypto-14.py', 'build-corecrypto-14.py --namespace',
                'build-nabu-platform.py ArmDTPlatform', 'build-nabu-platform.py ArmCpu',
                'build-libpthread-kernel.py']
    if name == 'nabu_qemu_root_defconfig':
        expected.append('build-nabu-owner-root.py')
    if name != 'nabu_bootstrap_defconfig':
        expected.append('build-nabu-virtio.py')
    if board['kernel']['archives'] != expected:
        raise ValueError('G0 archive producer list changed; re-audit the profile')
    return board


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--upstream', type=Path, required=True)
    p.add_argument('--device', type=Path, required=True)
    p.add_argument('--report', type=Path, required=True)
    p.add_argument('--profile', choices=PROFILES, default=PROFILES[0])
    args = p.parse_args()
    if args.profile != 'nabu_bootstrap_defconfig':
        select_storage_profile(args.device, args.upstream, args.profile == 'nabu_qemu_root_defconfig')
    board = validate_profile(args.device)
    head = subprocess.check_output(['git', '-C', str(args.upstream), 'rev-parse', 'HEAD'], text=True).strip()
    if head != UPSTREAM:
        raise SystemExit('Unexpected UniXNU source revision')
    path = args.upstream / PATCH
    result = fixed_patch(path.read_bytes()) + NABU_TEXT_PATCH.encode()
    path.write_bytes(result)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({
        'upstream_commit': head, 'profile': board['kernel']['defconfig'],
        'patch': PATCH, 'before_sha256': PATCH_SHA256,
        'after_sha256': hashlib.sha256(result).hexdigest(),
        'input_release': 'unixnu-source-inputs', 'input_asset': 'ipsw-21h16-small.zip',
        'input_sha256': INPUT_SHA256, 'runtime_qualified': False,
        'owner_policy': OWNER_POLICY if args.profile == 'nabu_qemu_root_defconfig' else None,
        'systemos_policy': SYSTEMOS_POLICY if args.profile == 'nabu_qemu_root_defconfig' else None,
    }, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
