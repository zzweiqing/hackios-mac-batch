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
PROFILES = ('nabu_bootstrap_defconfig', 'nabu_qemu_storage_defconfig')

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
    '@@ -43,6 +43,12 @@\n'
    ' #include <vm/pmap.h>\n'
    ' #include <vm/vm_map.h>\n'
    ' #include <pexpert/pexpert.h>\n'
    '+\n'
    '+extern "C" {\n'
    '+extern volatile uint32_t armdt_platform_configured, armcpu_gic_ready;\n'
    '+extern volatile uint64_t armcpu_timer_interrupts;\n'
    '+void nabu_armcpu_report(void);\n'
    '+}\n'
    ' #include <kern/clock.h>\n'
    ' #if CONFIG_KDP_INTERACTIVE_DEBUGGING\n'
    ' #include <kern/debug.h>\n'
    '@@ -690,6 +696,16 @@\n'
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
    '+\t\tnabu_armcpu_report();\n'
    '+\t}\n'
    ' \n'
    ' \t// stall here for anyone matching on the IOBSD resource to finish (filesystems)\n'
    ' \tmatching = IOService::serviceMatching(gIOResourcesKey);\n'
    '@@ -897,6 +913,10 @@\n'
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


def select_storage_profile(device, upstream):
    path = device / 'board.toml'
    text = path.read_text(encoding='utf-8')
    text = text.replace('defconfig = "nabu_bootstrap_defconfig"',
                        'defconfig = "nabu_qemu_storage_defconfig"')
    text = text.replace('  "build-libpthread-kernel.py",',
                        '  "build-libpthread-kernel.py",\n  "build-nabu-virtio.py",')
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
    build.write_text(text, encoding='utf-8')


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
    if board['kernel']['prelink']['roots'] != ['com.apple.filesystems.apfs']:
        raise ValueError('G0 requires the declared APFS/original-crypto closure')
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
    if name == 'nabu_qemu_storage_defconfig':
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
    if args.profile == 'nabu_qemu_storage_defconfig':
        select_storage_profile(args.device, args.upstream)
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
    }, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
