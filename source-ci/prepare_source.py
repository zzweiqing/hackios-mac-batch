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
    if name != 'nabu_bootstrap_defconfig' or board['ipsw']['build'] != '21H16':
        raise ValueError('Only the explicit G0/21H16 profile is supported')
    if board['kernel']['prelink']['roots'] != ['com.apple.filesystems.apfs']:
        raise ValueError('G0 requires the declared APFS/original-crypto closure')
    config = (device / 'configs' / name).read_text(encoding='utf-8')
    for disabled in ('BOOT_PROGRESS', 'NATIVE_UFS', 'NATIVE_AES', 'NATIVE_VIRTIO_BLOCK',
                     'SOURCE_MOCKFS', 'NATIVE_LEGACY_DISPLAY', 'SHENG_PMGR'):
        if f'CONFIG_XNU_{disabled}=n' not in config.splitlines():
            raise ValueError(f'G0 must leave {disabled} disabled')
    expected = ['build-corecrypto-14.py', 'build-corecrypto-14.py --namespace',
                'build-nabu-platform.py ArmDTPlatform', 'build-nabu-platform.py ArmCpu',
                'build-libpthread-kernel.py']
    if board['kernel']['archives'] != expected:
        raise ValueError('G0 archive producer list changed; re-audit the profile')
    return board


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--upstream', type=Path, required=True)
    p.add_argument('--device', type=Path, required=True)
    p.add_argument('--report', type=Path, required=True)
    args = p.parse_args()
    board = validate_profile(args.device)
    head = subprocess.check_output(['git', '-C', str(args.upstream), 'rev-parse', 'HEAD'], text=True).strip()
    if head != UPSTREAM:
        raise SystemExit('Unexpected UniXNU source revision')
    path = args.upstream / PATCH
    result = fixed_patch(path.read_bytes())
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
