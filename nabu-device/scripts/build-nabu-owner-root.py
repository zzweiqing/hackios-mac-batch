#!/usr/bin/env python3
"""Build the VerifiedRoot XNU archive from a prepared owner policy bundle."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import uuid


HEADER = struct.Struct('<8s4I2Q16s32s32s32sQ')
HEADER_BYTES = 160
BLOCK_BYTES = 4096
KEY_BYTES = 395


def read_policy(policy_dir):
    manifest_path = policy_dir / 'manifest.bin'
    key_path = policy_dir / 'trusted-key.bin'
    manifest = manifest_path.read_bytes()
    key = key_path.read_bytes()
    if len(manifest) < HEADER_BYTES + 384:
        raise ValueError('owner manifest is shorter than its header and RSA signature')
    if len(key) != KEY_BYTES:
        raise ValueError(f'owner trusted-key.bin must be exactly {KEY_BYTES} bytes')
    (magic, version, header_size, block_bytes, reserved, image_bytes, block_count,
     volume_uuid, image_digest, hash_digest, key_digest, generation) = HEADER.unpack_from(manifest)
    if (magic != b'VROOT01\0' or version != 1 or header_size != HEADER_BYTES or
            block_bytes != BLOCK_BYTES or reserved != 0):
        raise ValueError('owner manifest header does not match the retained VerifiedRoot v1 format')
    expected_blocks = image_bytes // BLOCK_BYTES + (image_bytes % BLOCK_BYTES != 0)
    expected_length = HEADER_BYTES + 384 + block_count * 32
    if (image_bytes == 0 or block_count != expected_blocks or
            len(manifest) != expected_length or generation == 0):
        raise ValueError('owner manifest has inconsistent image length, block count, or generation')
    if key[:8] != b'VROOTKEY' or key[392:] != b'\x01\x00\x01':
        raise ValueError('trusted-key.bin does not match the retained RSA3072 owner-key anchor format')
    if not key[8] & 0x80 or not key[391] & 1:
        raise ValueError('trusted-key.bin does not contain a full-size odd RSA modulus')
    if hashlib.sha256(key).digest() != key_digest:
        raise ValueError('owner manifest key identifier does not match trusted-key.bin')
    return {
        'manifest': manifest_path,
        'trusted_key': key_path,
        'manifest_bytes': len(manifest),
        'trusted_key_bytes': len(key),
        'image_bytes': image_bytes,
        'block_count': block_count,
        'volume_uuid': str(uuid.UUID(bytes=volume_uuid)).upper(),
        'generation': generation,
    }


def main():
    policy_value = os.environ.get('UNIXNU_OWNER_POLICY')
    if not policy_value:
        raise SystemExit('UNIXNU_OWNER_POLICY must name a prepared policy directory')

    root = Path(__file__).resolve().parents[1]
    policy_dir = Path(policy_value).resolve(strict=True)
    if not policy_dir.is_dir():
        raise SystemExit('UNIXNU_OWNER_POLICY must name a directory')
    policy = read_policy(policy_dir)

    recipe_path = root / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/bsd/DEVELOPMENT/bsd_init.o.json'
    recipe_bytes = recipe_path.read_bytes()
    record = json.loads(recipe_bytes.decode('utf-8').strip().rstrip(','))
    script_path = Path(__file__).resolve()
    platform_path = script_path.with_name('build-nabu-platform.py')
    spec = importlib.util.spec_from_file_location('nabu_platform_builder', platform_path)
    platform = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(platform)

    verified_root = root / 'kits/VerifiedRoot'
    include = verified_root / 'include'
    sources = [verified_root / 'src/verified_root.c',
               verified_root / 'adapters/xnu_crypto.c']
    out = root / 'build/verified-root-xnu'
    out.mkdir(parents=True, exist_ok=True)
    archive = out / 'libVerifiedRootProbe.a'
    if archive.exists():
        raise SystemExit('Refuse to reuse an existing VerifiedRoot archive; use a fresh build root')

    commands = []
    objects = []
    for source in sources:
        obj = out / (source.stem + '.o')
        command = platform.compile_command(record, source, obj)
        command += ['-I', str(include), '-I', str(root / '.cache/xnu-work/osfmk')]
        subprocess.run(command, cwd=record['directory'], check=True)
        commands.append(command)
        objects.append(obj)

    assembly = out / 'inputs.S'
    assembly.write_text(
        '.section __DATA_CONST,__const\n'
        '.balign 8\n'
        '.globl _verified_root_manifest\n'
        '_verified_root_manifest:\n'
        f'.incbin "{policy["manifest"].as_posix()}"\n'
        '.balign 8\n'
        '.globl _verified_root_manifest_bytes\n'
        '_verified_root_manifest_bytes:\n'
        f'.quad {policy["manifest_bytes"]}\n'
        '.balign 8\n'
        '.globl _verified_root_key\n'
        '_verified_root_key:\n'
        f'.incbin "{policy["trusted_key"].as_posix()}"\n',
        encoding='utf-8')
    inputs_obj = out / 'inputs.o'
    assembly_command = ['xcrun', 'clang', '-target', 'arm64-apple-ios17.0', '-c',
                        str(assembly), '-o', str(inputs_obj)]
    subprocess.run(assembly_command, check=True)
    commands.append(assembly_command)
    objects.append(inputs_obj)

    archive_command = ['xcrun', 'ar', 'rcs', str(archive), *(str(obj) for obj in objects)]
    subprocess.run(archive_command, check=True)
    commands.append(archive_command)
    (out / 'compile-command.json').write_text(
        json.dumps(commands, indent=2) + '\n', encoding='utf-8')
    report = {
        'archive': archive.name,
        'sources': ['VerifiedRoot/src/verified_root.c', 'VerifiedRoot/adapters/xnu_crypto.c',
                    'inputs.S'],
        'policy': {
            'format': 'VROOT01 v1',
            'image_bytes': policy['image_bytes'],
            'block_count': policy['block_count'],
            'volume_uuid': policy['volume_uuid'],
            'generation': policy['generation'],
        },
        'architecture': 'arm64',
        'deployment': 'iOS 17.0',
        'runtime_qualified': False,
        'boot_root_authenticated': False,
    }
    (out / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n',
                                           encoding='utf-8')


if __name__ == '__main__':
    main()
