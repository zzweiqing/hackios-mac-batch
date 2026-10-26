#!/usr/bin/env python3
"""Build only G0 platform archives using the current XNU compilation contract."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess


def compile_command(record, source, output):
    arguments = record['arguments']
    command = []
    index = 0
    while index < len(arguments):
        value = arguments[index]
        if value in ('-o', '-MF', '-MJ'):
            if value == '-o':
                command += ['-o', str(output)]
            index += 2
            continue
        if value not in ('-MD', '-MP'):
            command.append(str(source) if value == record['file'] else value)
        index += 1
    if str(source) not in command or str(output) not in command:
        raise ValueError('XNU recipe lacks the expected source/output arguments')
    return command


def check_object(data):
    if struct.unpack_from('<4I', data) != (0xfeedfacf, 0x100000c, 0, 1):
        raise ValueError('Expected ordinary ARM64 relocatable Mach-O')
    at, deployment = 32, None
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        cmd, size = struct.unpack_from('<II', data, at)
        if size < 8 or at + size > len(data):
            raise ValueError('Invalid Mach-O load command')
        if cmd == 0x32:
            deployment = struct.unpack_from('<II', data, at + 8)
        at += size
    if deployment != (2, 0x110000):
        raise ValueError(f'Expected iOS 17 deployment, got {deployment}')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('component', choices=['ArmDTPlatform', 'ArmCpu'])
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    recipe = root / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json'
    recipe_bytes = recipe.read_bytes()
    record = json.loads(recipe_bytes.decode('utf-8').strip().rstrip(','))
    source = root / 'drivers' / args.component / (args.component + '.cpp')
    out = root / 'build' / {'ArmDTPlatform': 'armdt-platform', 'ArmCpu': 'armcpu'}[args.component]
    out.mkdir(parents=True, exist_ok=True)
    original_armio = args.component == 'ArmDTPlatform' and os.environ.get('XNU_OWNER_ROOT_TRUST') == '1'
    if original_armio:
        from armdt_original_provider import patch_source
        patched = out / 'ArmDTPlatform.cpp'
        patched.write_text(patch_source(source.read_text(encoding='utf-8')), encoding='utf-8')
        source = patched
    obj = out / (args.component + '.o')
    command = compile_command(record, source, obj)
    command += ['-I', str(root / '.cache/xnu-work/osfmk')]
    (out / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n', encoding='utf-8')
    result = subprocess.run(command, cwd=record['directory'], capture_output=True)
    (out / 'compile.log').write_bytes(result.stdout + result.stderr)
    if recipe.read_bytes() != recipe_bytes:
        raise SystemExit('Platform build modified the original XNU compile record')
    if result.returncode:
        raise SystemExit(result.stderr.decode('utf-8', errors='replace')[-4000:])
    check_object(obj.read_bytes())
    objects = [obj]
    stubs = out / 'PmgrPublishStubs.cpp'
    stubs.write_text(
        'class IOService;\nclass IORegistryEntry;\n'
        'extern "C" {\n'
        '__attribute__((weak)) bool qemu_boot_pmgr_publish (IOService *, IORegistryEntry *) { return false; }\n'
        '__attribute__((weak)) bool nabu_boot_pmgr_publish (IOService *, IORegistryEntry *) { return false; }\n'
        '}\n', encoding='utf-8')
    stubs_obj = out / 'PmgrPublishStubs.o'
    stubs_command = compile_command(record, stubs, stubs_obj)
    stubs_command += ['-I', str(root / '.cache/xnu-work/osfmk')]
    result = subprocess.run(stubs_command, cwd=record['directory'], capture_output=True)
    (out / 'stubs-compile.log').write_bytes(result.stdout + result.stderr)
    if result.returncode:
        raise SystemExit(result.stderr.decode('utf-8', errors='replace')[-4000:])
    check_object(stubs_obj.read_bytes())
    objects.append(stubs_obj)
    boot_pmgr = None
    if original_armio:
        from qemu_pmgr_build import build
        if os.environ.get('NABU_BOOT_PMGR') == '1':
            boot_pmgr = 'NabuBootPMGR'
            objects += build(root, record, out / 'nabu-pmgr', compile_command,
                             Path(os.environ['UNIXNU_KERNELCACHE']),
                             source_name='NabuBootPMGR.cpp', prefix='NabuBootPMGR',
                             aon_storage='volatile nabu boot-session AON latch (not power hardware)')
        else:
            boot_pmgr = 'QemuBootPMGR'
            objects += build(root, record, out / 'qemu-pmgr', compile_command,
                             Path(os.environ['UNIXNU_KERNELCACHE']))
    archive = out / ('lib' + args.component + '.a')
    if archive.exists():
        raise SystemExit('Refuse to reuse an existing platform archive; use a fresh build')
    subprocess.run(['xcrun', 'ar', 'rcs', str(archive), *map(str, objects)], check=True)
    (out / 'build-report.json').write_text(json.dumps({
        'component': args.component, 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
        'recipe_sha256': hashlib.sha256(recipe_bytes).hexdigest(),
        'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
        'original_armio_factory_enabled': original_armio,
        'boot_pmgr': boot_pmgr,
        'architecture': 'arm64', 'deployment': 'iOS 17.0', 'runtime_qualified': False,
    }, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
