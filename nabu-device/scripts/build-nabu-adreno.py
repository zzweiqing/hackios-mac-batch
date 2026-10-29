#!/usr/bin/env python3
"""Build the opt-in SM8150/A640 CP proof archive from preserved licensed sources."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

CPP = (
    'NativeAdrenoMemory', 'NativeAdrenoVm', 'NativeAdrenoCpu', 'NativeAdrenoKernelTime',
    'NativeAdrenoRing', 'NativeAdrenoCpInit', 'NativeAdrenoIrq', 'NativeAdrenoSmmuMemory',
    'NativeAdrenoSmmuContext', 'NativeAdrenoGmuMemory', 'NativeAdrenoGmuContext',
    'NativeAdrenoGpuContext', 'NativeAdrenoA6xxPower', 'NativeAdrenoA6xxGmu',
    'NativeAdrenoA6xxHwInit', 'NativeAdrenoA6xxSmmu', 'NativeAdrenoA6xxZap',
    'NativeAdrenoService', 'NativeAdrenoSha256', 'NativeAdrenoGpuProfile', 'NabuGpuResources',
)
SAFE_SUFFIXES = {'.cpp', '.c', '.h'}
SAFE_NAMES = {'LICENSE', 'COPYING', 'PROVENANCE'}
PROFILE = 'nabu_ufs_gpu_defconfig'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_inventory(device):
    gpu = device / 'gpu'
    paths = sorted(p for p in gpu.rglob('*') if p.is_file() and
                   (p.suffix in SAFE_SUFFIXES or p.name in SAFE_NAMES))
    paths.append(device / 'scripts/build-nabu-adreno.py')
    if any(p.is_symlink() for p in paths):
        raise ValueError('GPU source cannot be a symlink')
    return {p.relative_to(device).as_posix(): sha(p.read_bytes()) for p in paths}


def source_identity(sources):
    return sha(json.dumps(sources, sort_keys=True, separators=(',', ':')).encode())


def verify_pmap(data):
    text = data.decode('utf-8')
    match = re.search(r'\bpmap_sync_page_attributes_phys\s*\([^)]*\)\s*\{([^}]+)\}', text)
    if not match or not re.search(r'flush_dcache\s*\(\s*\(vm_offset_t\)\s*ptoa\(pp\)', match[1]):
        raise ValueError('GPU NC allocation requires the applied pmap >=4 GiB physical address fix')
    if re.search(r'pp\s*<<\s*PAGE_SHIFT', re.sub(r'/\*.*?\*/', '', match[1], flags=re.S)):
        raise ValueError('pmap physical page shift still truncates above 4 GiB')


def main():
    if sys.platform != 'darwin':
        raise SystemExit('Apple archive compilation runs in the macOS GitHub Actions workflow')
    for name in ('XNU_NATIVE_ADRENO', 'XNU_NATIVE_UFS', 'XNU_OWNER_ROOT_TRUST', 'NABU_CAPTURE_LOG'):
        if os.environ.get(name) != '1':
            raise SystemExit('A640 diagnostic requires ' + name + '=1')
    root = Path(__file__).resolve().parents[1]
    device = Path(os.environ['UNIXNU_DEVICE']).resolve()
    config = (root.parent / '.config').read_text().splitlines()
    if 'CONFIG_XNU_NATIVE_ADRENO=y' not in config or 'CONFIG_XNU_NATIVE_MOBILE_DISPLAY=n' not in config:
        raise SystemExit('Unexpected A640 profile dependencies')
    out = root / 'build/native-adreno'
    if out.exists():
        raise SystemExit('Refuse existing GPU output; use a fresh build tree')
    pmap = root / '.cache/xnu-work/osfmk/arm/pmap/pmap.c'
    pmap_bytes = pmap.read_bytes()
    verify_pmap(pmap_bytes)
    sources = source_inventory(device)
    identity = source_identity(sources)
    staged = out / 'source'
    staged.mkdir(parents=True)
    # Merge first: quoted includes must resolve to the overlay header, rather
    # than an upstream header living beside an upstream translation unit.
    for directory in ('upstream/Adreno6xx', 'upstream/ArmSmmu4K', 'upstream/AdrenoPM4', 'a640', 'nabu'):
        for path in sorted((device / 'gpu' / directory).iterdir()):
            if path.is_file() and path.suffix in SAFE_SUFFIXES:
                shutil.copyfile(path, staged / path.name)
    (staged / 'NabuGpuBuild.h').write_text('#define NABU_GPU_SOURCE_ID "' + identity + '"\n', encoding='utf-8')
    logging_headers = {}
    for name in ('NabuLogCore.h', 'NabuLogFormat.h'):
        path = device / 'ufs' / name
        logging_headers[path.relative_to(device).as_posix()] = sha(path.read_bytes())
        shutil.copyfile(path, staged / name)
    spec = importlib.util.spec_from_file_location('nabu_platform_build', Path(__file__).with_name('build-nabu-platform.py'))
    platform = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(platform)
    base = root / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
    recipes = {'cpp': base / 'iokit/DEVELOPMENT/IOPlatformExpert.cpo.json',
               'c': base / 'bsd/DEVELOPMENT/bsd_init.o.json'}
    raw = {key: path.read_bytes() for key, path in recipes.items()}
    records = {key: json.loads(data.decode().strip().rstrip(',')) for key, data in raw.items()}
    c_sources = sorted(p.name for p in (device / 'gpu/upstream/ArmSmmu4K').glob('*.c'))
    c_sources += ['AdrenoPM4.c', 'NabuGpuStart.c']
    units = [(name + '.cpp', 'cpp') for name in CPP] + [(name, 'c') for name in c_sources]
    objects, commands, reports = [], {}, {}
    for name, language in units:
        source = staged / name
        obj = out / (source.stem + '.o')
        record = records[language]
        command = platform.compile_command(record, source, obj)
        command += ['-I', str(staged), '-I', str(root / '.cache/xnu-work/osfmk')]
        result = subprocess.run(command, cwd=record['directory'], capture_output=True)
        (out / (source.stem + '.log')).write_bytes(result.stdout + result.stderr)
        commands[source.stem] = command
        (out / 'compile-command.json').write_text(json.dumps(commands, indent=2) + '\n')
        if any(recipes[key].read_bytes() != data for key, data in raw.items()):
            raise SystemExit('GPU build modified an original XNU compile record')
        if result.returncode:
            raise SystemExit(result.stderr.decode('utf-8', errors='replace')[-6000:])
        platform.check_object(obj.read_bytes())
        objects.append(obj)
        reports[source.stem] = {'source': 'source/' + name, 'source_sha256': sha(source.read_bytes()),
                                'object': obj.name, 'sha256': sha(obj.read_bytes())}
    archive = out / 'libNativeAdreno.a'
    subprocess.run(['xcrun', 'ar', 'rcs', str(archive), *map(str, objects)], check=True)
    report = {'profile': PROFILE, 'mode': 'a640_diagnostic', 'firmware_mode': 'adt',
              'source_identity': identity, 'sources': sources, 'logging_headers': logging_headers,
              'objects': reports, 'archive_sha256': sha(archive.read_bytes()),
              'metal_accelerator': False, 'runtime_qualified': False, 'hardware_tested': False,
              'requires_pmap_64bit': True, 'pmap_sync_64bit_verified': True,
              'pmap_source_sha256': sha(pmap_bytes), 'startup': 'EARLY_BOOT thread; wait IOBSD',
              'trigger': 'nabu-gpu=1', 'irq_mode': 'synchronous worker polling',
              'table_memory': 'Normal NC; non-cacheable SMMU walks',
              'recipe_sha256': {key: sha(data) for key, data in raw.items()}}
    (out / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ('mode', 'source_identity', 'archive_sha256')}))


if __name__ == '__main__':
    main()
