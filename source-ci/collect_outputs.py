#!/usr/bin/env python3
"""Package source-build evidence privately; publish only bounded identity metadata."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tarfile

from prepare_source import INPUT_SHA256, UPSTREAM


def sha256(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(1 << 20), b''):
            value.update(data)
    return value.hexdigest()


def macho_summary(path):
    data = path.read_bytes()
    if len(data) < 32 or struct.unpack_from('<4I', data) != (0xfeedfacf, 0x100000c, 0, 2):
        raise ValueError('Candidate must be ordinary ARM64 MH_EXECUTE')
    count, extent = struct.unpack_from('<II', data, 16)
    at, undefined, symbols = 32, [], None
    for _ in range(count):
        cmd, size = struct.unpack_from('<II', data, at)
        if size < 8 or at + size > 32 + extent or at + size > len(data):
            raise ValueError('Malformed Mach-O command')
        if cmd == 2:
            symbols = struct.unpack_from('<4I', data, at + 8)
        at += size
    if symbols is None or at != 32 + extent:
        raise ValueError('Candidate must retain the symbol table')
    offset, number, strings, string_bytes = symbols
    if offset + number * 16 > len(data) or strings + string_bytes > len(data):
        raise ValueError('Malformed symbol/string table')
    for index in range(number):
        name, kind, _, _, _ = struct.unpack_from('<IBBHQ', data, offset + index * 16)
        if kind & 0xe0 or kind & 0xe:
            continue
        if name >= string_bytes:
            raise ValueError('Malformed symbol name')
        end = data.index(b'\0', strings + name, strings + string_bytes)
        undefined.append(data[strings + name:end].decode('utf-8'))
    return {'symbol_count': number, 'undefined_names': undefined}


def selected_files(upstream):
    work = upstream / 'out/nabu'
    if work.is_symlink():
        raise ValueError('Refuse a linked build output root')
    files = []
    selected_xnu_names = {'link.filelist', 'all-alias.exp', 'startup.o.json',
                          'prng_random.o.json', 'IOPlatformExpert.cpo.json'}
    report_names = {'report.json', 'bindings.json', 'compile-command.json', 'compile-command-namespaced.json',
                    'build-report.json', 'build-report-namespaced.json',
                    'link-survey.json', 'link-survey-namespaced.json'}

    def add(path, relative):
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents
                                    if parent != work and work in parent.parents):
            raise ValueError(f'Refuse a linked output: {relative}')
        if path.is_file():
            if any(part in ('.git', '.env') for part in relative.parts):
                raise ValueError(f'Refuse unexpected output: {relative}')
            files.append((path, 'outputs/' + relative.as_posix()))

    for relative in ('kernel', 'logs'):
        directory = work / relative
        if directory.is_dir():
            for path in sorted(directory.rglob('*')):
                add(path, path.relative_to(work))

    build = work / 'tree/build'
    xnu_obj = build / 'xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
    if xnu_obj.is_dir():
        for path in sorted(xnu_obj.rglob('*')):
            if path.is_file() and path.name in selected_xnu_names:
                add(path, path.relative_to(work))
    for relative in ('corecrypto-2023', 'armdt-platform', 'armcpu', 'libpthread-kernel',
                     'native-virtio-block', 'verified-root-xnu'):
        directory = build / relative
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob('*')):
            if path.is_dir():
                continue
            if path.suffix == '.a' or path.name in report_names or path.name in ('namespace.h', 'inputs.S', 'NativeVirtioBlock.cpp'):
                add(path, path.relative_to(work))

    add(work / '.config', Path('.config'))
    return files


def selected_sources(device):
    root = Path(__file__).resolve().parents[1]
    source_dir = root / ('source-ci' if (root / 'source-ci').is_dir() else 'scripts')
    workflow_dir = root / ('.github/workflows' if (root / '.github/workflows').is_dir()
                           else 'workflows')
    sources = [
        (device / 'board.toml', 'device/board.toml'),
        (device / 'configs/nabu_bootstrap_defconfig', 'device/configs/nabu_bootstrap_defconfig'),
        (device / 'configs/nabu_qemu_storage_defconfig', 'device/configs/nabu_qemu_storage_defconfig'),
        (device / 'configs/nabu_qemu_root_defconfig', 'device/configs/nabu_qemu_root_defconfig'),
        (device / 'LICENSE', 'device/LICENSE'),
        (device / 'scripts/build-nabu-platform.py', 'device/scripts/build-nabu-platform.py'),
        (device / 'scripts/build-nabu-virtio.py', 'device/scripts/build-nabu-virtio.py'),
        (device / 'scripts/build-nabu-owner-root.py', 'device/scripts/build-nabu-owner-root.py'),
        (source_dir / 'prepare_source.py', 'source-ci/prepare_source.py'),
        (source_dir / 'collect_outputs.py', 'source-ci/collect_outputs.py'),
        (workflow_dir / 'unixnu-source.yml', '.github/workflows/unixnu-source.yml'),
    ]
    root = root.resolve()
    for path, _ in sources:
        if (path.is_symlink() or not path.is_file()
                or not path.resolve().is_relative_to(root)
                or any(parent.is_symlink() for parent in path.parents if parent != root)):
            raise ValueError(f'Refuse missing or linked source input: {path}')
    return sources


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--upstream', type=Path, required=True)
    p.add_argument('--device', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--run-id', type=int, required=True)
    p.add_argument('--attempt', type=int, required=True)
    p.add_argument('--head-sha', required=True)
    p.add_argument('--build-outcome', required=True)
    p.add_argument('--input-sha256', default='')
    p.add_argument('--prepare-report', type=Path, required=True)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    files = selected_files(args.upstream)
    prepared = json.loads(args.prepare_report.read_text()) if args.prepare_report.is_file() else {}
    identity = {'run_id': args.run_id, 'run_attempt': args.attempt, 'head_sha': args.head_sha,
                'upstream_commit': UPSTREAM, 'profile': prepared.get('profile', 'nabu_bootstrap_defconfig'),
                'inputs_release': 'unixnu-source-inputs', 'inputs_asset': 'ipsw-21h16-small.zip',
                'inputs_sha256': args.input_sha256 or None,
                'input_verified': args.input_sha256 == INPUT_SHA256,
                'build_step_outcome': args.build_outcome, 'runtime_qualified': False,
                'owner_policy': prepared.get('owner_policy'),
                'hardware_tested': False, 'apple_launchd_executed': False}
    summary = dict(identity, candidate_present=False, candidate_validated=False)
    manifest = dict(identity)
    files.extend(selected_sources(args.device))
    if args.prepare_report.is_file():
        files.append((args.prepare_report, 'prepare-report.json'))
    if (args.upstream / '.git').exists():
        actual_head = subprocess.check_output(['git', '-C', str(args.upstream), 'rev-parse', 'HEAD'], text=True).strip()
        manifest['actual_upstream_commit'] = actual_head
        manifest['submodules'] = subprocess.check_output(['git', '-C', str(args.upstream), 'submodule', 'status', '--recursive'], text=True)
        manifest['upstream_diff'] = subprocess.check_output(['git', '-C', str(args.upstream), 'diff', '--no-ext-diff'], text=True)
    candidate = args.upstream / 'out/nabu/kernel/kernel.macho'
    report = candidate.with_suffix('.json')
    if candidate.is_file():
        summary.update(candidate_present=True, candidate_sha256=sha256(candidate), candidate_bytes=candidate.stat().st_size)
        try:
            parsed = json.loads(report.read_text(encoding='utf-8'))
            macho = macho_summary(candidate)
            valid = (parsed['candidate_sha256'] == summary['candidate_sha256']
                     and parsed['original_sha256'] == 'f7d1952c7a21633d212eccf288e77444fff0cc86976db5de292f6819c2ffa1b2'
                     and parsed['slide'] == -0x1360000
                     and {'com.apple.filesystems.apfs', 'com.apple.kec.corecrypto'} <= set(parsed['components'])
                     and not macho['undefined_names'] and macho['symbol_count'] > 0
                     and manifest.get('actual_upstream_commit') == UPSTREAM
                     and identity['input_verified'] and args.prepare_report.is_file())
            summary['candidate_validated'] = valid
            summary['undefined_symbol_count'] = len(macho['undefined_names'])
            manifest['macho'] = macho
        except (KeyError, ValueError, OSError, struct.error) as error:
            manifest['candidate_validation_error'] = str(error)
    manifest['files'] = {name: {'bytes': path.stat().st_size, 'sha256': sha256(path)} for path, name in files}
    manifest['summary'] = summary
    manifest_path = args.output / 'source-manifest.json'
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    tag = f'source-{args.run_id}-attempt-{args.attempt}'
    with tarfile.open(args.output / (tag + '.tar.gz'), 'w:gz') as archive:
        for path, name in files:
            archive.add(path, arcname=name, recursive=False)
        archive.add(manifest_path, arcname='source-manifest.json')
    summary['private_release'] = tag
    summary['private_asset'] = tag + '.tar.gz'
    summary['private_asset_sha256'] = sha256(args.output / (tag + '.tar.gz'))
    (args.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    if args.build_outcome == 'success' and not summary['candidate_validated']:
        raise SystemExit('Build succeeded without a valid bound candidate; private evidence was preserved')


if __name__ == '__main__':
    main()
