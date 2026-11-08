"""Prepare and qualify FileProtectionNone on the verified OwnerData mount."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct


TARGETS = {'kern_exec': 'bsd/kern/kern_exec.c', 'kpi_vfs': 'bsd/vfs/kpi_vfs.c'}
OBJECT_ROOT = 'outputs/tree/build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/bsd/DEVELOPMENT/'


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(content):
    return hashlib.sha256(content).hexdigest()


def generator(path=None):
    if path is None:
        path = Path(__file__).with_name('nabu_data_none_source.py')
        if not path.is_file():
            path = Path(__file__).resolve().parents[1] / 'nabu-device/scripts/nabu_data_none_source.py'
    spec = importlib.util.spec_from_file_location('nabu_data_none_bound_source', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def wire_build(text):
    require('nabu_data_none_ci.py' not in text, 'OwnerData None build already wired')
    anchor = 'python3 scripts/prepare-xnu-source.py\n'
    require(text.count(anchor) == 1, 'Missing unique XNU preparation call')
    text = text.replace(anchor, anchor +
        'python3 scripts/nabu_data_none_ci.py --root "$ROOT"\n', 1)
    anchor = 'for LATE_PATCH in '
    require(text.count(anchor) == 1, 'Missing unique late-patch reversal')
    text = text.replace(anchor,
        'python3 scripts/nabu_data_none_ci.py --root "$ROOT" --restore\n' + anchor, 1)
    anchor = 'EXTRA_MAKE_ARGS+=("kern_exec.o_CFLAGS_ADD='
    require(text.count(anchor) == 1, 'Missing OwnerData compilation flags')
    return text.replace(anchor,
        'EXTRA_MAKE_ARGS+=("kpi_vfs.o_CFLAGS_ADD=-DXNU_OWNER_DATA_MOUNT=$OWNER_DATA_MOUNT")\n' + anchor, 1)


def prepare(upstream, device):
    policy = generator(Path(device) / 'scripts/nabu_data_none_source.py')
    build = Path(upstream) / 'scripts/build-xnu-4k-baseline.sh'
    build.write_text(wire_build(build.read_text(encoding='utf-8')), encoding='utf-8')
    shutil.copyfile(Path(__file__), Path(upstream) / 'scripts/nabu_data_none_ci.py')
    shutil.copyfile(Path(policy.__file__), Path(upstream) / 'scripts/nabu_data_none_source.py')
    return dict(contract=policy.CONTRACT, generator_sha256=sha(Path(policy.__file__).read_bytes()),
                embedded_source_identity=policy.identity(), runtime_qualified=False)


def apply(root, restore=False):
    root = Path(root)
    policy = generator()
    enabled = os.environ.get('XNU_OWNER_DATA_MOUNT', '0') == '1'
    sources = {}
    for target, relative in TARGETS.items():
        path = root / '.cache/xnu-work' / relative
        before = path.read_text(encoding='utf-8')
        after = policy.source(before, target, restore=restore or not enabled)
        if before != after:
            path.write_text(after, encoding='utf-8')
        sources[target] = after
    if not restore:
        directory = root / 'build/nabu-data-none'
        directory.mkdir(parents=True, exist_ok=True)
        record = policy.metadata(sources) if enabled else dict(compiled=False, runtime_qualified=False)
        (directory / 'source-report.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')


def branch_references(content):
    require(len(content) >= 32 and struct.unpack_from('<4I', content) ==
            (0xfeedfacf, 0x100000c, 0, 1), 'Expected ARM64 VFS object')
    count, extent = struct.unpack_from('<II', content, 16)
    cursor, relocations, table = 32, [], None
    for _ in range(count):
        require(cursor + 8 <= 32 + extent <= len(content), 'Invalid VFS load commands')
        command, size = struct.unpack_from('<II', content, cursor)
        require(size >= 8 and cursor + size <= 32 + extent, 'Invalid VFS command size')
        if command == 0x19:
            require(size >= 72, 'Short VFS segment')
            sections = struct.unpack_from('<I', content, cursor + 64)[0]
            require(72 + sections * 80 <= size, 'Short VFS section table')
            for section in range(sections):
                position = cursor + 72 + section * 80
                _, section_size, file_offset = struct.unpack_from('<QQI', content, position + 32)
                flags = struct.unpack_from('<I', content, position + 64)[0]
                offset, number = struct.unpack_from('<II', content, position + 56)
                require(offset + number * 8 <= len(content), 'VFS relocation bounds')
                for index in range(number):
                    address, word = struct.unpack_from('<II', content, offset + index * 8)
                    if word >> 28 == 2:
                        require(flags & 0x80000000 and address % 4 == 0 and
                                address + 4 <= section_size and file_offset + section_size <= len(content),
                                'VFS branch is outside backed instructions')
                        require(word >> 24 & 1 and word >> 25 & 3 == 2,
                                'VFS branch relocation has invalid size or PC mode')
                        instruction = struct.unpack_from('<I', content, file_offset + address)[0]
                        require(instruction & 0x7c000000 == 0x14000000,
                                'VFS branch relocation is not B or BL')
                    relocations.append((address, word))
        elif command == 2:
            require(size >= 24 and table is None, 'Invalid VFS symbol table')
            table = struct.unpack_from('<4I', content, cursor + 8)
        cursor += size
    require(table is not None, 'VFS object lacks symbols')
    offset, number, strings, length = table
    require(offset + number * 16 <= len(content) and strings + length <= len(content), 'VFS symbol bounds')
    names = []
    for index in range(number):
        name = struct.unpack_from('<I', content, offset + index * 16)[0]
        require(name < length, 'VFS symbol string bounds')
        end = content.find(b'\0', strings + name, strings + length)
        require(end >= 0, 'VFS symbol not terminated')
        names.append(content[strings + name:end].decode())
    references = set()
    for _, word in relocations:
        if word >> 28 == 2 and word >> 27 & 1:
            index = word & 0xffffff
            require(index < len(names), 'VFS branch symbol index')
            references.add(names[index])
    return references


def qualify(read, candidate):
    from nabu_display_ci import symbols_and_segments
    from nabu_ui_watch_qualification import object_symbols
    policy = generator()
    config = read('outputs/.config').decode().splitlines()
    enabled = 'CONFIG_XNU_OWNER_DATA_MOUNT=y' in config
    final, segments = symbols_and_segments(candidate)
    if not enabled:
        require(not any(name.startswith('_nabu_owner_data_none_') for name in final) and
                b'NABUDATA_NONE_SOURCE_SHA256=' not in candidate, 'Disabled kernel contains OwnerData None code')
        return dict(compiled=False, runtime_qualified=False)
    bound_generator = read('device/scripts/nabu_data_none_source.py')
    require(bound_generator.replace(b'\r\n', b'\n') ==
            Path(policy.__file__).read_bytes().replace(b'\r\n', b'\n'), 'OwnerData None generator changed')
    sources = {target: read('outputs/tree/.cache/xnu-work/' + relative).decode()
               for target, relative in TARGETS.items()}
    metadata = policy.metadata(sources)
    prepared = json.loads(read('prepare-report.json')).get('data_none')
    require(prepared is not None and prepared['contract'] == policy.CONTRACT and
            prepared['embedded_source_identity'] == policy.identity() and
            prepared['generator_sha256'] == sha(bound_generator), 'OwnerData None preparation mismatch')
    objects = {}
    for target, relative in TARGETS.items():
        object_path = OBJECT_ROOT + target + '.o'
        content = read(object_path)
        recipe_bytes = read(object_path + '.json')
        recipe = json.loads(recipe_bytes.decode().strip().rstrip(','))
        arguments = recipe['arguments']
        definitions = [arguments[index + 1] if word == '-D' else word[2:]
                       for index, word in enumerate(arguments) if word == '-D' or word.startswith('-D')]
        require([value for value in definitions if value.startswith('XNU_OWNER_DATA_MOUNT=')] ==
                ['XNU_OWNER_DATA_MOUNT=1'], 'OwnerData None compile flag mismatch')
        require(recipe['file'].endswith('/.cache/xnu-work/' + relative) and recipe['file'] in arguments and
                Path(recipe['output']).name == target + '.o' and '-o' in arguments and
                Path(arguments[arguments.index('-o') + 1]).name == target + '.o', 'OwnerData None recipe target mismatch')
        references = branch_references(content)
        required = ({'_nabu_owner_data_none_publish'} if target == 'kern_exec' else
                    set(policy.CONTRACT['symbols']) - {'_nabu_owner_data_none_publish'})
        require(required <= references, 'OwnerData None object missing actual helper calls: ' + target)
        if target == 'kpi_vfs':
            require(set(policy.CONTRACT['symbols']) <= set(object_symbols(content, '_nabu_owner_data_none_')),
                    'OwnerData None helper definitions missing')
            require(('NABUDATA_NONE_SOURCE_SHA256=' + policy.identity()).encode() in content,
                    'OwnerData None object source stamp missing')
        objects[target] = dict(sha256=sha(content), recipe_sha256=sha(recipe_bytes),
                               helper_references=sorted(required))
    for name in policy.CONTRACT['symbols']:
        require(name in final, 'OwnerData None final symbol missing: ' + name)
        address = final[name]
        require(any(start <= address and address + 4 <= start + backed and
                    any(candidate[offset + address - start:offset + address - start + 4])
                    for start, _, offset, backed in segments), 'OwnerData None final code unbacked')
    require(('NABUDATA_NONE_SOURCE_SHA256=' + policy.identity()).encode() in candidate,
            'OwnerData None final identity missing')
    return dict(compiled=True, **metadata, objects=objects,
                final_definitions={name: hex(final[name]) for name in policy.CONTRACT['symbols']},
                candidate_sha256=sha(candidate))


def qualify_candidate(upstream, device, candidate, prepared):
    work = Path(upstream) / 'out/nabu'

    def read(name):
        if name.startswith('device/'):
            return (Path(device) / name.removeprefix('device/')).read_bytes()
        if name.startswith('outputs/'):
            return (work / name.removeprefix('outputs/')).read_bytes()
        if name == 'prepare-report.json':
            return json.dumps(prepared).encode()
        raise ValueError('Unexpected OwnerData None qualification input')

    return qualify(read, Path(candidate).read_bytes())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--restore', action='store_true')
    args = parser.parse_args()
    apply(args.root, args.restore)
