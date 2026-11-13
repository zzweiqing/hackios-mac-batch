"""Build the nine pinned network host units and their late constructor glue.

build_kernel(root, out=None) runs on macOS inside the assembled XNU build.
It returns root-relative archive/object/source/header/report paths. Its report
qualifies emitted objects, dependency bytes and archive members. Final kernel
linkage and device execution are owned by the caller's integration step.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import posixpath
import re
import shutil
import struct
import subprocess
import sys
import tempfile

import nabu_wifi_network_source as source
from nabu_idle_ci import _function, _image


PROFILE = 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
CXX_RECIPE = PROFILE + '/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json'
C_PREFERENCE = ('kern_malloc.c', 'kern_subr.c', 'if.c', 'if_fake.c')
GLUE = 'NabuWifiNetworkConstructors.cpp'
CONSTRUCTOR_PREFIX = '__GLOBAL__sub_I_'
STARTUP_WORDS = ('startup', 'init_entry', 'kalloc')


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(content):
    return hashlib.sha256(content).hexdigest()


def read_recipe(content):
    record = json.loads(content.decode('utf-8').strip().rstrip(','))
    require(isinstance(record, dict) and isinstance(record.get('arguments'), list), 'Missing XNU recipe arguments')
    require(isinstance(record.get('file'), str) and isinstance(record.get('directory'), str), 'Missing XNU recipe paths')
    require(all(isinstance(value, str) for value in record['arguments']), 'Non-string XNU compiler argument')
    return record


def admit_recipe(record, language):
    """Reject foreign deployment/source/language recipes before any compiler call."""
    arguments = record['arguments']
    require(arguments and arguments.count(record['file']) == 1 and arguments.count('-o') == 1,
            'XNU recipe needs one actual source and one output')
    require('-c' in arguments and '-mkernel' in arguments, 'XNU recipe must compile kernel code')
    suffix = '.c' if language == 'c' else '.cpp'
    require(record['file'].endswith(suffix), 'Wrong XNU recipe source language')
    target = []
    arch = []
    for index, value in enumerate(arguments):
        if value in ('-target', '--target', '-arch'):
            require(index + 1 < len(arguments), 'Truncated XNU target argument')
            (arch if value == '-arch' else target).append(arguments[index + 1])
        elif value.startswith(('--target=', '-target=')):
            target.append(value.split('=', 1)[1])
        elif value.startswith(('-miphoneos-version-min=', '-mtargetos=')):
            require(value.split('=', 1)[1] in ('17.0', '17.0.0', 'ios17.0', 'ios17.0.0'),
                    'Foreign XNU deployment override')
    require(target and all(re.fullmatch(r'arm64-apple-ios17\.0(?:\.0)?', value) for value in target),
            'XNU recipe requires ordinary arm64 iOS17.0')
    require(not arch or all(value == 'arm64' for value in arch), 'Foreign XNU architecture')
    language_flags = [value for value in arguments if value in ('-xc', '-xc++', '--driver-mode=g++')]
    for index, value in enumerate(arguments):
        if value == '-x':
            require(index + 1 < len(arguments), 'Truncated XNU language argument')
            language_flags.append('-x' + arguments[index + 1])
    expected_language = ('-xc',) if language == 'c' else ('-xc++', '--driver-mode=g++')
    require(all(value in expected_language for value in language_flags), 'Conflicting XNU source language flags')
    standards = [value for value in arguments if value.startswith('-std=')]
    if language == 'c':
        # Actual XNU .o.json C records rely on the compiler's default dialect.
        # command_for explicitly selects gnu17 for the generated network units.
        require(len(standards) <= 1 and not any('++' in value for value in standards), 'XNU recipe dialect drift')
    else:
        require(len(standards) == 1 and '++' in standards[0], 'XNU recipe dialect drift')
    return record


def choose_c_recipe(records):
    """Select a deterministic BSD C source, failing on a drifted preferred recipe."""
    candidates = [(path, record) for path, record in records
                  if record['file'].endswith('.c') and '/bsd/' in record['file'].replace('\\', '/')]
    require(candidates, 'No actual BSD .c compilation recipe was found')
    def preference(item):
        filename = item[1]['file'].replace('\\', '/').rsplit('/', 1)[-1]
        priority = C_PREFERENCE.index(filename) if filename in C_PREFERENCE else len(C_PREFERENCE)
        return priority, item[0]
    chosen = min(candidates, key=preference)
    admit_recipe(chosen[1], 'c')
    return chosen


def _platform(root):
    path = root / 'scripts/build-nabu-platform.py'
    if not path.is_file():
        path = Path(__file__).resolve().parents[1] / 'nabu-device/scripts/build-nabu-platform.py'
    require(path.is_file(), 'Current XNU compile_command helper is missing')
    spec = importlib.util.spec_from_file_location('nabu_network_platform_build', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, path


def command_for(record, path, obj, dependency, source_dir, header_dir, language, retarget):
    admit_recipe(record, language)
    command = retarget(record, path, obj)
    command = [value for value in command if value not in ('-MMD', '-MD', '-MP')]
    if language == 'c':
        command = [value for value in command if not value.startswith('-std=')]
        command.append('-std=gnu17')
    prefixes = ['-I', str(source_dir / 'bsd')]
    prefixes += ['-I', str(header_dir)]
    command[1:1] = prefixes
    command += [
        '-DKERNEL=1', '-DKERNEL_PRIVATE=1', '-DXNU_KERNEL_PRIVATE=1',
        '-DBSD_KERNEL_PRIVATE=1', '-D__APPLE_API_PRIVATE=1', '-D__APPLE_API_UNSTABLE=1']
    command += ['-mgeneral-regs-only', '-ffreestanding', '-fno-common', '-MMD', '-MF', str(dependency), '-MT', str(obj)]
    require('-fno-common' in command and '-mgeneral-regs-only' in command, 'Missing kernel object flags')
    if language == 'c':
        require([value for value in command if value.startswith('-std=')] == ['-std=gnu17'], 'C dialect drift')
    return command


def full_dependency_command(command, dependency, obj):
    result = []
    index = 0
    while index < len(command):
        value = command[index]
        if value in ('-o', '-MF', '-MT', '-MQ', '-MJ'):
            index += 2
            continue
        if value not in ('-c', '-MMD', '-MD', '-MP'):
            result.append(value)
        index += 1
    return result + ['-M', '-MF', str(dependency), '-MT', str(obj)]


def dependency_words(content):
    """Read one Clang make dependency rule, including escaped path characters."""
    text = content.decode('utf-8').replace('\\\r\n', '').replace('\\\n', '')
    escaped = False
    separator = None
    for index, character in enumerate(text):
        if escaped:
            escaped = False
        elif character == '\\':
            escaped = True
        elif character == ':':
            separator = index
            break
    require(separator is not None, 'Missing compiler dependency target')
    words, word, escaped = [], [], False
    for character in text[separator + 1:]:
        if escaped:
            word.append(character)
            escaped = False
        elif character == '\\':
            escaped = True
        elif character.isspace():
            if word:
                words.append(''.join(word).replace('$$', '$'))
                word = []
        elif character in ('#', ':'):
            raise ValueError('Unexpected additional compiler dependency rule')
        else:
            word.append(character)
    require(not escaped, 'Truncated compiler dependency escape')
    if word:
        words.append(''.join(word).replace('$$', '$'))
    require(words, 'Empty compiler dependency closure')
    return words


def dependency_paths(content, directory):
    return sorted({Path(os.path.abspath(value if Path(value).is_absolute() else Path(directory) / value))
                   for value in dependency_words(content)})


def dependency_names(content, directory):
    """Replay macOS dependency names lexically after its filesystem disappears."""
    return sorted({posixpath.normpath(value if value.startswith('/') else posixpath.join(directory, value))
                   for value in dependency_words(content)})


def archive_members(content):
    """Decode ordinary BSD/GNU ar members without invoking runner tools."""
    require(content.startswith(b'!<arch>\n'), 'Expected an ordinary network archive')
    cursor, strings, result = 8, b'', []
    while cursor < len(content):
        require(cursor + 60 <= len(content), 'Truncated archive member header')
        header = content[cursor:cursor + 60]
        require(header[58:60] == b'`\n', 'Invalid archive member header')
        size = int(header[48:58].strip())
        cursor += 60
        require(0 <= size <= len(content) - cursor, 'Archive member payload bounds')
        data = content[cursor:cursor + size]
        name = header[:16].decode().rstrip()
        cursor += size
        if size & 1:
            require(cursor < len(content) and content[cursor:cursor + 1] == b'\n', 'Archive member padding')
            cursor += 1
        if name.startswith('#1/'):
            length = int(name[3:])
            require(0 < length <= len(data), 'BSD archive filename bounds')
            name = data[:length].rstrip(b'\0').decode()
            data = data[length:]
        elif name == '//':
            strings = data
            continue
        elif re.fullmatch(r'/\d+', name):
            offset = int(name[1:])
            end = strings.find(b'/\n', offset)
            require(0 <= offset < end, 'GNU archive filename bounds')
            name = strings[offset:end].decode()
        elif name.endswith('/') and name not in ('/', '/SYM64/'):
            name = name[:-1]
        if name in ('/', '/SYM64/', '__.SYMDEF', '__.SYMDEF SORTED', '__.SYMDEF_64', '__.SYMDEF_64 SORTED'):
            continue
        require(name and '/' not in name and name not in {item[0] for item in result}, 'Duplicate or invalid archive member')
        result.append((name, data))
    require(cursor == len(content), 'Archive trailing data')
    return result


def artifact_bytes(read, record):
    path = PurePosixPath(record['artifact_path'])
    require(path.parts and not path.is_absolute() and '..' not in path.parts and '\\' not in str(path) and
            ':' not in str(path) and str(path) == record['artifact_path'], 'External network artifact path')
    content = read(str(path))
    require(isinstance(content, bytes) and sha(content) == record['sha256'], 'Network artifact SHA mismatch: ' + str(path))
    return content


def capture_dependency(root, output, original, content):
    """Capture only one actual-used input, with a portable root-relative receipt."""
    key = sha(str(original).encode())
    target = output / 'dependencies' / key / original.name
    require(target.resolve().is_relative_to(root), 'Dependency capture escaped its build root')
    _write(target, content)
    require(target.read_bytes() == content, 'Captured dependency readback drift')
    return dict(artifact_path=target.relative_to(root).as_posix(), sha256=sha(content), bytes=len(content))


def inspect_object(content):
    """Reuse the existing ARM64 parser and retain semantic relocation identities."""
    image = _image(content, 1)
    sections, entries, table, deployment = [], [], None, None
    offset = 32
    for _ in range(struct.unpack_from('<I', content, 16)[0]):
        command, size = struct.unpack_from('<II', content, offset)
        if command == 0x19:
            for index in range(struct.unpack_from('<I', content, offset + 64)[0]):
                at = offset + 72 + index * 80
                label, segment, address, length, fileoff, _, reloc, count, flags = struct.unpack_from('<16s16sQQ5I', content, at)
                key = segment.rstrip(b'\0').decode() + ',' + label.rstrip(b'\0').decode()
                zero_fill = flags & 0xff in (1, 0xc, 0x12)
                require(zero_fill or fileoff + length <= len(content), 'Unbacked network object section')
                sections.append(dict(name=key, address=address, bytes=length, flags=flags,
                                     data=b'' if zero_fill else content[fileoff:fileoff + length],
                                     relocation_offset=reloc, relocation_count=count))
        elif command == 2:
            table = struct.unpack_from('<4I', content, offset + 8)
        elif command == 0x32:
            require(size >= 24 and deployment is None, 'Malformed network deployment record')
            deployment = struct.unpack_from('<II', content, offset + 8)
        offset += size
    require(deployment == (2, 0x110000), 'Network object must target iOS17.0')
    require(len({section['name'] for section in sections}) == len(sections), 'Duplicate network section names')
    symoff, count, stroff, extent = table
    for index in range(count):
        name, kind, ordinal, _, address = struct.unpack_from('<IBBHQ', content, symoff + index * 16)
        require(name < extent, 'Network symbol string range')
        end = content.find(b'\0', stroff + name, stroff + extent)
        require(end >= 0, 'Network symbol terminator')
        entries.append(dict(name=content[stroff + name:end].decode(), kind=kind, section=ordinal, address=address))
        require(kind & 0xe0 or kind & 0xe != 0 or address == 0, 'Network object has unallocated COMMON storage')
    for section in sections:
        relocations = []
        for index in range(section['relocation_count']):
            at, value = struct.unpack_from('<II', content, section['relocation_offset'] + index * 8)
            require(not at & 0x80000000, 'Scattered ARM64 relocation is unsupported')
            target = value & 0xffffff
            external = bool(value >> 27 & 1)
            require(target < len(entries) if external else 0 < target <= len(sections), 'Network relocation target bounds')
            relocations.append(dict(offset=at, type=value >> 28, length=value >> 25 & 3,
                                    pcrel=bool(value >> 24 & 1), external=external,
                                    target=entries[target]['name'] if external else sections[target - 1]['name']))
        section['relocations'] = relocations
    return dict(image=image, sections=sections, symbols=entries, sha256=sha(content))


def section_receipt(parsed):
    return {section['name']: dict(bytes=section['bytes'], flags=section['flags'],
                                 sha256=sha(section['data']), relocations=section['relocations'])
            for section in parsed['sections']}


def constructor_symbol(parsed):
    initializers = [section for section in parsed['sections'] if section['name'].endswith(',__mod_init_func')]
    require(len(initializers) == 1 and initializers[0]['name'] == '__DATA,__mod_init_func',
            'Expected one __DATA constructor section')
    section = initializers[0]
    require(section['bytes'] == 8 and len(section['relocations']) == 1, 'Expected one constructor pointer')
    relocation = section['relocations'][0]
    require(relocation['offset'] == 0 and relocation['type'] == 0 and relocation['length'] == 3 and
            not relocation['pcrel'], 'Unexpected constructor pointer relocation')
    if relocation['external']:
        matches = [entry for entry in parsed['symbols'] if entry['name'] == relocation['target'] and
                   not entry['kind'] & 0xe0 and entry['kind'] & 0xe == 0xe]
    else:
        address = struct.unpack('<Q', section['data'])[0]
        ordinal = next(index + 1 for index, item in enumerate(parsed['sections']) if item['name'] == relocation['target'])
        matches = [entry for entry in parsed['symbols'] if entry['section'] == ordinal and entry['address'] == address and
                   not entry['kind'] & 0xe0 and entry['kind'] & 0xe == 0xe and entry['name'].startswith(CONSTRUCTOR_PREFIX)]
    require(len(matches) == 1 and re.fullmatch(r'__GLOBAL__sub_I_[A-Za-z0-9_.$]+', matches[0]['name']),
            'Initializer does not identify one actual constructor symbol')
    require(matches[0]['name'] in parsed['image']['names'], 'Constructor must contain defined instructions')
    _function(parsed['image'], matches[0]['name'])
    return matches[0]['name']


def check_late_object(before, after, constructor):
    old, new = section_receipt(before), section_receipt(after)
    require('__DATA,__mod_init_func' in old, 'Original constructor section is missing')
    require(not any(name.endswith(',__mod_init_func') for name in new), 'Late object retained automatic constructors')
    require({name: record for name, record in old.items() if name != '__DATA,__mod_init_func'} == new,
            'Late transformation changed preserved sections or startup relocations')
    symbols = [entry for entry in after['symbols'] if entry['name'] == constructor and entry['kind'] == 0xf]
    require(len(symbols) == 1, 'Actual constructor was not globalized')
    return dict(before_sha256=before['sha256'], after_sha256=after['sha256'], constructor=constructor,
                removed_section='__DATA,__mod_init_func', preserved_sections=new,
                startup_sections=[name for name in new if any(word in name for word in STARTUP_WORDS)])


def constructor_source(constructors):
    require(len(constructors) == 2 and len(set(constructors)) == 2 and
            all(re.fullmatch(r'__GLOBAL__sub_I_[A-Za-z0-9_.$]+', name) for name in constructors),
            'Constructor glue requires two distinct observed symbols')
    text = '/* Derived Nabu network constructor glue, APSL-2.0. */\n'
    for index, name in enumerate(constructors):
        text += f'extern "C" void nabu_wifi_network_ctor_{index}(void) __asm__("{name}");\n'
    text += ('extern "C" void nabu_wifi_network_static_init(void)\n{\n'
             '    nabu_wifi_network_ctor_0();\n    nabu_wifi_network_ctor_1();\n}\n')
    identity = 'NABUWIFI_NETWORK_CONSTRUCTORS_SHA256=' + sha(text.encode())
    text += ('extern "C" const char nabu_wifi_network_static_init_identity[];\n'
             f'const char nabu_wifi_network_static_init_identity[] __attribute__((used)) = "{identity}";\n')
    return text, identity


def check_glue(parsed, constructors, identity):
    image = parsed['image']
    require('_nabu_wifi_network_static_init' in image['names'] and
            '_nabu_wifi_network_static_init_identity' in image['names'], 'Missing constructor glue exports')
    start, words, section = _function(image, '_nabu_wifi_network_static_init')
    calls = []
    for item in parsed['sections']:
        for relocation in item['relocations']:
            address = item['address'] + relocation['offset']
            if start <= address < start + len(words) * 4 and relocation['type'] == 2:
                require(relocation['external'] and relocation['length'] == 2 and relocation['pcrel'], 'Malformed glue branch')
                require(words[(address - start) // 4] & 0x7c000000 == 0x14000000, 'Glue relocation is not B/BL')
                calls.append((address, relocation['target']))
    require([name for _, name in sorted(calls)] == constructors, 'Glue does not call the two actual constructors in order')
    require(not any(item['name'].endswith(',__mod_init_func') for item in parsed['sections']), 'Glue has automatic initializers')
    require(any(identity.encode() in item['data'] for item in parsed['sections']), 'Glue source identity is absent')
    return dict(sha256=parsed['sha256'], calls=constructors, identity=identity, automatic_initializers=False)


def _run(command, directory, log):
    result = subprocess.run(command, cwd=directory, capture_output=True)
    if log is not None:
        log.write_bytes(result.stdout + result.stderr)
    if result.returncode:
        detail = str(log) if log is not None else result.stderr.decode('utf-8', errors='replace')
        raise RuntimeError(f'Network build command failed ({result.returncode}); {detail}')
    return result.stdout


def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        require(path.read_bytes() == content, 'Existing network build input drift: ' + str(path))
    else:
        path.write_bytes(content)


def finish_report(result, report):
    """Attach a serializable report with a snapshot of the public build result."""
    report['build_result'] = dict(result)
    result['qualification'] = report
    return result


def qualify_artifacts(read, metadata):
    """Replay collected bytes only. read takes a root-relative POSIX path.

    The caller may wrap read('outputs/tree/' + path). Commands are reconstructed
    with the current trusted compile helper and collected recipe bytes. SDK and
    generated-header inputs come from the captured dependency artifacts.
    The caller separately qualifies the final linked kernel and linkedBoot gate.
    """
    require(metadata['version'] == 2, 'Unsupported network build receipt version')
    result = metadata['build_result']
    root = PurePosixPath(metadata['build_root'])
    require(root.is_absolute() and '..' not in root.parts, 'Non-POSIX original build root')
    output = PurePosixPath(result['archive']).parent
    source_dir, header_dir = root / result['source_dir'], root / result['header_dir']
    require(set(metadata['inputs']) == set(source.dependency_manifest()), 'Network input manifest drift')
    require(set(metadata['headers']) == set(source.XNU_HEADERS), 'Network API header manifest drift')
    inputs = {path: artifact_bytes(read, record) for path, record in metadata['inputs'].items()}
    headers = {path: artifact_bytes(read, record) for path, record in metadata['headers'].items()}
    files = {path: artifact_bytes(read, record) for path, record in metadata['source_artifacts'].items()}
    source.qualify(inputs, headers, files, metadata['source_report'])
    for path, record in metadata['headers'].items():
        require(record['staged_path'] == path.split('/', 1)[1] and
                root / record['artifact_path'] == header_dir / record['staged_path'], 'Staged API header namespace drift')
    for path, record in metadata['source_artifacts'].items():
        require(root / record['artifact_path'] == source_dir / path, 'Generated source artifact namespace drift')

    helper, helper_path = _platform(Path(__file__).resolve().parents[1])
    require(artifact_bytes(read, metadata['compile_helper']) == helper_path.read_bytes() and
            metadata['compile_helper_sha256'] == sha(helper_path.read_bytes()), 'Current compile helper drift')
    require(set(metadata['recipes']) == {'c', 'c++'}, 'Network recipe manifest drift')
    recipes = {language: read_recipe(artifact_bytes(read, record)) for language, record in metadata['recipes'].items()}
    chosen = metadata['selected_c_recipe']
    require(chosen.startswith(PROFILE + '/') and chosen.endswith(('.o.json', '.co.json')) and
            '/bsd/' in recipes['c']['file'], 'Selected actual BSD recipe drift')
    require(metadata['chosen_recipe_sha256'] == metadata['recipes']['c']['sha256'] and
            metadata['cxx_recipe_sha256'] == metadata['recipes']['c++']['sha256'], 'Actual recipe input SHA drift')
    require(metadata['selected_c_source'] == recipes['c']['file'] and metadata['cxx_recipe'] == CXX_RECIPE,
            'Actual recipe source selection drift')
    require(recipes['c']['arguments'][0] == recipes['c++']['arguments'][0], 'Compiler recipe identity drift')
    for language, recipe in recipes.items():
        admit_recipe(recipe, language)

    units = metadata['source_report']['translation_units']
    unit_order = metadata['translation_unit_order']
    require(unit_order == list(source.EXPORTS), 'Pinned translation unit order drift')
    constructor_units = metadata['source_report']['compile']['constructor_units']
    require(len(units) == 9 and len(constructor_units) == 2 and
            set(metadata['objects']) == set(units) | {GLUE}, 'Network raw object manifest drift')
    require(set(metadata['constructor_transformations']) == set(constructor_units), 'Late constructor manifest drift')
    raw_objects, final_objects, parsed, dependencies = {}, {}, {}, {}
    for unit, record in metadata['objects'].items():
        language = 'c++' if unit == GLUE else units[unit]['language']
        source_path = root / record['source_artifact']['artifact_path']
        expected_source = root / output / 'inputs/generated' / GLUE if unit == GLUE else source_dir / unit
        require(source_path == expected_source, 'Actual compilation source path drift')
        content = artifact_bytes(read, record['source_artifact'])
        require(sha(content) == record['source_sha256'] and (unit == GLUE or content == files[unit]), 'Actual compilation source bytes drift')
        obj = root / record['raw_object']['artifact_path']
        require(obj == root / output / 'objects/raw' / (PurePosixPath(unit).stem + '.o'), 'Raw object namespace drift')
        dependency = root / record['dependency_artifact']['artifact_path']
        full_dependency = root / record['full_dependency_artifact']['artifact_path']
        expected = command_for(recipes[language], source_path, obj, dependency, source_dir, header_dir,
                               language, helper.compile_command)
        require(record['recipe'] == (chosen if language == 'c' else CXX_RECIPE), 'Unit recipe selection drift')
        require(record['command'] == expected and json.loads(artifact_bytes(read, record['command_artifact'])) == expected,
                'Actual compilation flags drift')
        require(json.loads(artifact_bytes(read, record['dependency_command_artifact'])) ==
                full_dependency_command(expected, full_dependency, obj), 'Actual full dependency flags drift')
        local = set(dependency_names(artifact_bytes(read, record['dependency_artifact']), recipes[language]['directory']))
        closure = dependency_names(artifact_bytes(read, record['full_dependency_artifact']), recipes[language]['directory'])
        require(local <= set(closure) and str(source_path) in closure and set(record['dependencies']) == set(closure),
                'Actual dependency closure manifest drift')
        for original, receipt in record['dependencies'].items():
            path = output / 'dependencies' / sha(original.encode()) / PurePosixPath(original).name
            require(receipt['artifact_path'] == str(path), 'Dependency artifact path-key drift')
            captured = artifact_bytes(read, receipt)
            require(len(captured) == receipt['bytes'], 'Dependency artifact byte extent drift')
            require(original not in dependencies or dependencies[original] == receipt, 'Cross-unit dependency input drift')
            dependencies[original] = receipt
            if original == str(source_path):
                require(captured == content, 'Actual used source dependency drift')
            for header_path, header in metadata['headers'].items():
                names = (root / '.cache/xnu-work' / header_path, root / header['artifact_path'])
                if original in {str(name) for name in names}:
                    require(captured == headers[header_path], 'Actual used API header dependency drift')
        raw = artifact_bytes(read, record['raw_object'])
        require(sha(raw) == record['object_sha256'], 'Raw object receipt SHA drift')
        parsed[unit] = inspect_object(raw)
        require(section_receipt(parsed[unit]) == record['sections'], 'Raw object section receipt drift')
        if unit != GLUE:
            raw_objects[unit] = raw
        final_objects[unit] = artifact_bytes(read, record['final_object'])
    raw_qualified = source.qualify(inputs, headers, files, metadata['source_report'], raw_objects)
    require(raw_qualified == metadata['source_qualification'], 'Raw source qualification receipt drift')

    constructors, late_receipts = [], {}
    for unit in unit_order:
        record = metadata['objects'][unit]
        final = record['final_object']
        if unit in constructor_units:
            constructor = constructor_symbol(parsed[unit])
            constructors.append(constructor)
            late = inspect_object(final_objects[unit])
            receipt = check_late_object(parsed[unit], late, constructor)
            recorded = metadata['constructor_transformations'][unit]
            require({key: value for key, value in recorded.items() if key != 'command_artifact'} == receipt,
                    'Late constructor receipt drift')
            command = json.loads(artifact_bytes(read, recorded['command_artifact']))
            require(len(command) == 5 and PurePosixPath(command[0]).name == 'llvm-objcopy' and command[1:] ==
                    ['--remove-section=__DATA,__mod_init_func', '--globalize-symbol=' + constructor,
                     str(root / record['raw_object']['artifact_path']), str(root / final['artifact_path'])],
                    'Actual late constructor command drift')
            require(root / final['artifact_path'] == root / output / 'objects/late' / (PurePosixPath(unit).stem + '.late.o'),
                    'Late object namespace drift')
            late_receipts[unit] = receipt
        else:
            require(final == record['raw_object'], 'Ordinary object unexpectedly transformed')
        final_parsed = inspect_object(final_objects[unit])
        require(not any(section['name'].endswith(',__mod_init_func') for section in final_parsed['sections']),
                'Archive object retained automatic initializers')
        require(record['archive_object'] == final['artifact_path'] and
                record['archive_sections'] == section_receipt(final_parsed), 'Archive object section receipt drift')
        require(sha(final_objects[unit]) == record['archive_object_sha256'], 'Final object archive SHA drift')
    glue_source, identity = constructor_source(constructors)
    glue_record = metadata['objects'][GLUE]
    require(artifact_bytes(read, glue_record['source_artifact']) == glue_source.encode() and
            metadata['glue_source_sha256'] == sha(glue_source.encode()), 'Actual constructor glue source drift')
    require(glue_record['final_object'] == glue_record['raw_object'], 'Glue object unexpectedly transformed')
    glue = check_glue(parsed[GLUE], constructors, identity)
    require(glue == metadata['constructor_glue'], 'Constructor glue call receipt drift')
    qualified = source.qualify(inputs, headers, files, metadata['source_report'],
                               {unit: final_objects[unit] for unit in units})
    require(qualified == metadata['archive_source_qualification'], 'Compiled source qualification receipt drift')
    require(metadata['link_qualified'] is False and metadata['runtime_qualified'] is False and
            metadata['linked_into_final_kernel'] is False, 'Network artifact qualification boundary drift')
    expected_paths = [metadata['objects'][unit]['final_object']['artifact_path'] for unit in [*unit_order, GLUE]]
    names = [PurePosixPath(path).name for path in expected_paths]
    require(result['objects'] == expected_paths and metadata['archive_members'] == names, 'Archive exact member manifest drift')
    archive = artifact_bytes(read, dict(artifact_path=result['archive'], sha256=metadata['archive_sha256']))
    members = archive_members(archive)
    require([name for name, _ in members] == names and len(members) == 10, 'Archive exact member set drift')
    require([content for _, content in members] == [final_objects[unit] for unit in [*unit_order, GLUE]], 'Archive member byte drift')
    return dict(version=2, source_qualified=True, objects_qualified=True, dependency_artifacts_qualified=True,
                recipes_flags_qualified=True, raw_object_count=9, late_constructor_count=2, glue_object_count=1,
                archive_member_count=10, dependency_count=len(dependencies), late_constructors=late_receipts, glue=glue,
                apple80211_21h16_abi_qualified=qualified['apple80211_21h16_abi_qualified'],
                apple80211_21h16_complete_abi_qualified=False, archive_sha256=sha(archive),
                link_qualified=False, runtime_qualified=False)


def build_kernel(root, out=None):
    if sys.platform != 'darwin':
        raise RuntimeError('Network Mac compilation requires macOS/Xcode in GitHub Actions')
    root = Path(root).resolve(strict=True)
    output = root / source.OUTPUT if out is None else Path(out)
    if not output.is_absolute():
        output = root / output
    output = output.resolve()
    require(output.is_relative_to(root), 'Network output must stay inside the assembled build root')
    inputs = source.fetch_inputs()
    source_report = source.apply(root, inputs)
    source_dir = root / source.OUTPUT / 'source'
    header_dir = output / 'headers'
    headers, header_artifacts, input_artifacts = {}, {}, {}
    for path, digest in source.XNU_HEADERS.items():
        content = source._validated((root / '.cache/xnu-work' / path).read_bytes(), digest, path)
        _write(header_dir / path.split('/', 1)[1], content)
        headers[path] = content
        header_artifacts[path] = dict(artifact_path=(header_dir / path.split('/', 1)[1]).relative_to(root).as_posix(),
                                      sha256=sha(content), staged_path=path.split('/', 1)[1])
    for path, content in inputs.items():
        _write(output / 'inputs' / path, content)
        input_artifacts[path] = dict(artifact_path=(output / 'inputs' / path).relative_to(root).as_posix(), sha256=sha(content))
    files = {path: (source_dir / path).read_bytes() for path in source_report['outputs']}
    source_artifacts = {path: dict(artifact_path=(source_dir / path).relative_to(root).as_posix(), sha256=sha(content))
                        for path, content in files.items()}
    source.qualify(inputs, headers, files, source_report)
    platform, platform_path = _platform(root)
    recipe_root = root / PROFILE
    recipe_files = sorted([*recipe_root.rglob('*.o.json'), *recipe_root.rglob('*.co.json')])
    recipe_inputs = {path.relative_to(root).as_posix(): path.read_bytes() for path in recipe_files}
    candidates = [(path, read_recipe(content)) for path, content in recipe_inputs.items()]
    chosen, c_record = choose_c_recipe(candidates)
    cxx_input = (root / CXX_RECIPE).read_bytes()
    cxx_record = admit_recipe(read_recipe(cxx_input), 'c++')
    require(c_record['arguments'][0] == cxx_record['arguments'][0], 'C and C++ XNU compiler identities differ')
    output.mkdir(parents=True, exist_ok=True)
    recipe_artifacts = {}
    for language, content in (('c', recipe_inputs[chosen]), ('c++', cxx_input)):
        path = output / 'inputs/recipes' / ('c.json' if language == 'c' else 'cxx.json')
        _write(path, content)
        recipe_artifacts[language] = dict(artifact_path=path.relative_to(root).as_posix(), sha256=sha(content))
    helper_copy = output / 'inputs/build-nabu-platform.py'
    _write(helper_copy, platform_path.read_bytes())
    helper_artifact = dict(artifact_path=helper_copy.relative_to(root).as_posix(), sha256=sha(platform_path.read_bytes()))
    compiler_version = _run([c_record['arguments'][0], '--version'], root, output / 'compiler-version.log').decode()
    records, raw_objects, paths, dependency_cache = {}, {}, {}, {}

    def compile_unit(unit, language, path):
        obj = output / 'objects/raw' / (path.stem + '.o')
        obj.parent.mkdir(parents=True, exist_ok=True)
        record = c_record if language == 'c' else cxx_record
        commands = output / 'commands'
        commands.mkdir(parents=True, exist_ok=True)
        dependency = commands / (path.stem + '.d')
        full_dependency = commands / (path.stem + '.full.d')
        command = command_for(record, path, obj, dependency, source_dir, header_dir, language, platform.compile_command)
        command_path = commands / (path.stem + '.compile.json')
        command_path.write_text(json.dumps(command, indent=2) + '\n')
        dependency_command = full_dependency_command(command, full_dependency, obj)
        dependency_command_path = commands / (path.stem + '.dependencies.json')
        dependency_command_path.write_text(json.dumps(dependency_command, indent=2) + '\n')
        _run(dependency_command, record['directory'], obj.with_suffix('.dependencies.log'))
        closure = dependency_paths(full_dependency.read_bytes(), record['directory'])
        require(Path(os.path.abspath(path)) in closure, 'Compiler dependency closure drift')
        dependency_records = {}
        for dependency_path in closure:
            require(dependency_path.is_file(), 'Missing actual compiler dependency: ' + str(dependency_path))
            dependency_content = dependency_path.read_bytes()
            digest = sha(dependency_content)
            if dependency_path in dependency_cache:
                require(dependency_cache[dependency_path] == digest, 'Concurrent compiler dependency mutation')
            dependency_cache[dependency_path] = digest
            dependency_records[str(dependency_path)] = capture_dependency(root, output, dependency_path, dependency_content)
        _run(command, record['directory'], obj.with_suffix('.log'))
        local = set(dependency_paths(dependency.read_bytes(), record['directory']))
        require(local <= set(closure), 'Compiler dependency closure drift')
        for dependency_path in closure:
            require(sha(dependency_path.read_bytes()) == dependency_cache[dependency_path],
                    'Compiler dependency changed during compilation')
        data = obj.read_bytes()
        platform.check_object(data)
        parsed = inspect_object(data)
        if unit in source_report['translation_units']:
            required = source_report['translation_units'][unit]
            require(set(required['exports']) <= set(parsed['image']['names']) and
                    required['source_identity'].encode() in data, 'Compiled network source binding drift: ' + unit)
        records[unit] = dict(source_sha256=sha(path.read_bytes()), object_sha256=sha(data),
                             command=command, recipe=chosen if language == 'c' else CXX_RECIPE,
                             source_artifact=dict(artifact_path=path.relative_to(root).as_posix(), sha256=sha(path.read_bytes())),
                             raw_object=dict(artifact_path=obj.relative_to(root).as_posix(), sha256=sha(data)),
                             command_artifact=dict(artifact_path=command_path.relative_to(root).as_posix(), sha256=sha(command_path.read_bytes())),
                             dependency_command_artifact=dict(artifact_path=dependency_command_path.relative_to(root).as_posix(),
                                                              sha256=sha(dependency_command_path.read_bytes())),
                             dependency_artifact=dict(artifact_path=dependency.relative_to(root).as_posix(), sha256=sha(dependency.read_bytes())),
                             full_dependency_artifact=dict(artifact_path=full_dependency.relative_to(root).as_posix(),
                                                          sha256=sha(full_dependency.read_bytes())),
                             dependencies=dependency_records, sections=section_receipt(parsed))
        return obj, data, parsed

    parsed_objects, compilation_failures = {}, []
    for unit, policy in source_report['translation_units'].items():
        try:
            obj, data, parsed = compile_unit(unit, policy['language'], source_dir / unit)
        except RuntimeError as error:
            # Compile independent units to preserve all actionable compiler
            # diagnostics in this run. Never qualify or archive a partial set.
            compilation_failures.append(dict(unit=unit, error=str(error)))
            continue
        raw_objects[unit], parsed_objects[unit], paths[unit] = data, parsed, obj
    if compilation_failures:
        _write(output / 'compilation-failures.json',
               (json.dumps(compilation_failures, indent=2) + '\n').encode())
        raise RuntimeError('Network compilation failed for: ' +
                           ', '.join(item['unit'] for item in compilation_failures))
    qualification = source.qualify(inputs, headers, files, source_report, raw_objects)
    constructors, late = [], {}
    objcopy = shutil.which('llvm-objcopy')
    require(objcopy is not None, 'The existing LLVM Mach-O objcopy tool is required')
    for unit in source_report['compile']['constructor_units']:
        constructor = constructor_symbol(parsed_objects[unit])
        original = paths[unit]
        transformed = output / 'objects/late' / (original.stem + '.late.o')
        transformed.parent.mkdir(parents=True, exist_ok=True)
        command = [objcopy, '--remove-section=__DATA,__mod_init_func', '--globalize-symbol=' + constructor,
                   str(original), str(transformed)]
        _run(command, root, original.with_suffix('.objcopy.log'))
        late[unit] = check_late_object(parsed_objects[unit], inspect_object(transformed.read_bytes()), constructor)
        command_path = output / 'commands' / (original.stem + '.objcopy.json')
        command_path.write_text(json.dumps(command, indent=2) + '\n')
        late[unit]['command_artifact'] = dict(artifact_path=command_path.relative_to(root).as_posix(), sha256=sha(command_path.read_bytes()))
        paths[unit] = transformed
        constructors.append(constructor)
    for unit, path in paths.items():
        parsed = inspect_object(path.read_bytes())
        require(not any(item['name'].endswith(',__mod_init_func') for item in parsed['sections']),
                'Archive member retained an automatic initializer: ' + unit)
        records[unit]['archive_object'] = path.relative_to(root).as_posix()
        records[unit]['archive_object_sha256'] = parsed['sha256']
        records[unit]['final_object'] = dict(artifact_path=path.relative_to(root).as_posix(), sha256=parsed['sha256'])
        records[unit]['archive_sections'] = section_receipt(parsed)
    text, identity = constructor_source(constructors)
    glue_path = output / 'inputs/generated' / GLUE
    _write(glue_path, text.encode())
    glue_obj, glue_data, glue_parsed = compile_unit(GLUE, 'c++', glue_path)
    records[GLUE]['final_object'] = dict(artifact_path=glue_obj.relative_to(root).as_posix(), sha256=sha(glue_data))
    glue = check_glue(glue_parsed, constructors, identity)
    members = list(paths.values()) + [glue_obj]
    require(len(members) == 10 and len({path.name for path in members}) == 10, 'Network archive requires exactly ten objects')
    for path, digest in dependency_cache.items():
        require(sha(path.read_bytes()) == digest, 'Compiler dependency changed before archive qualification')
    for path, digest in source.XNU_HEADERS.items():
        require(sha((header_dir / path.split('/', 1)[1]).read_bytes()) == digest,
                'Staged API header changed during compilation')
    require((root / chosen).read_bytes() == recipe_inputs[chosen] and
            (root / CXX_RECIPE).read_bytes() == cxx_input, 'XNU compilation recipe changed during this build')
    archive = output / 'libNabuWifiNetwork.a'
    descriptor, temporary = tempfile.mkstemp(prefix='.NabuWifiNetwork-', suffix='.a', dir=output)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(b'!<arch>\n')
    pending_archive = Path(temporary)
    require(pending_archive.resolve().is_relative_to(root), 'Network archive escaped its build root')
    _run(['xcrun', 'ar', 'rcs', str(pending_archive), *map(str, members)], root, output / 'archive.log')
    require(pending_archive.read_bytes().startswith(b'!<arch>\n'), 'Expected an ordinary network archive')
    listed = _run(['xcrun', 'ar', 't', str(pending_archive)], root, output / 'archive-members.log').decode().splitlines()
    require(listed == [path.name for path in members], 'Network archive member set drift')
    for path in members:
        stored = _run(['xcrun', 'ar', 'p', str(pending_archive), path.name], root, None)
        require(stored == path.read_bytes(), 'Archive member differs from qualified network object')
    pending_archive.replace(archive)
    result = dict(archive=archive.relative_to(root).as_posix(),
                  objects=[path.relative_to(root).as_posix() for path in members],
                  source_dir=source_dir.relative_to(root).as_posix(), header_dir=header_dir.relative_to(root).as_posix(),
                  report=(output / 'build-report.json').relative_to(root).as_posix())
    report = dict(version=2, build_root=str(root), source_report=source_report,
                  translation_unit_order=list(source_report['translation_units']), selected_c_recipe=chosen,
                  selected_c_source=c_record['file'], cxx_recipe=CXX_RECIPE,
                  compile_helper_sha256=sha(platform_path.read_bytes()),
                  chosen_recipe_sha256=sha(recipe_inputs[chosen]), cxx_recipe_sha256=sha(cxx_input),
                  compiler_version=compiler_version,
                  objects=records, constructor_transformations=late, constructor_glue=glue,
                  glue_source_sha256=sha(text.encode()), archive_members=listed,
                  headers=header_artifacts, inputs=input_artifacts, source_artifacts=source_artifacts,
                  recipes=recipe_artifacts, compile_helper=helper_artifact,
                  source_qualification=qualification,
                  archive_source_qualification=source.qualify(inputs, headers, files, source_report,
                                                             {unit: path.read_bytes() for unit, path in paths.items()}),
                  archive_sha256=sha(archive.read_bytes()),
                  archive_members_verified=True, static_init='nabu_wifi_network_static_init',
                  runtime_registration='nabu_wifi_network_register_classes(g_kernel_kmod_info.name, static_init)',
                  linked_into_final_kernel=False, link_qualified=False, runtime_qualified=False)
    finish_report(result, report)
    report['artifact_qualification'] = qualify_artifacts(lambda path: (root / path).read_bytes(), report)
    reports = output / 'reports'
    reports.mkdir(parents=True, exist_ok=True)
    for unit, record in records.items():
        (reports / (Path(unit).stem + '.json')).write_text(json.dumps(record, indent=2) + '\n')
    (output / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--out', type=Path)
    arguments = parser.parse_args()
    built = build_kernel(arguments.root, arguments.out)
    print(json.dumps({key: value for key, value in built.items() if key != 'qualification'}, indent=2))
