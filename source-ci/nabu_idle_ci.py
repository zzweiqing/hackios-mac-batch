"""Bind the optional nabu shallow-idle source, cpu.o and final kernel."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import struct


TARGET = 'osfmk/arm64/cpu.c'
OBJECT = 'outputs/tree/build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/osfmk/DEVELOPMENT/cpu.o'
SOURCE = 'outputs/tree/.cache/xnu-work/' + TARGET
REPORT = 'outputs/tree/build/nabu-idle/source-report.json'


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(content):
    return hashlib.sha256(content).hexdigest()


def generator(path=None):
    if path is None:
        path = Path(__file__).with_name('nabu_idle_source.py')
        if not path.is_file():
            path = Path(__file__).resolve().parents[1] / 'nabu-device/scripts/nabu_idle_source.py'
    spec = importlib.util.spec_from_file_location('nabu_idle_bound_source', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def wire_build(text):
    require('nabu_idle_ci.py' not in text and 'cpu.o_CFLAGS_ADD' not in text,
            'Nabu idle build already wired or CPU flags conflict')
    edits = [
        ('for LATE_PATCH in ',
         'python3 scripts/nabu_idle_ci.py --root "$ROOT" --restore\nfor LATE_PATCH in '),
        ('python3 scripts/prepare-xnu-source.py\n',
         'export XNU_NABU_SHALLOW_IDLE=1\n'
         'python3 scripts/prepare-xnu-source.py\npython3 scripts/nabu_idle_ci.py --root "$ROOT" --enable\n'),
        ('EXTRA_MAKE_ARGS=()\n',
         'EXTRA_MAKE_ARGS=()\n'
         'EXTRA_MAKE_ARGS+=("cpu.o_CFLAGS_ADD=-DXNU_NABU_SHALLOW_IDLE=1")\n'
         'rm -f "$ROOT/build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/osfmk/DEVELOPMENT/cpu.o"\n'),
    ]
    for before, after in edits:
        require(text.count(before) == 1, 'Missing unique nabu idle build anchor: ' + before)
        text = text.replace(before, after, 1)
    return text


def prepare(upstream, device, enabled=False):
    require(type(enabled) is bool, 'Nabu idle enablement must be Boolean')
    policy = generator(Path(device) / 'scripts/nabu_idle_source.py')
    if enabled:
        build = Path(upstream) / 'scripts/build-xnu-4k-baseline.sh'
        build.write_text(wire_build(build.read_text(encoding='utf-8')), encoding='utf-8')
        shutil.copyfile(Path(__file__), Path(upstream) / 'scripts/nabu_idle_ci.py')
        shutil.copyfile(Path(policy.__file__), Path(upstream) / 'scripts/nabu_idle_source.py')
    return dict(enabled=enabled, contract=policy.CONTRACT,
                environment={policy.MACRO: '1' if enabled else '0'},
                generator_sha256=sha(Path(policy.__file__).read_bytes()),
                embedded_source_identity=policy.identity(), runtime_qualified=False)


def apply(root, enabled=False, restore=False):
    require(type(enabled) is bool and type(restore) is bool, 'Nabu idle flags must be Boolean')
    policy = generator()
    root = Path(root)
    path = root / '.cache/xnu-work' / TARGET
    before = path.read_bytes().decode('utf-8')
    after = policy.source(before, enabled=enabled, restore=restore)
    if before != after:
        path.write_bytes(after.encode('utf-8'))
    if not restore:
        directory = root / 'build/nabu-idle'
        directory.mkdir(parents=True, exist_ok=True)
        metadata = policy.metadata(after) if enabled else dict(enabled=False, compiled=False, runtime_qualified=False)
        (directory / 'source-report.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')


def _image(content, expected_kind):
    from nabu_ui_watch_qualification import object_symbols
    require(len(content) >= 32 and struct.unpack_from('<4I', content) ==
            (0xfeedfacf, 0x100000c, 0, expected_kind), 'Expected ordinary ARM64 Mach-O')
    if expected_kind == 1:
        object_symbols(content, prefix='')
    count, extent = struct.unpack_from('<II', content, 16)
    require(0 < count <= 65536 and extent <= len(content) - 32, 'Nabu idle command extent')
    cursor, table, sections = 32, None, []
    for _ in range(count):
        require(cursor + 8 <= 32 + extent, 'Nabu idle command header')
        command, size = struct.unpack_from('<II', content, cursor)
        require(size >= 8 and cursor + size <= 32 + extent, 'Nabu idle command bounds')
        if command == 0x19:
            require(size >= 72, 'Nabu idle segment bounds')
            number = struct.unpack_from('<I', content, cursor + 64)[0]
            require(72 + number * 80 <= size, 'Nabu idle section table')
            for index in range(number):
                position = cursor + 72 + index * 80
                address, length, offset, _, reloc, reloc_count, flags = struct.unpack_from('<QQ5I', content, position + 32)
                require(reloc + reloc_count * 8 <= len(content), 'Nabu idle relocation extent')
                sections.append((address, length, offset, reloc, reloc_count, flags))
        elif command == 2:
            require(size >= 24 and table is None, 'Nabu idle symbol table')
            table = struct.unpack_from('<4I', content, cursor + 8)
        cursor += size
    require(cursor == 32 + extent and table is not None, 'Nabu idle missing symbols')
    offset, number, strings, length = table
    require(offset + number * 16 <= len(content) and strings + length <= len(content),
            'Nabu idle symbol extent')
    symbols, names = [], {}
    for index in range(number):
        label, kind, section, _, address = struct.unpack_from('<IBBHQ', content, offset + index * 16)
        require(label < length, 'Nabu idle symbol name bounds')
        end = content.find(b'\0', strings + label, strings + length)
        require(end >= 0, 'Nabu idle unterminated symbol')
        name = content[strings + label:end].decode()
        symbols.append((name, address, kind))
        if not kind & 0xe0 and kind & 0xe == 0xe:
            require(0 < section <= len(sections), 'Nabu idle definition section')
            critical = name.startswith('_nabu_idle_') or name in (
                '_cpu_idle', '_ClearIdlePop', '_cpu_idle_exit', '_platform_cache_idle_enter')
            require(not critical or name not in names, 'Duplicate nabu idle contract symbol')
            names[name] = address
    return dict(content=content, kind=expected_kind, sections=sections, symbols=symbols, names=names)


def _function(image, name):
    require(name in image['names'], 'Missing idle function: ' + name)
    start = image['names'][name]
    candidates = [section for section in image['sections']
                  if section[0] <= start < section[0] + section[1] and section[5] & 0x80000000]
    require(len(candidates) == 1, 'Idle function is not unique backed instructions: ' + name)
    section = candidates[0]
    address, length, offset = section[:3]
    require(offset + length <= len(image['content']), 'Idle function unbacked')
    end = min([value for label, value, kind in image['symbols']
               if not kind & 0xe0 and kind & 0xe == 0xe and
               start < value < address + length and not re.fullmatch(r'_?ltmp\d+', label)] +
              [address + length])
    require(start % 4 == 0 and (end - start) % 4 == 0 and end > start, 'Idle function alignment')
    raw = image['content'][offset + start - address:offset + end - address]
    return start, struct.unpack('<%dI' % (len(raw) // 4), raw), section


def _branches(image, name):
    start, words, section = _function(image, name)
    relocations = {}
    if image['kind'] == 1:
        for index in range(section[4]):
            offset, relocation = struct.unpack_from('<II', image['content'], section[3] + index * 8)
            if relocation >> 28 != 2:
                continue
            require(relocation >> 27 & 1 and relocation >> 24 & 1 and relocation >> 25 & 3 == 2,
                    'Idle branch relocation type')
            require(offset % 4 == 0 and offset + 4 <= section[1], 'Idle branch relocation outside instructions')
            instruction = struct.unpack_from('<I', image['content'], section[2] + offset)[0]
            require(instruction & 0x7c000000 == 0x14000000, 'Idle branch relocation is not B/BL')
            symbol = relocation & 0xffffff
            require(symbol < len(image['symbols']), 'Idle branch symbol bounds')
            require(section[0] + offset not in relocations, 'Duplicate idle branch relocation')
            relocations[section[0] + offset] = image['symbols'][symbol][0]
    names = {address: label for label, address in image['names'].items()}
    branches = []
    for index, word in enumerate(words):
        if word & 0x7c000000 != 0x14000000:
            continue
        pc = start + index * 4
        immediate = word & 0x3ffffff
        if immediate & 0x2000000:
            immediate -= 0x4000000
        target = (pc + 4 * immediate) & 0xffffffffffffffff
        branches.append((pc, relocations.get(pc, names.get(target))))
    return start, words, branches


def check_code(content, kind):
    image = _image(content, kind)
    start, words, branches = _branches(image, '_cpu_idle')
    require(not any(target == '_platform_cache_idle_enter' for _, target in branches),
            'Idle caller still invokes generic cache maintenance')
    note = [address for address, target in branches if target == '_nabu_idle_note']
    wfi = [start + index * 4 for index, word in enumerate(words) if word == 0xd503207f]
    require(len(note) == 4 and len(wfi) == 1, 'Idle requires four notes and one ordinary WFI')
    require(all(words[(address - start) // 4] & 0xfc000000 == 0x94000000 for address in note),
            'Idle observer sites must call with BL')
    position = (wfi[0] - start) // 4
    require(position > 0 and words[position - 1] == 0xd5033f9f, 'Idle WFI lost its immediate DSB SY')
    require(note[0] < note[1] < note[2] < wfi[0] < note[3], 'Idle notes do not bracket WFI')
    for name in ('_ClearIdlePop', '_cpu_idle_exit'):
        require(any(address > note[3] and target == name for address, target in branches),
                'Idle exit call missing after WFI: ' + name)
    for name in ('_nabu_idle_note', '_nabu_idle_snapshot'):
        helper_start, helper_words, helper_branches = _branches(image, name)
        require(not any(word & 0xfc000000 == 0x94000000 or
                        word & 0xfffffc1f in (0xd61f0000, 0xd63f0000)
                        for word in helper_words), 'Idle observer helper contains BL/BLR: ' + name)
        for index, word in enumerate(helper_words):
            if word & 0xfc000000 == 0x14000000:
                immediate = word & 0x3ffffff
                if immediate & 0x2000000:
                    immediate -= 0x4000000
                target = (helper_start + index * 4 + immediate * 4) & 0xffffffffffffffff
                require(helper_start <= target < helper_start + len(helper_words) * 4,
                        'Idle observer helper branches outside its body: ' + name)
        require(not any(target is not None and target != name for _, target in helper_branches),
                'Idle observer helper calls another function: ' + name)
    for name in generator().CONTRACT['symbols']:
        require(name in image['names'], 'Idle final definition missing: ' + name)
    return dict(cpu_idle=hex(start), note_calls=[hex(address) for address in note],
                wfi=hex(wfi[0]), dsb_sy_immediately_before_wfi=True,
                generic_cache_call_absent=True)


def qualify_writer(read, candidate):
    root = 'outputs/tree/build/native-ufs/'
    command_bytes = read(root + 'compile-command.json')
    command = json.loads(command_bytes)
    require([argument for argument in command if argument.startswith('-DXNU_NABU_SHALLOW_IDLE=')] ==
            ['-DXNU_NABU_SHALLOW_IDLE=1'], 'Idle writer compile flag mismatch')
    content = read(root + 'NativeUfs.o')
    image = _image(content, 1)
    callers = [name for name in image['names']
               if name.startswith(('__ZL13nabuLogThread', '__ZL19nabuLogEarlySmpPoll'))]
    require(callers, 'Idle writer has no ordinary thread or SMP poll function')
    calls = [(name, address) for name in callers
             for address, target in _branches(image, name)[2] if target == '_nabu_idle_snapshot']
    require(calls, 'Idle snapshot is not called from the ordinary writer')
    final = _image(candidate, 2)
    final_callers = [name for name in final['names']
                     if name.startswith(('__ZL13nabuLogThread', '__ZL19nabuLogEarlySmpPoll'))]
    final_calls = [(name, address) for name in final_callers
                   for address, target in _branches(final, name)[2] if target == '_nabu_idle_snapshot']
    require(final_calls, 'Final kernel ordinary writer does not call the idle snapshot')
    return dict(object_sha256=sha(content), recipe_sha256=sha(command_bytes),
                snapshot_calls=[dict(caller=name, pc=hex(address)) for name, address in calls],
                final_snapshot_calls=[dict(caller=name, pc=hex(address)) for name, address in final_calls])


def qualify(read, candidate):
    policy = generator()
    preparation = json.loads(read('prepare-report.json'))
    prepared = preparation.get('nabu_idle', {})
    enabled = prepared.get('enabled', False)
    require(type(enabled) is bool, 'Nabu idle preparation flag must be Boolean')
    final = _image(candidate, 2)
    if not enabled:
        require(not any(name.startswith('_nabu_idle_') for name in final['names']) and
                b'NABUIDLE_SOURCE_SHA256=' not in candidate, 'Disabled kernel contains nabu idle helpers')
        return dict(enabled=False, compiled=False, runtime_qualified=False)
    bound = read('device/scripts/nabu_idle_source.py')
    require(bound.replace(b'\r\n', b'\n') == Path(policy.__file__).read_bytes().replace(b'\r\n', b'\n'),
            'Nabu idle generator changed')
    require(prepared == dict(enabled=True, contract=policy.CONTRACT,
                             environment={policy.MACRO: '1'},
                             generator_sha256=sha(bound), embedded_source_identity=policy.identity(),
                             runtime_qualified=False), 'Nabu idle preparation binding mismatch')
    source = read(SOURCE)
    metadata = policy.metadata(source.decode())
    require(json.loads(read(REPORT)) == metadata, 'Nabu idle actual source report mismatch')
    obj, recipe_bytes = read(OBJECT), read(OBJECT + '.json')
    recipe = json.loads(recipe_bytes.decode().strip().rstrip(','))
    arguments = recipe['arguments']
    definitions = []
    for index, argument in enumerate(arguments):
        if argument == '-D':
            require(index + 1 < len(arguments), 'Nabu idle truncated definition')
            definitions.append(arguments[index + 1])
        elif argument.startswith('-D'):
            definitions.append(argument[2:])
    require([value for value in definitions if value.startswith(policy.MACRO + '=')] ==
            [policy.MACRO + '=1'], 'Nabu idle compile flag mismatch')
    require(recipe['file'].endswith('/.cache/xnu-work/' + TARGET) and recipe['file'] in arguments and
            Path(recipe['output']).name == 'cpu.o' and '-o' in arguments and
            arguments.index('-o') + 1 < len(arguments) and
            Path(arguments[arguments.index('-o') + 1]).name == 'cpu.o', 'Nabu idle recipe target mismatch')
    stamp = ('NABUIDLE_SOURCE_SHA256=' + policy.identity()).encode()
    require(stamp in obj and stamp in candidate, 'Nabu idle object/final source stamp mismatch')
    writer = qualify_writer(read, candidate) if preparation.get('log_capture') else None
    return dict(**metadata, object_sha256=sha(obj), recipe_sha256=sha(recipe_bytes),
                candidate_sha256=sha(candidate), object_code=check_code(obj, 1),
                final_code=check_code(candidate, 2), writer_poll=writer)


def qualify_candidate(upstream, device, candidate, prepared):
    work = Path(upstream) / 'out/nabu'

    def read(name):
        if name.startswith('device/'):
            return (Path(device) / name.removeprefix('device/')).read_bytes()
        if name.startswith('outputs/'):
            return (work / name.removeprefix('outputs/')).read_bytes()
        if name == 'prepare-report.json':
            return json.dumps(prepared).encode()
        raise ValueError('Unexpected nabu idle qualification input')

    return qualify(read, Path(candidate).read_bytes())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    switches = parser.add_mutually_exclusive_group()
    switches.add_argument('--enable', action='store_true')
    switches.add_argument('--restore', action='store_true')
    options = parser.parse_args()
    apply(options.root, enabled=options.enable, restore=options.restore)
