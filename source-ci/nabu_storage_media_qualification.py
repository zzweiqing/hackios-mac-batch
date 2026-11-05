"""Replay source, object, and final-kernel binding for solid-state media publication."""
import ast
import hashlib
import json
from pathlib import Path

TRANSPORTS = {
    'ram': ('outputs/tree/build/native-ram-block/', 'NativeRamBlock.cpp', 'NativeRamBlock.o'),
    'ufs': ('outputs/tree/build/native-ufs/', 'source/NativeUfs.cpp', 'NativeUfs.o'),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def qualify(read, candidate):
    from nabu_display_ci import symbols_and_segments
    from nabu_ui_watch_qualification import object_symbols
    generator = read('device/scripts/nabu_storage_media.py')
    constants = {}
    for node in ast.parse(generator.decode()).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in ('CONTRACT', 'HELPER', 'ANCHORS'):
                require(name not in constants, 'Duplicate storage media constant')
                constants[name] = ast.literal_eval(node.value)
    require(set(constants) == {'CONTRACT', 'HELPER', 'ANCHORS'}, 'Missing storage media constants')
    contract = constants['CONTRACT']
    require(contract == dict(version=1, property='Device Characteristics', key='Medium Type', value='Solid State',
                             before_parent_start=True, preserves_existing_characteristics=True,
                             changes_write_protection=False, changes_persistence=False), 'Unexpected storage media contract')
    identity = sha(generator.replace(b'\r\n', b'\n'))
    stamp = ('NABUMEDIA_SOURCE_SHA256=' + identity).encode()
    require(stamp in candidate, 'Final kernel lacks storage media source identity')
    final, segments = symbols_and_segments(candidate)
    results = {}
    for kind, (prefix, source_name, object_name) in TRANSPORTS.items():
        source, obj = read(prefix + source_name), read(prefix + object_name)
        report = json.loads(read(prefix + 'build-report.json'))
        metadata = report.get('solid_state_media', {})
        helper = constants['HELPER'].replace('__NABU_KIND__', kind).replace('__NABU_SOURCE_ID__', identity)
        anchor = constants['ANCHORS'][kind]
        call = f'  if (!nabu_{kind}_publish_solid_state(this)) return false;\n'
        require(source.count((helper + anchor + call).encode()) == 1, 'Storage start hook mismatch: ' + kind)
        symbol = f'_nabu_{kind}_publish_solid_state'
        require(metadata == dict(contract=contract, kind=kind, generator_sha256=sha(generator),
                                 embedded_source_identity=identity, symbol=symbol,
                                 actual_source_sha256=sha(source), runtime_qualified=False), 'Storage build report mismatch: ' + kind)
        require(report.get('object_sha256') == sha(obj) and stamp in obj, 'Storage object identity mismatch: ' + kind)
        definitions = object_symbols(obj, prefix='_nabu_' + kind + '_publish_')
        require(symbol in definitions and symbol in final, 'Missing real media publication code: ' + kind)
        address = final[symbol]
        require(any(start <= address < start + backed and
                    any(candidate[offset + address - start:offset + address - start + min(16, start + backed - address)])
                    for start, _, offset, backed in segments), 'Unbacked media publication code: ' + kind)
        results[kind] = dict(source_sha256=sha(source), object_sha256=sha(obj), symbol=symbol,
                             object_definition=definitions[symbol], final_definition=hex(address))
    return dict(contract=contract, generator_sha256=sha(generator), embedded_source_identity=identity,
                transports=results, runtime_qualified=False)


def qualify_candidate(upstream, device, candidate):
    work = Path(upstream) / 'out/nabu'

    def read(name):
        if name.startswith('device/'):
            return (Path(device) / name.removeprefix('device/')).read_bytes()
        if name.startswith('outputs/'):
            return (work / name.removeprefix('outputs/')).read_bytes()
        raise ValueError('Unexpected storage media input')

    return qualify(read, Path(candidate).read_bytes())
