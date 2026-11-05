"""Bind the optional LaunchServices mmap observer to captured source and machine code."""
import ast
import hashlib


SYMBOLS = ('_nabu_ui_watch_ls_mmap_enter', '_nabu_ui_watch_ls_mmap_exit')
SOURCE_PATH = 'outputs/tree/.cache/xnu-work/bsd/kern/kern_mman.c'
OBJECT_PATH = 'outputs/tree/build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/bsd/DEVELOPMENT/kern_mman.o'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def constants(generator):
    names = {'CONTRACT', 'HELPER', 'SIGNATURE', 'LOCAL', 'ENTER', 'SUCCESS', 'EXIT'}
    result = {}
    for node in ast.parse(generator.decode('utf-8')).body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            continue
        name = node.targets[0].id
        if name in names:
            require(name not in result, 'Duplicate mmap observer constant')
            result[name] = ast.literal_eval(node.value)
    require(set(result) == names and isinstance(result['CONTRACT'], dict) and
            all(isinstance(result[name], str) and result[name] for name in names - {'CONTRACT'}),
            'Malformed mmap observer constants')
    return result


def qualify(read, candidate):
    from nabu_gpu_ci import candidate_definitions, json_object, METAL_PROFILE
    from nabu_ui_watch_qualification import object_symbols
    capture = json_object(read('outputs/tree/build/nabu-log/source-report.json'))
    enabled = capture.get('ls_mmap_watch', False)
    require(type(enabled) is bool, 'mmap observer flag must be Boolean')
    if 'ls_mmap_watch' in capture:
        require(enabled == capture.get('ui_watch', False), 'mmap diagnostic build flag differs from UI build')
    if not enabled:
        require(b'NabuLSMap:' not in candidate and b'nabu-ls-mmap' not in candidate and
                not any(symbol.encode() in candidate for symbol in SYMBOLS),
                'Disabled kernel retains mmap observer')
        try:
            source = read(SOURCE_PATH)
        except KeyError:
            source = b''
        require(b'NABU_LS_MMAP_OBSERVER_VERSION' not in source, 'Disabled source retains mmap observer')
        return {'compiled': False, 'runtime_qualified': False}
    require(capture.get('ui_watch') is True, 'mmap observer requires the enabled UI diagnostic build')
    generator = read('device/scripts/nabu_ls_mmap_source.py')
    source = read(SOURCE_PATH)
    require(capture.get('ls_mmap_generator_sha256') == digest(generator) and
            capture.get('hooks', {}).get('bsd/kern/kern_mman.c') == digest(source),
            'mmap observer source binding mismatch')
    values = constants(generator)
    contract = values['CONTRACT']
    require(contract.get('version') == 1 and contract.get('trigger') == 'nabu-ls-mmap=1' and
            contract.get('max_calls') == 64 and contract.get('symbols') == list(SYMBOLS) and
            contract.get('user_memory_read') is False and contract.get('changes_mmap_result') is False,
            'Unexpected mmap observer contract')
    identity = digest(generator.replace(b'\r\n', b'\n'))
    stamp = ('NABULSMAP_SOURCE_SHA256=' + identity).encode()
    expected = (
        values['HELPER'].replace('__NABU_LS_MMAP_SOURCE_ID__', identity) + values['SIGNATURE'],
        values['LOCAL'] + '\tunsigned nabu_ls_mmap_call = 0;\n\tint nabu_ls_mmap_mapped = 0;\n'
                          '\tuser_addr_t nabu_ls_mmap_address = 0;\n',
        values['ENTER'] + '\t\tnabu_ls_mmap_call = nabu_ui_watch_ls_mmap_enter(p, uap, vp);\n',
        values['SUCCESS'] + '\t\tnabu_ls_mmap_mapped = 1;\n\t\tnabu_ls_mmap_address = *retval;\n',
        '\tnabu_ui_watch_ls_mmap_exit(nabu_ls_mmap_call, p, error, nabu_ls_mmap_mapped, nabu_ls_mmap_address);\n' + values['EXIT'],
    )
    require(all(source.count(fragment.encode()) == 1 for fragment in expected), 'mmap call-site hooks differ')
    obj = read(OBJECT_PATH)
    require(stamp in obj and stamp in candidate, 'mmap object or kernel comes from a different generator')
    definitions = object_symbols(obj)
    require(set(SYMBOLS) <= set(definitions), 'mmap object lacks real observer instructions')
    final, _ = candidate_definitions(candidate, METAL_PROFILE, SYMBOLS)
    require(b'NabuLSMap: enter' in candidate and b'NabuLSMap: exit' in candidate and b'nabu-ls-mmap' in candidate,
            'Final kernel lacks mmap observer strings')
    return dict(compiled=True, trigger=contract['trigger'], contract=contract,
                generator_sha256=digest(generator), source_sha256=digest(source),
                embedded_source_identity=identity,
                object_path=OBJECT_PATH, object_sha256=digest(obj),
                object_definitions={symbol: definitions[symbol] for symbol in SYMBOLS},
                final_definitions={symbol: final[symbol] for symbol in SYMBOLS}, runtime_qualified=False)
