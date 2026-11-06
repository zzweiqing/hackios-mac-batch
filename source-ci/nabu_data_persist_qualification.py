"""Bind Data persistence policy, independent GPT geometry, objects and final kernel."""
import ast
import hashlib
import json
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def literal(source, name):
    matches = [node.value for node in ast.parse(source.decode()).body
               if isinstance(node, ast.Assign) and len(node.targets) == 1 and
               isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    require(len(matches) == 1, 'Missing/duplicate Data source constant: ' + name)
    return ast.literal_eval(matches[0])


def qualify(read, candidate):
    from nabu_display_ci import symbols_and_segments
    from nabu_ui_watch_qualification import object_symbols
    generator = read('device/scripts/nabu_data_persist_source.py')
    source_id = sha(generator.replace(b'\r\n', b'\n'))
    contract = literal(generator, 'CONTRACT')
    require(contract == dict(version=1, mode_argument='nabu-data-persist', default_mode=0,
        tail_argument='nabu-data-tail-lba', reset_argument='sheng-data-reset',
        initialization_requires_reset=True, gpt_check_before_open=True, runtime_qualified=False),
        'Unexpected Data persistence policy')
    ram_prefix, ufs_prefix = 'outputs/tree/build/native-ram-block/', 'outputs/tree/build/native-ufs/'
    ram_source, ram_obj = read(ram_prefix+'NativeRamBlock.cpp'), read(ram_prefix+'NativeRamBlock.o')
    ram_report = json.loads(read(ram_prefix+'build-report.json'))
    policy = literal(generator, 'POLICY').replace('__SOURCE_ID__', source_id).encode()
    require(ram_source.count(policy) == 1 and
            literal(generator, 'OPEN_NEW').encode() in ram_source and
            literal(generator, 'UNLOCK_NEW').encode() in ram_source,
            'Actual RAM source lacks Data policy/open/log hooks')
    require(b'native_data_persist_gpt_after != 0' in ram_source and b'directFailed = true;' in ram_source,
            'Actual RAM source lacks post-open GPT failure gate')
    symbol = '_nabu_data_persist_allow_open'
    require(ram_report.get('optional_ufs_persistence') is True and
            ram_report.get('actual_source_sha256') == sha(ram_source) and
            ram_report.get('object_sha256') == sha(ram_obj) and
            ram_report.get('data_persistence') == dict(contract=contract, generator_sha256=sha(generator),
                embedded_source_identity=source_id, actual_source_sha256=sha(ram_source),
                symbol=symbol, runtime_qualified=False), 'RAM Data source/object/report mismatch')
    ufs_source, ufs_obj = read(ufs_prefix+'source/NativeUfs.cpp'), read(ufs_prefix+'NativeUfs.o')
    ufs_report = json.loads(read(ufs_prefix+'build-report.json'))
    applied = json.loads(read(ufs_prefix+'source/nabu-ufs-source.json'))
    patch = read('device/patches/nabu-nativeufs-board.patch')
    builder = read('device/scripts/build-nabu-ufs-root.py')
    require(applied.get('patch_sha256') == sha(patch) and
            ufs_report.get('source_files',{}).get('NativeUfs.cpp') == sha(ufs_source) and
            ufs_report.get('object_sha256') == sha(ufs_obj) and
            ufs_report.get('data_persistence_default') == 'off' and
            ufs_report.get('data_store_tail_arg') == 'nabu-data-tail-lba', 'UFS Data source/object/report mismatch')
    for name in ('DIRECT_FUNCTION', 'DIRECT_STORE_GEOMETRY'):
        require(ufs_source.count(literal(builder,name).encode()) == 1,
                'UFS direct root/store separation mismatch: ' + name)
    required_ufs = ('_native_ufs_store_mode', '_native_ufs_store_open', '_native_ufs_store_read',
                    '_native_ufs_store_write', '_native_ufs_store_sync', '_native_ufs_store_gpt_check')
    final, segments = symbols_and_segments(candidate)
    result = {}
    for kind, obj, names in (('ram',ram_obj,(symbol,)), ('ufs',ufs_obj,required_ufs)):
        definitions = object_symbols(obj, prefix='_nabu_data_' if kind=='ram' else '_native_ufs_store_')
        for name in names:
            require(name in definitions and name in final, 'Missing Data object/final definition: '+name)
            address = final[name]
            require(any(start <= address < start+backed and
                any(candidate[offset+address-start:offset+address-start+min(16,start+backed-address)])
                for start,_,offset,backed in segments), 'Unbacked Data code: '+name)
        result[kind] = dict(object_sha256=sha(obj), final_definitions={name:hex(final[name]) for name in names})
    stamp = ('NABUDATA_SOURCE_SHA256='+source_id).encode()
    require(stamp in ram_obj and stamp in candidate, 'Missing final Data policy source identity')
    return dict(contract=contract, embedded_source_identity=source_id,
                sources=dict(ram=sha(ram_source),ufs=sha(ufs_source),patch=sha(patch),builder=sha(builder)),
                objects=result, candidate_sha256=sha(candidate), runtime_qualified=False)


def qualify_candidate(upstream, device, candidate):
    work = Path(upstream) / 'out/nabu'

    def read(name):
        if name.startswith('device/'):
            return (Path(device)/name.removeprefix('device/')).read_bytes()
        if name.startswith('outputs/'):
            return (work/name.removeprefix('outputs/')).read_bytes()
        raise ValueError('Unexpected Data qualification path')

    return qualify(read, Path(candidate).read_bytes())
