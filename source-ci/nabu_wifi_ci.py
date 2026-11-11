"""Explicit full-source Wi-Fi control build, independent of GPU plugin jobs."""
import hashlib
import json
from pathlib import Path


def enable_wifi(upstream, device):
    kernel = Path(upstream) / 'scripts/unixnu/kernel.py'
    text = kernel.read_text(encoding='utf-8')
    marker = '    env = dict(os.environ)\n'
    if text.count(marker) != 1:
        raise ValueError('Expected the pinned kernel build environment')
    text = text.replace(marker, marker + "    env['NABU_WIFI_CONTROL'] = '1'\n", 1)
    kernel.write_text(text, encoding='utf-8')
    sources = sorted((Path(device) / 'platform').glob('NabuWifi*'))
    sources += sorted((Path(device) / 'ufs').glob('NabuWifi*.h'))
    return dict(build_gate='NABU_WIFI_CONTROL=1', boot_arg='nabu-wifi=1/2',
                input_only_mode=1, cold_start_mode=2, runtime_qualified=False,
                sources={path.relative_to(device).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                         for path in sources})


def qualify(read, candidate, intent):
    """Replay exact sources, compilation objects, and the linked entry point."""
    from nabu_idle_ci import _image, _branches, _function, require
    base = 'outputs/tree/build/native-ufs/'
    report = json.loads(read(base + 'build-report.json'))
    built = report.get('wifi_control', {})
    image = _image(candidate, 2)
    required = {'_nabu_wifi_start', '_nabu_wifi_firmware_load', '_nabu_wifi_firmware_file'}
    if intent is None:
        require(built.get('enabled') is False and not required & image['names'].keys(),
                'Wi-Fi code differs from the disabled build intent')
        return dict(compiled=False, runtime_qualified=False)
    require(built.get('enabled') is True and built.get('default') == 'off' and
            built.get('input_only_mode') == 1 and built.get('cold_start_mode') == 2,
            'Missing explicit Wi-Fi build contract')
    require(intent.get('runtime_qualified') is False and required <= image['names'].keys(),
            'Missing linked Wi-Fi definitions or invalid runtime claim')
    for original, expected in intent['sources'].items():
        compiled = original if original.startswith('platform/') else original.split('/', 1)[1]
        actual = hashlib.sha256(read(base + 'source/' + compiled)).hexdigest()
        require(actual == expected == built['sources'].get(compiled), 'Compiled Wi-Fi source differs from intent')
    scm_source = 'gpu/a640/NabuScmCall.h'
    scm_digest = hashlib.sha256(read(base + 'source/' + scm_source)).hexdigest()
    require(scm_digest == built['sources'].get(scm_source) ==
            hashlib.sha256(read('device/' + scm_source)).hexdigest(), 'Wi-Fi SCM helper source binding mismatch')
    expected_units = {'NabuWifiBoot.cpp', 'NabuWifiControl.cpp', 'NabuWifiMpss.cpp', 'NabuWifiPower.cpp'}
    require(set(built['objects']) == expected_units, 'Incomplete Wi-Fi translation unit set')
    for name, metadata in built['objects'].items():
        obj = read(base + name.removesuffix('.cpp') + '.o')
        require(hashlib.sha256(obj).hexdigest() == metadata['object_sha256'], 'Wi-Fi object digest mismatch')
        require(metadata['source_sha256'] == built['sources']['platform/' + name], 'Wi-Fi object/source binding mismatch')
        _image(obj, 1)
        command = json.loads(read(base + name.removesuffix('.cpp') + '-compile-command.json'))
        require(any(value.endswith('/source/platform/' + name) for value in command),
                'Wi-Fi compile command does not consume the bound source')
    roots = [name for name in image['names'] if 'NativeUfs9startRoot' in name]
    require(len(roots) == 1, 'Wi-Fi UFS root entry is ambiguous')
    _, _, branches = _branches(image, roots[0])
    require(any(target == '_nabu_wifi_start' for _, target in branches), 'Linked UFS entry does not start the Wi-Fi executor')
    smc = {}
    for name in image['names']:
        if 'NabuWifiMpss' in name and 'nativeSmc' in name:
            address, words, _ = _function(image, name)
            require(0xd4000003 in words, 'Native Wi-Fi SCM function lacks the real SMC instruction')
            smc[name] = hex(address)
    require(smc, 'Native Wi-Fi SMC adapter was not linked')
    return dict(compiled=True, sources=built['sources'], objects=built['objects'],
                final_definitions={name: hex(image['names'][name]) for name in sorted(required)},
                ufs_entry=roots[0], smc_functions=smc,
                candidate_sha256=hashlib.sha256(candidate).hexdigest(), runtime_qualified=False)


def qualify_candidate(upstream, candidate, prepared):
    tree = Path(upstream) / 'out/nabu'
    return qualify(lambda name: (tree / name.removeprefix('outputs/')).read_bytes(),
                   Path(candidate).read_bytes(), prepared.get('wifi_control'))
