"""Bind the optional nabu GPIO9 sampler to its compiled UFS entry."""
import hashlib
import json
from pathlib import Path


def enable_hall(upstream, device):
    kernel = Path(upstream) / 'scripts/unixnu/kernel.py'
    text = kernel.read_text(encoding='utf-8')
    marker = '    env = dict(os.environ)\n'
    if text.count(marker) != 1:
        raise ValueError('Expected the pinned kernel build environment')
    kernel.write_text(text.replace(marker, marker + "    env['NABU_HALL_SENSOR'] = '1'\n", 1),
                      encoding='utf-8')
    sources = sorted((Path(device) / 'platform').glob('NabuHall*'))
    return dict(build_gate='NABU_HALL_SENSOR=1', boot_arg='nabu-hall=1',
                default='off', runtime_qualified=False, system_hes_qualified=False,
                sources={path.relative_to(device).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                         for path in sources})


def qualify(read, candidate, intent):
    from nabu_idle_ci import _image, _function, require
    base = 'outputs/tree/build/native-ufs/'
    report = json.loads(read(base + 'build-report.json')).get('hall_sensor', {})
    image = _image(candidate, 2)
    name = '_nabu_hall_start'
    if intent is None:
        require(not report.get('enabled', False) and name not in image['names'],
                'Hall sampler differs from the disabled build intent')
        return dict(compiled=False, runtime_qualified=False)
    require(report.get('enabled') is True and report.get('default') == 'off' and
            intent.get('runtime_qualified') is False and name in image['names'],
            'Missing explicit compiled Hall contract')
    required_sources = {'platform/NabuHall.cpp', 'platform/NabuHall.h', 'platform/NabuHallResources.h'}
    require(required_sources <= intent['sources'].keys(), 'Hall intent lacks bound source/resource headers')
    for path, expected in intent['sources'].items():
        actual = hashlib.sha256(read(base + 'source/' + path)).hexdigest()
        require(actual == expected == report['sources'].get(path), 'Hall compiled source differs from intent')
    metadata = report['objects'].get('NabuHall.cpp', {})
    obj = read(base + 'NabuHall.o')
    require(set(report['objects']) == {'NabuHall.cpp'} and
            hashlib.sha256(obj).hexdigest() == metadata.get('object_sha256') and
            metadata.get('source_sha256') == report['sources']['platform/NabuHall.cpp'],
            'Hall object/source binding mismatch')
    _image(obj, 1)
    command = json.loads(read(base + 'NabuHall-compile-command.json'))
    require('-DXNU_NABU_HALL=1' in command and
            any(value.endswith('/source/platform/NabuHall.cpp') for value in command),
            'Hall command does not compile the enabled bound source')
    start, words, _ = _function(image, '__ZN9NativeUfs9startRootEP9IOService')
    calls = []
    for index, word in enumerate(words):
        if word & 0xfc000000 != 0x94000000:
            continue
        displacement = word & 0x3ffffff
        if displacement & 0x2000000:
            displacement -= 0x4000000
        calls.append((start + index * 4 + displacement * 4) & 0xffffffffffffffff)
    require(image['names'][name] in calls, 'UFS entry does not start the Hall sampler')
    return dict(compiled=True, sources=report['sources'], objects=report['objects'],
                final_definition=hex(image['names'][name]),
                candidate_sha256=hashlib.sha256(candidate).hexdigest(),
                runtime_qualified=False, system_hes_qualified=False)


def qualify_candidate(upstream, device, candidate, prepared):
    tree = Path(upstream) / 'out/nabu'
    return qualify(lambda name: (tree / name.removeprefix('outputs/')).read_bytes(),
                   Path(candidate).read_bytes(), prepared.get('hall_sensor'))
