#!/usr/bin/env python3
"""Build the fixed 24-object ath10k and 23-object SAE set on macOS."""
import ast
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import urllib.request

MANIFEST_SHA = '9e4fa40b65231951baf36aa8c0f4b60004fa299c6ff019f2602106a65a6b5abb'
GENERATOR_SHA = 'bc8b25a6f85bc423b0cab471e26c45f5ea9be4a70f6dfa84704398ce437330a9'
FUNCTIONS = {'run', 'archive', 'extract', 'compile_all', 'sae_build', 'driver_build'}
REMAP = {'lx_' + name: 'nabu_ath10k_driver_' + name
         for name in ('prepare', 'start', 'stop', 'transmit')}
REMAP.update({'lx_os_' + name: 'nabu_ath10k_os_' + name for name in (
    'radio_memory', 'map_registers', 'print', 'tell', 'option', 'firmware',
    'rproc_boot', 'radio_powered', 'radio_address', 'irq_attach', 'irq_enable',
    'irq_disable', 'irq_detach_all', 'station', 'station_lost', 'station_fatal',
    'net_attach', 'net_link', 'net_input')})


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def manifest():
    device = Path(os.environ.get('UNIXNU_DEVICE', Path(__file__).resolve().parents[1]))
    path = device / 'configs/nabu-wifi-ath10k.json'
    content = path.read_bytes()
    require(sha(content) == MANIFEST_SHA, 'ath10k fixed manifest drift')
    return json.loads(content)


def inside(root, path):
    root, path = Path(root).resolve(strict=True), Path(path).absolute()
    require(path.resolve().is_relative_to(root) and path != root, 'ath10k output escaped build root')
    require(not any(parent.is_symlink() for parent in (path, *path.parents)
                    if parent == root or root in parent.parents), 'ath10k path follows a symlink')
    return path


def write(root, path, content):
    path = inside(root, path)
    if path.exists():
        require(path.is_file() and path.read_bytes() == content, 'ath10k existing input drift: ' + str(path))
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(content)


def acquire(root, output, cfg, inputs=None):
    records = []
    for origin, files in (('reference', cfg['reference_files']), ('donor', cfg['donor_patches'])):
        repository = cfg['reference_repository' if origin == 'reference' else 'donor_repository']
        revision = cfg['reference_commit' if origin == 'reference' else 'donor_commit']
        for path, expected in files.items():
            digest = expected['sha256'] if isinstance(expected, dict) else expected
            records.append((origin, repository, revision, path, digest, expected))

    def fetch(record):
        origin, repository, revision, path, digest, expected = record
        local = output / 'inputs' / origin / path
        if local.exists():
            content = local.read_bytes()
        elif inputs is not None:
            folder = 'helium' if origin == 'reference' else 'donor'
            content = (Path(inputs) / folder / path).read_bytes()
        else:
            url = f'https://raw.githubusercontent.com/{repository}/{revision}/{path}'
            with urllib.request.urlopen(url, timeout=90) as stream:
                content = stream.read()
        require(sha(content) == digest, 'ath10k pinned input digest mismatch: ' + path)
        if isinstance(expected, dict):
            git_blob = hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest()
            require(len(content) == expected['bytes'] and git_blob == expected['git_blob'],
                    'ath10k fixed Git blob mismatch: ' + path)
        return origin, path, content

    with ThreadPoolExecutor(max_workers=8) as pool:
        fetched = list(pool.map(fetch, records))
    for origin, path, content in fetched:
        write(root, output / 'inputs' / origin / path, content)
    return fetched


def retarget_generator(content):
    require(sha(content) == GENERATOR_SHA, 'ath10k upstream generator drift')
    text = content.decode()
    sdk = "sdk = Path(os.environ.get('THEOS', str(Path.home() / 'theos'))) / 'sdks/iPhoneOS16.5.sdk'"
    require(text.count(sdk) == 1 and text.count('arm64-apple-ios16.5') == 2,
            'ath10k SDK/deployment anchor drift')
    text = text.replace(sdk, "sdk = Path(os.environ['NABU_WIFI_SDK'])")
    return text.replace('arm64-apple-ios16.5', 'arm64-apple-ios17.0').encode()


def relocate_patch(files, content):
    """Relocate fixed hunks after the previous patch using unique exact context."""
    lines = content.decode().splitlines(keepends=True)
    path = lines[0][6:].rstrip('\n')
    require(lines[0] == '--- a/' + path + '\n' and lines[1] == '+++ b/' + path + '\n',
            'ath10k reference patch target drift')
    original = files[path].splitlines(keepends=True)
    updated, index, delta = lines[:2], 2, 0
    while index < len(lines):
        match = re.fullmatch(r'@@ -\d+,(\d+) \+\d+,(\d+) @@([^\n]*)\n', lines[index])
        require(match is not None, 'ath10k reference hunk format drift')
        old_count, new_count = int(match[1]), int(match[2])
        index += 1
        begin = index
        while index < len(lines) and not lines[index].startswith('@@ '):
            require(lines[index][:1] in (' ', '-', '+'), 'ath10k reference patch body drift')
            index += 1
        body = lines[begin:index]
        context = [line[1:] for line in body if line[0] in ' -']
        positions = [at for at in range(len(original) - len(context) + 1)
                     if original[at:at + len(context)] == context]
        require(len(positions) == 1, 'ath10k reference patch lacks unique exact context')
        start = positions[0] + 1
        updated.append(f'@@ -{start},{old_count} +{start + delta},{new_count} @@{match[3]}\n')
        updated.extend(body)
        delta += new_count - old_count
    return ''.join(updated).encode()


def prepare_reference(fetched, headers):
    require(set(headers) == {'lx', 'qmi', 'sta'}, 'ath10k shared header set drift')
    reference = {path: content.decode() for origin, path, content in fetched if origin == 'reference'}
    patches = {path: content for origin, path, content in fetched if origin == 'donor'}
    scripts = Path(os.environ.get('NABU_WIFI_CI_SCRIPTS', Path(__file__).resolve().parents[2] / 'scripts'))
    sys.path.insert(0, str(scripts))
    from nabu_wifi_network_source import _patch
    before = {path: sha(content.encode()) for path, content in reference.items()}
    relocated = {}
    for name in ('station-start-rollback.patch', 'station-association.patch'):
        patch = relocate_patch(reference, patches['patches/nabu-ath10k/' + name])
        reference = _patch(reference, patch)
        relocated[name] = patch
    for name, content in headers.items():
        reference[f'xnu/files/bsd/sys/hakios.{name}.h'] = content.decode()
    reference['tools/mk-ath10k.py'] = retarget_generator(
        reference['tools/mk-ath10k.py'].encode()).decode()
    for name in ('macho-pcpu-globl.patch', 'xcode-counted-by.patch'):
        reference['wifi/lx/patches/' + name] = patches['patches/nabu-ath10k/' + name].decode()
    return reference, before, relocated


def prepare(root, out, headers, inputs=None):
    root = Path(root).resolve(strict=True)
    output = inside(root, out)
    cfg = manifest()
    fetched = acquire(root, output, cfg, inputs)
    header_root = Path(headers).resolve(strict=True)
    network = json.loads((header_root.parent.parent / 'source-report.json').read_text())
    shared_headers = {}
    for name in ('lx', 'qmi', 'sta'):
        path = f'bsd/sys/hakios.{name}.h'
        content = (header_root / f'sys/hakios.{name}.h').read_bytes()
        require(sha(content) == network['outputs'][path], 'ath10k network header source drift')
        shared_headers[name] = content
    reference, before, relocated = prepare_reference(fetched, shared_headers)
    for path, content in reference.items():
        write(root, output / 'reference' / path, content.encode())
    for name, patch in relocated.items():
        write(root, output / 'prepared-patches' / name, patch)
    result = dict(manifest_sha256=MANIFEST_SHA, generator_before_sha256=GENERATOR_SHA,
                  generator_after_sha256=sha(reference['tools/mk-ath10k.py'].encode()),
                  sources=cfg['sources'], reference_commit=cfg['reference_commit'],
                  inputs={origin + '/' + path: sha(content) for origin, path, content in fetched},
                  original_reference=before,
                  prepared_reference={path: sha(content.encode()) for path, content in reference.items()},
                  network_headers={name: network['outputs'][f'bsd/sys/hakios.{name}.h']
                                   for name in ('lx', 'qmi', 'sta')},
                  deployment='arm64-apple-ios17.0', driver_objects=24, sae_objects=23,
                  compiled=False, hardware_tested=False)
    write(root, output / 'source-report.json', (json.dumps(result, indent=2) + '\n').encode())
    return result


def load_functions(output, cfg):
    source = (output / 'reference/tools/mk-ath10k.py').read_bytes()
    tree = ast.parse(source)
    selected = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom)) or
                isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS]
    require({node.name for node in selected if isinstance(node, ast.FunctionDef)} == FUNCTIONS,
            'ath10k upstream function set drift')
    reference = output / 'reference'
    namespace = dict(ROOT=reference, B=output / 'build', W=reference / 'wifi/lx',
                     CACHE=output / 'build/cache',
                     SOURCES={name: (value['filename'], value['url'], value['sha256'])
                              for name, value in cfg['sources'].items()})
    exec(compile(ast.Module(body=selected, type_ignores=[]), '<pinned-ath10k-functions>', 'exec'), namespace)
    original_archive, original_extract = namespace['archive'], namespace['extract']
    verified = {}

    def archive(name):
        require(name in cfg['sources'], 'ath10k undeclared source archive')
        if name not in verified:
            verified[name] = original_archive(name)
        return verified[name]

    def extract(name, strip=1, members=(), patches=()):
        require(name in cfg['sources'], 'ath10k undeclared extraction')
        inside(output, output / 'build' / name)
        if name == 'linux':
            patches = (*patches, output / 'inputs/donor/patches/nabu-ath10k/ready-only-qmi.patch')
        return original_extract(name, strip, members, patches)

    namespace.update(archive=archive, extract=extract)
    return namespace


def run(command, output, name):
    (output / (name + '-command.json')).write_text(json.dumps(list(map(str, command)), indent=2) + '\n')
    result = subprocess.run(list(map(str, command)), capture_output=True)
    (output / (name + '.log')).write_bytes(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(name + ': ' + result.stderr.decode(errors='replace')[-6000:])
    return result.stdout


def object_image(content):
    from nabu_idle_ci import _image
    import struct
    image = _image(content, 1)
    offset, deployment = 32, None
    for _ in range(struct.unpack_from('<I', content, 16)[0]):
        command, size = struct.unpack_from('<II', content, offset)
        if command == 0x32:
            deployment = struct.unpack_from('<II', content, offset + 8)
        offset += size
    require(deployment == (2, 0x110000), 'ath10k object deployment differs from iOS17')
    return image


def symbols(content):
    definitions, undefined, common = set(), set(), set()
    for line in content.decode().splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        name, kind = fields[:2]
        if kind == 'U':
            undefined.add(name)
        else:
            definitions.add(name)
        if kind == 'C':
            common.add(name)
    return definitions, undefined, common


def external_contract(definitions, undefined, common):
    require(not common, 'ath10k contains unallocated COMMON storage')
    external = sorted(undefined - definitions)
    libc = set('memcmp memcpy memmove memset strcmp strncmp strlen strnlen strchr strrchr '
               'strlcpy strlcat bzero snprintf vsnprintf __stack_chk_fail __stack_chk_guard'.split())
    libc = {name.lstrip('_') for name in libc}
    unexpected = [name for name in external if name.lstrip('_') not in libc and not name.startswith(
        ('_lx_os_', '_nabu_ath10k_os_', '_qmi_', '_hakios_qmi_', 'section$'))]
    require(not unexpected, 'ath10k unimplemented imports: ' + ', '.join(unexpected))
    exports = {'_nabu_ath10k_driver_' + name for name in ('prepare', 'start', 'stop', 'transmit')}
    require(exports <= definitions, 'ath10k driver entry point set is incomplete')
    for name in ('station', 'station_lost', 'station_fatal', 'net_attach', 'net_link', 'net_input'):
        require('_nabu_ath10k_os_' + name in external and '_lx_os_' + name not in external,
                'ath10k native station/network hook drift: ' + name)
    return external, exports


def build_kernel(root, out=None, *, headers, inputs=None):
    require(sys.platform == 'darwin', 'Apple compiler/backend builds require macOS Actions')
    root = Path(root).resolve(strict=True)
    from nabu_wifi_network_ci import dependency_paths, full_dependency_command
    output = inside(root, out or root / 'build/nabu-wifi-ath10k')
    intent = prepare(root, output, headers, inputs)
    cfg = manifest()
    namespace = load_functions(output, cfg)
    namespace['CACHE'].mkdir(parents=True, exist_ok=True)
    compiler = run(['xcrun', '--sdk', 'iphoneos', '--find', 'clang'], output, 'compiler-path').decode().strip()
    sdk = run(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], output, 'sdk-path').decode().strip()
    sdk_version = run(['xcrun', '--sdk', 'iphoneos', '--show-sdk-version'], output, 'sdk-version').decode().strip()
    environment = {name: os.environ.get(name) for name in ('CC', 'NABU_WIFI_SDK')}
    os.environ['CC'] = shlex.join([compiler, '-fno-common', *['-D' + key + '=' + value for key, value in REMAP.items()]])
    os.environ['NABU_WIFI_SDK'] = sdk
    try:
        driver = namespace['driver_build']()
        crypto, _ = namespace['sae_build'](False)
    finally:
        for name, value in environment.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    require(len(driver) == 24 and len(crypto) == 23, 'ath10k captured object set drift')
    licenses = {}
    linux_archive = namespace['archive']('linux')
    for name in ('COPYING', 'LICENSES/preferred/GPL-2.0'):
        data = run(['tar', '-xOf', linux_archive, 'linux-7.0.14/' + name], output,
                   'linux-license-' + Path(name).name)
        target = output / 'licenses/linux' / Path(name).name
        write(root, target, data)
        licenses[target.relative_to(root).as_posix()] = sha(data)
    for name, license_name in (('freebsd', 'COPYRIGHT'), ('hostap', 'COPYING'), ('mbedtls', 'LICENSE')):
        original = output / 'build' / name / license_name
        require(original.is_file(), 'ath10k source license is unavailable: ' + name)
        data = original.read_bytes()
        target = output / 'licenses' / name / license_name
        write(root, target, data)
        licenses[target.relative_to(root).as_posix()] = sha(data)
    objects = [*driver, *crypto]
    records, dependencies = {}, {}
    definitions, undefined, common = set(), set(), set()
    for index, path in enumerate(objects):
        content = path.read_bytes()
        object_image(content)
        defined, imports, tentative = symbols(run(['xcrun', 'nm', '-g', '-P', path], output, f'object-{index}-symbols'))
        definitions.update(defined)
        undefined.update(imports)
        common.update(tentative)
        command = shlex.split(path.with_suffix('.command').read_text())
        source = Path(command[command.index('-c') + 1])
        require(source.is_file(), 'ath10k compiler source is unavailable')
        full_dependency = path.with_suffix('.full.d')
        dependency_command = full_dependency_command(command, full_dependency, path)
        run(dependency_command, output, f'object-{index}-dependencies')
        used_paths = dependency_paths(full_dependency.read_bytes(), root)
        local_paths = dependency_paths(Path(str(path) + '.d').read_bytes(), root)
        require(set(local_paths) <= set(used_paths) and source.resolve() in used_paths,
                'ath10k actual compiler dependency closure drift')
        used = [str(original) for original in used_paths]
        for original in used_paths:
            require(original.is_file(), 'ath10k compile dependency is unavailable')
            if str(original) in dependencies:
                continue
            data = original.read_bytes()
            target = output / 'dependencies' / sha(str(original).encode())[:16] / original.name
            write(root, target, data)
            dependencies[str(original)] = dict(path=target.relative_to(root).as_posix(), sha256=sha(data))
        records[path.relative_to(root).as_posix()] = dict(sha256=sha(content),
            source=source.relative_to(root).as_posix(), source_sha256=sha(source.read_bytes()),
            command=command, dependencies=used)
    external, exports = external_contract(definitions, undefined, common)
    exported = output / 'exports.txt'
    write(root, exported, ('\n'.join(sorted(exports)) + '\n').encode())
    combined = output / 'all.o'
    run(['xcrun', 'ld', '-r', '-arch', 'arm64', '-platform_version', 'ios', '17.0', sdk_version,
         '-exported_symbols_list', exported, *objects, '-o', combined], output, 'relocatable-link')
    object_image(combined.read_bytes())
    linked_defs, linked_imports, linked_common = symbols(run(['xcrun', 'nm', '-g', '-P', combined], output, 'linked-symbols'))
    require(linked_defs == exports and not linked_common, 'ath10k relocatable export/storage drift')
    require(linked_imports == set(external), 'ath10k relocatable import contract drift')
    archive = output / 'libNabuAth10k.a'
    run(['xcrun', 'ar', 'rcs', archive, combined], output, 'archive')
    stored = run(['xcrun', 'ar', 'p', archive, 'all.o'], output, 'archive-member')
    require(stored == combined.read_bytes(), 'ath10k archive member drift')
    result = dict(archive=archive.relative_to(root).as_posix(), objects=[combined.relative_to(root).as_posix()],
                  header_dir=Path(headers).relative_to(root).as_posix(),
                  report=(output / 'build-report.json').relative_to(root).as_posix())
    report = dict(version=1, build_root=str(root), intent=intent, build_result=dict(result), objects=records,
                  dependencies=dependencies, imports=external, exports=sorted(exports),
                  licenses=licenses,
                  relocatable_sha256=sha(combined.read_bytes()), archive_sha256=sha(archive.read_bytes()),
                  compiler=compiler, sdk_path=sdk, sdk_version=sdk_version,
                  symbol_remaps=REMAP, driver_objects=24, sae_objects=23,
                  compiled=True, archive_members_verified=True,
                  link_qualified=False, runtime_qualified=False, hardware_tested=False)
    (output / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n')
    return result


def qualify_artifacts(read, metadata):
    """Replay collected sources, objects and dependencies using relative paths."""
    from pathlib import PurePosixPath
    from nabu_gpu_ci import archive_members
    from nabu_wifi_network_ci import inspect_object
    require(metadata['version'] == 1 and metadata['compiled'] is True and
            metadata['driver_objects'] == 24 and metadata['sae_objects'] == 23,
            'ath10k build receipt contract drift')
    cfg = manifest()
    result = metadata['build_result']
    output = PurePosixPath(result['archive']).parent

    def get(path):
        path = PurePosixPath(path)
        require(not path.is_absolute() and '..' not in path.parts, 'ath10k artifact path escape')
        return read(path.as_posix())

    intent = metadata['intent']
    require(len(metadata['licenses']) == 5, 'ath10k source license set drift')
    for path, expected in metadata['licenses'].items():
        require(sha(get(path)) == expected, 'ath10k archived source license drift')
    require(intent['manifest_sha256'] == MANIFEST_SHA and intent['generator_before_sha256'] == GENERATOR_SHA,
            'ath10k fixed source intent drift')
    fetched = []
    for origin, expected_files in (('reference', cfg['reference_files']), ('donor', cfg['donor_patches'])):
        for path, pin in expected_files.items():
            content = get(output / 'inputs' / origin / path)
            expected = pin['sha256'] if isinstance(pin, dict) else pin
            require(sha(content) == expected == intent['inputs'][origin + '/' + path],
                    'ath10k archived pinned source drift: ' + path)
            fetched.append((origin, path, content))
    require(len(intent['inputs']) == len(fetched), 'ath10k archived input set drift')
    headers = {name: get(output / f'reference/xnu/files/bsd/sys/hakios.{name}.h')
               for name in ('lx', 'qmi', 'sta')}
    require({name: sha(content) for name, content in headers.items()} == intent['network_headers'],
            'ath10k shared network header drift')
    reference, before, patches = prepare_reference(fetched, headers)
    require(before == intent['original_reference'] and
            {path: sha(content.encode()) for path, content in reference.items()} == intent['prepared_reference'],
            'ath10k prepared source transformation drift')
    for path, content in reference.items():
        require(get(output / 'reference' / path) == content.encode(), 'ath10k archived prepared source drift')
    for name, content in patches.items():
        require(get(output / 'prepared-patches' / name) == content, 'ath10k exact relocated patch drift')
    require(len(metadata['objects']) == 47 and len(result['objects']) == 1,
            'ath10k compiled or relocatable object set drift')
    definitions, undefined = set(), set()
    for path, record in metadata['objects'].items():
        content = get(path)
        source_key = str(PurePosixPath(metadata['build_root']) / record['source'])
        source_record = metadata['dependencies'][source_key]
        require(sha(content) == record['sha256'] and
                sha(get(source_record['path'])) == source_record['sha256'] == record['source_sha256'],
                'ath10k object/source dependency binding drift')
        parsed = inspect_object(content)
        for symbol in parsed['symbols']:
            if symbol['kind'] & 0xe0 or not symbol['kind'] & 1:
                continue
            if symbol['kind'] & 0xe:
                definitions.add(symbol['name'])
            else:
                undefined.add(symbol['name'])
        command = record['command']
        require(shlex.split(get(PurePosixPath(path).with_suffix('.command')).decode()) == command and
                '-fno-common' in command and 'arm64-apple-ios17.0' in command,
                'ath10k compilation command/deployment drift')
        require(all('-D' + key + '=' + value in command for key, value in REMAP.items()),
                'ath10k compilation symbol-remap drift')
        for original in record['dependencies']:
            dependency = metadata['dependencies'][original]
            require(sha(get(dependency['path'])) == dependency['sha256'], 'ath10k compiler dependency drift')
    external, exports = external_contract(definitions, undefined, set())
    require(external == metadata['imports'] and sorted(exports) == metadata['exports'],
            'ath10k relocatable symbol contract drift')
    combined = get(result['objects'][0])
    require(sha(combined) == metadata['relocatable_sha256'], 'ath10k linked object drift')
    combined_symbols = inspect_object(combined)['symbols']
    linked_definitions = {symbol['name'] for symbol in combined_symbols
                          if not symbol['kind'] & 0xe0 and symbol['kind'] & 1 and symbol['kind'] & 0xe}
    linked_imports = {symbol['name'] for symbol in combined_symbols
                      if not symbol['kind'] & 0xe0 and symbol['kind'] & 1 and not symbol['kind'] & 0xe}
    require(linked_definitions == exports and linked_imports == set(external),
            'ath10k combined object export/import drift')
    root = PurePosixPath(metadata['build_root'])
    require(root.is_absolute() and '..' not in root.parts, 'ath10k original build root drift')
    link = json.loads(get(output / 'relocatable-link-command.json'))
    require('-r' in link and '-exported_symbols_list' in link and
            [value for value in link if value.endswith('.o') and value != str(root / result['objects'][0])] ==
            [str(root / path) for path in metadata['objects']], 'ath10k relocatable link object set drift')
    archive = get(result['archive'])
    require(sha(archive) == metadata['archive_sha256'] and
            archive_members(archive) == {PurePosixPath(result['objects'][0]).name: combined},
            'ath10k archive/member drift')
    return dict(source_qualified=True, object_count=47, archive_qualified=True,
                link_qualified=False, runtime_qualified=False)
