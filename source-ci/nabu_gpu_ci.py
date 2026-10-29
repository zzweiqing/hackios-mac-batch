"""Replay the A640 diagnostic build identity; never claim GPU runtime success."""
import hashlib
import json
from pathlib import PurePosixPath
import re
import struct

from nabu_display_ci import HARDWARE_GPU_PROFILE as PROFILE

OUTPUT = 'outputs/tree/build/native-adreno/'
PMAP_SOURCE = 'outputs/tree/.cache/xnu-work/osfmk/arm/pmap/pmap.c'
SOURCE_SUFFIXES = {'.c', '.cpp', '.h'}
SOURCE_NAMES = {'LICENSE', 'COPYING', 'PROVENANCE'}
REQUIRED_SYMBOLS = {'_native_adreno_a6xx_start', '_native_adreno_a6xx_resources',
                    '_native_adreno_checkpoint', '_native_adreno_poll_irqs', '_nabu_log_committed_end'}
FORBIDDEN_SYMBOLS = {'_native_adreno_accelerator_publish', '_native_adreno_publish',
                     '_native_adreno_control_publish', '_native_adreno_new_user_client'}
REQUIRED_OBJECTS = {name for name in (
    'NativeAdrenoMemory', 'NativeAdrenoVm', 'NativeAdrenoCpu', 'NativeAdrenoKernelTime',
    'NativeAdrenoRing', 'NativeAdrenoCpInit', 'NativeAdrenoIrq', 'NativeAdrenoSmmuMemory',
    'NativeAdrenoSmmuContext', 'NativeAdrenoGmuMemory', 'NativeAdrenoGmuContext',
    'NativeAdrenoGpuContext', 'NativeAdrenoA6xxPower', 'NativeAdrenoA6xxGmu',
    'NativeAdrenoA6xxHwInit', 'NativeAdrenoA6xxSmmu', 'NativeAdrenoA6xxZap',
    'NativeAdrenoService', 'NativeAdrenoSha256', 'NativeAdrenoGpuProfile', 'NabuGpuResources', 'NabuGpuStart',
    'ArmSmmu4K', 'ArmSmmu4KAudit', 'ArmSmmu4KContext', 'ArmSmmu4KLive',
    'ArmSmmu4KMmio', 'ArmSmmu4KProgram', 'ArmSmmu4KStreams', 'ArmSmmu4KTableMemory', 'AdrenoPM4')}
FORBIDDEN_OBJECTS = {'NativeAdrenoPublish', 'NativeAdrenoAccelerator', 'NativeAdrenoUserClient',
                     'NativeAdrenoClient', 'NativeAdrenoSubmit', 'NativeAdrenoScheduler'}
CONTRACT = {'profile': PROFILE, 'mode': 'a640_diagnostic', 'firmware_mode': 'adt',
            'trigger': 'nabu-gpu=1', 'metal_accelerator': False, 'runtime_qualified': False}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def json_object(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate GPU JSON key: ' + key)
            result[key] = value
        return result
    value = json.loads(data, object_pairs_hook=unique)
    require(isinstance(value, dict), 'Expected GPU JSON object')
    return value


def relative(name):
    require(isinstance(name, str) and name and '\\' not in name and ':' not in name,
            'Invalid GPU relative path')
    path = PurePosixPath(name)
    require(bool(path.parts) and not path.is_absolute() and path.as_posix() == name and
            all(part not in ('.', '..') for part in path.parts), 'GPU path traversal')
    return path


def public_source(name):
    path = relative(name)
    return path.parts[0] == 'gpu' and (path.suffix in SOURCE_SUFFIXES or path.name in SOURCE_NAMES)


def source_identity(sources):
    return sha(json.dumps(sources, sort_keys=True, separators=(',', ':')).encode())


def archive_members(data):
    """Read ordinary BSD/GNU ar members without invoking a host toolchain."""
    require(data.startswith(b'!<arch>\n'), 'GPU archive is not an ordinary ar archive')
    at, result, names = 8, {}, b''
    while at < len(data):
        require(at + 60 <= len(data), 'Truncated GPU archive header')
        header = data[at:at + 60]
        require(header[58:60] == b'`\n', 'Invalid GPU archive header')
        try:
            size = int(header[48:58].strip())
            name = header[:16].decode('ascii').rstrip()
        except (ValueError, UnicodeDecodeError) as error:
            raise ValueError('Invalid GPU archive member metadata') from error
        at += 60
        require(0 <= size <= len(data) - at, 'Truncated GPU archive member')
        payload = data[at:at + size]
        at += size + (size & 1)
        require(at <= len(data), 'Missing GPU archive member padding')
        if name.startswith('#1/'):
            length = int(name[3:])
            require(0 < length <= len(payload), 'Invalid BSD archive member name')
            name, payload = payload[:length].rstrip(b'\0').decode(), payload[length:]
        elif name == '//':
            names = payload
            continue
        elif name.startswith('/') and name[1:].isdigit():
            offset = int(name[1:])
            require(offset < len(names), 'Invalid GNU archive member name')
            end = names.find(b'/\n', offset)
            require(end >= offset, 'Unterminated GNU archive member name')
            name = names[offset:end].decode()
        elif name not in ('/', '/SYM64/'):
            name = name.removesuffix('/')
        if name in ('/', '/SYM64/', '__.SYMDEF', '__.SYMDEF SORTED', '__.SYMDEF_64', '__.SYMDEF_64 SORTED'):
            continue
        require(relative(name).name == name and name not in result, 'Duplicate or nested GPU archive member')
        result[name] = payload
    return result


def candidate_definitions(data):
    require(len(data) >= 32 and struct.unpack_from('<4I', data) == (0xfeedfacf, 0x100000c, 0, 2),
            'GPU candidate is not an ARM64 executable')
    count, extent = struct.unpack_from('<II', data, 16)
    require(count > 0 and extent <= len(data) - 32, 'Invalid GPU Mach-O commands')
    at, table = 32, None
    for _ in range(count):
        require(at + 8 <= 32 + extent, 'Truncated GPU Mach-O command')
        command, size = struct.unpack_from('<II', data, at)
        require(size >= 8 and size <= 32 + extent - at, 'Invalid GPU Mach-O command')
        if command == 2:
            require(size >= 24 and table is None, 'Invalid GPU symbol table command')
            table = struct.unpack_from('<4I', data, at + 8)
        at += size
    require(at == 32 + extent and table is not None, 'Missing GPU symbol table')
    offset, number, strings, length = table
    require(offset + number * 16 <= len(data) and strings + length <= len(data),
            'Invalid GPU symbol table bounds')
    found = {}
    for index in range(number):
        name, kind, section, _, address = struct.unpack_from('<IBBHQ', data, offset + 16 * index)
        if kind & 0xe0:
            continue
        require(name < length, 'Invalid GPU symbol name')
        end = data.find(b'\0', strings + name, strings + length)
        require(end >= 0, 'Unterminated GPU symbol name')
        name = data[strings + name:end].decode()
        require(name not in FORBIDDEN_SYMBOLS, 'Diagnostic GPU candidate contains publication symbol: ' + name)
        if name in REQUIRED_SYMBOLS:
            require(kind & 0xe == 0xe and section > 0 and address > 0 and name not in found,
                    'GPU entry is not a unique section definition: ' + name)
            found[name] = hex(address)
    require(set(found) == REQUIRED_SYMBOLS, 'Missing GPU diagnostic definitions: ' +
            ', '.join(sorted(REQUIRED_SYMBOLS - set(found))))
    return found


def qualify_gpu_bundle(read, candidate, source_names):
    """read(relative_name) returns manifest-bound bytes in the collector layout."""
    raw_report = read(OUTPUT + 'build-report.json')
    report = json_object(raw_report)
    require(all(report.get(key) == CONTRACT[key] for key in ('profile', 'mode', 'firmware_mode')) and
            report.get('runtime_qualified') is False and report.get('hardware_tested') is False and
            report.get('metal_accelerator') is False and report.get('requires_pmap_64bit') is True and
            report.get('pmap_sync_64bit_verified') is True, 'GPU build report has the wrong diagnostic scope')
    sources = report.get('sources')
    require(isinstance(sources, dict) and 0 < len(sources) <= 1024 and
            set(sources) == set(source_names), 'GPU source inventory mismatch')
    require('scripts/build-nabu-adreno.py' in sources, 'GPU source inventory lacks the actual builder')
    source_bytes = {}
    for name, digest in sources.items():
        require(public_source(name) or name == 'scripts/build-nabu-adreno.py', 'Unexpected GPU source input')
        require(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest), 'Invalid GPU source digest')
        data = read('device/' + name)
        require(sha(data) == digest, 'GPU source hash mismatch: ' + name)
        source_bytes[name] = data
    identity = source_identity(sources)
    require(identity == report.get('source_identity'), 'GPU source identity mismatch')
    generated = read(OUTPUT + 'source/NabuGpuBuild.h')
    require(generated == ('#define NABU_GPU_SOURCE_ID "' + identity + '"\n').encode(),
            'Generated GPU identity header mismatch')
    merged_headers = {}
    for name in sorted(sources):
        path = relative(name)
        if path.suffix != '.h':
            continue
        choices = ['gpu/' + prefix + '/' + path.name for prefix in
                   ('nabu', 'a640', 'upstream/AdrenoPM4', 'upstream/ArmSmmu4K', 'upstream/Adreno6xx')]
        selected = next((choice for choice in choices if choice in sources), None)
        require(selected is not None, 'GPU header outside merged source directories')
        require(read(OUTPUT + 'source/' + path.name) == source_bytes[selected],
                'Merged GPU header differs from selected overlay: ' + path.name)
        merged_headers[path.name] = {'source': selected, 'sha256': sources[selected]}
    commands = json_object(read(OUTPUT + 'compile-command.json'))
    require(set(commands) == REQUIRED_OBJECTS and all(isinstance(command, list) and command
            for command in commands.values()), 'GPU compile command inventory mismatch')
    logging = report.get('logging_headers')
    require(isinstance(logging, dict) and {'ufs/NabuLogCore.h', 'ufs/NabuLogFormat.h'} <= set(logging),
            'GPU checkpoint logging header identities are absent')
    for name, digest in logging.items():
        path = relative(name)
        require(path.parent.as_posix() == 'ufs' and path.name.startswith('NabuLog') and path.suffix == '.h',
                'Unexpected GPU logging header')
        data = read('device/' + name)
        require(sha(data) == digest and read(OUTPUT + 'source/' + path.name) == data,
                'GPU logging header hash mismatch: ' + name)
    archive = read(OUTPUT + 'libNativeAdreno.a')
    require(sha(archive) == report.get('archive_sha256'), 'GPU archive hash mismatch')
    members = archive_members(archive)
    objects = report.get('objects')
    require(isinstance(objects, dict) and set(objects) == REQUIRED_OBJECTS and
            not set(objects) & FORBIDDEN_OBJECTS, 'GPU diagnostic object inventory mismatch')
    require(set(members) == {stem + '.o' for stem in objects}, 'GPU archive object inventory mismatch')
    objects_verified = {}
    for stem, metadata in objects.items():
        require(isinstance(metadata, dict) and metadata.get('object') == stem + '.o',
                'Invalid GPU object record')
        path = relative(metadata.get('source'))
        require(path.parent.as_posix() == 'source' and path.stem == stem and path.suffix in ('.c', '.cpp'),
                'Invalid merged GPU source path')
        choices = [prefix + path.name for prefix in ('gpu/nabu/', 'gpu/a640/',
                   'gpu/upstream/AdrenoPM4/', 'gpu/upstream/ArmSmmu4K/', 'gpu/upstream/Adreno6xx/')]
        selected = next((name for name in choices if name in sources), None)
        require(selected is not None, 'GPU object source is not inventoried: ' + stem)
        merged = read(OUTPUT + path.as_posix())
        require(merged == source_bytes[selected] and sha(merged) == metadata.get('source_sha256'),
                'Merged GPU source differs from selected overlay: ' + stem)
        obj = read(OUTPUT + metadata['object'])
        require(len(obj) >= 16 and struct.unpack_from('<4I', obj) == (0xfeedfacf, 0x100000c, 0, 1),
                'GPU object is not ARM64 Mach-O: ' + stem)
        require(sha(obj) == metadata.get('sha256') and obj == members[metadata['object']],
                'GPU object/archive identity mismatch: ' + stem)
        if stem == 'NabuGpuResources':
            require(identity.encode() + b'\0' in obj, 'GPU resource object lacks its source identity banner')
        objects_verified[stem] = {'object': metadata['object'], 'sha256': sha(obj),
                                  'source': selected, 'source_sha256': sha(merged)}
    require(identity.encode() + b'\0' in candidate, 'Final GPU candidate lacks its source identity banner')
    pmap = read(PMAP_SOURCE)
    require(sha(pmap) == report.get('pmap_source_sha256'), 'GPU pmap source hash mismatch')
    function = re.search(rb'pmap_sync_page_attributes_phys\s*\(\s*ppnum_t\s+pp\s*\)\s*\{([^}]+)\}', pmap)
    require(function is not None, 'GPU pmap cache-attribute function is absent')
    body = re.sub(rb'/\*.*?\*/|//[^\n]*', b'', function[1], flags=re.S)
    require(re.search(rb'flush_dcache\s*\(\s*\(vm_offset_t\)\s*ptoa\(pp\)\s*,\s*PAGE_SIZE\s*,\s*TRUE\s*\)', body),
            'GPU pmap cache-attribute source does not preserve 64-bit physical addresses')
    return {**CONTRACT, 'hardware_tested': False, 'candidate_sha256': sha(candidate),
            'source_identity': identity, 'source_count': len(sources),
            'archive': OUTPUT + 'libNativeAdreno.a', 'archive_sha256': sha(archive),
            'build_report': OUTPUT + 'build-report.json', 'build_report_sha256': sha(raw_report),
            'generated_header_sha256': sha(generated),
            'compile_commands_sha256': sha(read(OUTPUT + 'compile-command.json')), 'sources': sources,
            'objects': objects_verified, 'merged_headers': merged_headers, 'logging_headers': logging,
            'pmap_source': PMAP_SOURCE, 'pmap_source_sha256': sha(pmap),
            'pmap_sync_64bit_verified': True, 'final_definitions': candidate_definitions(candidate)}


def qualify_gpu_candidate(upstream, device, candidate, expected_profile=PROFILE):
    require(expected_profile == PROFILE, 'GPU qualification requires its explicit profile')
    roots = {'device': device, 'outputs': upstream / 'out/nabu'}

    def read(name):
        path = relative(name)
        root = roots.get(path.parts[0])
        require(root is not None, 'Unknown GPU evidence root')
        target = root.joinpath(*path.parts[1:])
        require(target.is_file() and target.resolve().is_relative_to(root.resolve()) and
                not any(p.is_symlink() for p in (target, *target.parents)), 'Missing or linked GPU evidence: ' + name)
        return target.read_bytes()

    names = [p.relative_to(device).as_posix() for p in sorted((device / 'gpu').rglob('*'))
             if p.is_file() and public_source(p.relative_to(device).as_posix())]
    names.append('scripts/build-nabu-adreno.py')
    return qualify_gpu_bundle(read, candidate.read_bytes(), names)
