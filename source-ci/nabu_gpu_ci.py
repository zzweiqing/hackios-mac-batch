"""Replay the A640 GPU build identity; never claim GPU runtime success.

Two contracts share this module.

* The diagnostic profile must NOT contain the publication objects or the
  publication symbols. It is the candidate that has actually run on the tablet,
  so its negative controls stay in place.
* The Metal profile must contain them, must stage the two late objects whose
  static initializers may only run after the original IOGPUFamily has
  registered, and must bind the three original IOAcceleratorES symbols to
  addresses derived from this candidate's own extents rather than from a fixed
  slide of another image's addresses.

Neither profile claims a runtime capability: ``runtime_qualified`` and
``hardware_tested`` stay false, and compiling the publication path is not
evidence that the service was published.
"""
import hashlib
import json
from pathlib import PurePosixPath
import re
import struct

from nabu_display_ci import (HARDWARE_GPU_PROFILE as PROFILE,
                             HARDWARE_GPU_METAL_PROFILE as METAL_PROFILE)

OUTPUT = 'outputs/tree/build/native-adreno/'
PMAP_SOURCE = 'outputs/tree/.cache/xnu-work/osfmk/arm/pmap/pmap.c'
# The audited accelerator ABI contract is a build input, not decoration: the
# bindings generator consumes it, so it must be manifest-bound like any source.
SOURCE_SUFFIXES = {'.c', '.cpp', '.h', '.json'}
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

# Accelerator mode. NativeAdrenoTimer is not optional: NativeAdrenoUserClient
# reads the always-on counter through it, so omitting it leaves a link gap.
PUBLICATION_OBJECTS = ('NativeAdrenoPublish', 'NativeAdrenoAccelerator', 'NativeAdrenoUserClient',
                       'NativeAdrenoClient', 'NativeAdrenoSubmit', 'NativeAdrenoScheduler',
                       'NativeAdrenoTimer')
# Exactly these two defer their static initializer: their registration would run
# before the original parent metaclass exists. Their __text must not change.
LATE_OBJECTS = ('NativeAdrenoPublish', 'NativeAdrenoAccelerator')
PUBLICATION_SYMBOLS = {'_native_adreno_accelerator_publish', '_native_adreno_publish',
                       '_native_adreno_new_user_client'}
BINDING_SYMBOLS = ('__ZN15IOAcceleratorESC2EPK11OSMetaClass',
                   '__ZN15IOAcceleratorESD2Ev',
                   '__ZN15IOAcceleratorES10gMetaClassE')
BINDINGS_SOURCE = 'original-accelerator-bindings.S'
BINDINGS_OBJECT = 'original-accelerator-bindings.o'
BINDINGS_REPORT = 'adreno-bindings.json'
BINDINGS_GENERATOR = 'scripts/nabu_adreno_bindings.py'
IOGPU_MODULE = 'com.apple.iokit.IOGPUFamily'
METAL_REQUIRED_OBJECTS = REQUIRED_OBJECTS | set(PUBLICATION_OBJECTS)
METAL_REQUIRED_SYMBOLS = REQUIRED_SYMBOLS | PUBLICATION_SYMBOLS
METAL_CONTRACT = {'profile': METAL_PROFILE, 'mode': 'a640_metal', 'firmware_mode': 'adt',
                  'trigger': 'nabu-gpu=1', 'metal_accelerator': True, 'runtime_qualified': False}
GPU_PROFILES = (PROFILE, METAL_PROFILE)
CONTRACTS = {PROFILE: CONTRACT, METAL_PROFILE: METAL_CONTRACT}
ADDRESS = re.compile('0x[0-9a-f]{16}')
# A segment size is a byte count, not an address: the generator writes hex(size).
EXTENT = re.compile('0x[0-9a-f]{1,16}')


def gpu_contract(profile):
    try:
        return CONTRACTS[profile]
    except KeyError:
        raise ValueError('No GPU contract is declared for profile: ' + str(profile)) from None


def accelerator_mode(profile):
    return profile == METAL_PROFILE


def source_scripts(profile):
    builder = 'scripts/build-nabu-adreno.py'
    return (builder, BINDINGS_GENERATOR) if accelerator_mode(profile) else (builder,)


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


def candidate_definitions(data, profile=PROFILE):
    """Return (section definitions, absolute original-base bindings)."""
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
    metal = accelerator_mode(profile)
    required = METAL_REQUIRED_SYMBOLS if metal else REQUIRED_SYMBOLS
    forbidden = set() if metal else FORBIDDEN_SYMBOLS
    found, bindings = {}, {}
    for index in range(number):
        name, kind, section, _, address = struct.unpack_from('<IBBHQ', data, offset + 16 * index)
        if kind & 0xe0:
            continue
        require(name < length, 'Invalid GPU symbol name')
        end = data.find(b'\0', strings + name, strings + length)
        require(end >= 0, 'Unterminated GPU symbol name')
        name = data[strings + name:end].decode()
        require(name not in forbidden, 'Diagnostic GPU candidate contains publication symbol: ' + name)
        if name in required:
            require(kind & 0xe == 0xe and section > 0 and address > 0 and name not in found,
                    'GPU entry is not a unique section definition: ' + name)
            found[name] = hex(address)
        elif metal and name in BINDING_SYMBOLS:
            # A linker .set alias is an absolute definition, not a section one.
            require(kind & 0xe == 0x2 and section == 0 and address > 0 and name not in bindings,
                    'Accelerator original-base binding is not a unique absolute definition: ' + name)
            bindings[name] = hex(address)
    missing = ', '.join(sorted(required - set(found)))
    require(set(found) == required,
            ('Missing GPU definitions: ' if metal else 'Missing GPU diagnostic definitions: ') + missing)
    return found, bindings


def accelerator_bindings(read, candidate, report):
    """Bind the generated original-base aliases to this candidate.

    The addresses come from this candidate's own IOGPUFamily extents, so the
    assembly source, the generator's plan and the candidate symbol table are
    checked against each other instead of trusting a recorded address. The plan
    must name this same candidate and this same original kernelcache, and every
    check the generator performed must have passed.
    """
    raw = read(OUTPUT + BINDINGS_REPORT)
    plan = json_object(raw)
    checks = plan.get('checks')
    require(plan.get('status') == 'ok' and plan.get('mode') == 'generate' and
            plan.get('module') == IOGPU_MODULE and plan.get('address_space') == 'candidate',
            'Accelerator bindings report has the wrong scope')
    require(isinstance(checks, dict) and checks and
            all(value == 'passed' for value in checks.values()) and
            plan.get('runtime_qualified') is False and plan.get('images_modified') is False,
            'Accelerator bindings report did not pass every check')
    require(plan.get('kernelcache_sha256') == report.get('kernelcache_sha256'),
            'Accelerator bindings were derived from a different original kernelcache')
    candidate_plan = plan.get('candidate')
    require(isinstance(candidate_plan, dict) and candidate_plan.get('candidate_sha256') == sha(candidate),
            'Accelerator bindings report is not bound to this candidate')
    symbols = plan.get('bindings')
    require(isinstance(symbols, dict) and set(symbols) == set(BINDING_SYMBOLS),
            'Accelerator bindings must define exactly the three original-base symbols')
    for name, address in symbols.items():
        require(isinstance(address, str) and ADDRESS.fullmatch(address),
                'Malformed accelerator binding address: ' + name)
    extents = candidate_plan.get('extents')
    require(isinstance(extents, dict) and extents, 'Accelerator bindings lack candidate extents')
    ranges = []
    for extent in extents.values():
        require(isinstance(extent, dict) and ADDRESS.fullmatch(str(extent.get('candidate_va'))) and
                EXTENT.fullmatch(str(extent.get('size'))) and extent.get('header_matches_report') is True,
                'Malformed accelerator candidate extent')
        low = int(extent['candidate_va'], 16)
        size = int(extent['size'], 16)
        require(size > 0 and low + size <= 1 << 64, 'Invalid accelerator candidate extent bounds')
        ranges.append((low, low + size))
    for name, address in symbols.items():
        value = int(address, 16)
        require(any(low <= value < high for low, high in ranges),
                'Accelerator binding is outside this candidate IOGPUFamily extents: ' + name)
    source = read(OUTPUT + BINDINGS_SOURCE)
    for name, address in sorted(symbols.items()):
        require(('.globl ' + name + '\n.set ' + name + ', ' + address + '\n').encode() in source,
                'Accelerator bindings source does not define ' + name)
    original = plan.get('original')
    require(isinstance(original, dict) and isinstance(original.get('metaclass'), dict) and
            ADDRESS.fullmatch(str(original['metaclass'].get('object'))),
            'Accelerator bindings lack the audited original metaclass object')
    # Pin the audited shape rather than re-deriving it here: a rebuilt accelerator
    # subclass is only ABI-compatible while the original base keeps this layout.
    require(original.get('reported_instance_bytes') == 136 and
            original.get('virtual_entries') == 168 and
            original.get('metadata_overrides') == [0, 1, 7],
            'Audited original IOAcceleratorES ABI shape changed')
    return {'symbols': symbols, 'source': OUTPUT + BINDINGS_SOURCE, 'source_sha256': sha(source),
            'report': OUTPUT + BINDINGS_REPORT, 'report_sha256': sha(raw),
            'original_metaclass': original['metaclass']['object'],
            'original_instance_bytes': original.get('reported_instance_bytes'),
            'original_virtual_entries': original.get('virtual_entries'),
            'original_metadata_overrides': original.get('metadata_overrides'),
            'candidate_extents': {name: extent['candidate_va'] for name, extent in extents.items()},
            'checks': checks, 'runtime_qualified': False}


def qualify_gpu_bundle(read, candidate, source_names, profile=PROFILE):
    """read(relative_name) returns manifest-bound bytes in the collector layout."""
    contract = gpu_contract(profile)
    metal = accelerator_mode(profile)
    required_objects = METAL_REQUIRED_OBJECTS if metal else REQUIRED_OBJECTS
    forbidden_objects = set() if metal else FORBIDDEN_OBJECTS
    raw_report = read(OUTPUT + 'build-report.json')
    report = json_object(raw_report)
    require(all(report.get(key) == contract[key] for key in
                ('profile', 'mode', 'firmware_mode', 'trigger', 'metal_accelerator')) and
            report.get('runtime_qualified') is False and report.get('hardware_tested') is False and
            report.get('requires_pmap_64bit') is True and
            report.get('pmap_sync_64bit_verified') is True,
            'GPU build report has the wrong scope')
    sources = report.get('sources')
    require(isinstance(sources, dict) and 0 < len(sources) <= 1024 and
            set(sources) == set(source_names), 'GPU source inventory mismatch')
    scripts = source_scripts(profile)
    require(set(scripts) <= set(sources), 'GPU source inventory lacks an actual build/bindings script')
    source_bytes = {}
    for name, digest in sources.items():
        require(public_source(name) or name in scripts, 'Unexpected GPU source input')
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
    require(set(commands) == required_objects and all(isinstance(command, list) and command
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
    require(isinstance(objects, dict) and set(objects) == required_objects and
            not set(objects) & forbidden_objects, 'GPU object inventory mismatch')
    expected_members = {stem + ('.late.o' if metal and stem in LATE_OBJECTS else '.o') for stem in objects}
    if metal:
        expected_members.add(BINDINGS_OBJECT)
    require(set(members) == expected_members, 'GPU archive object inventory mismatch')
    objects_verified = {}
    for stem, metadata in objects.items():
        late = metal and stem in LATE_OBJECTS
        require(isinstance(metadata, dict) and
                metadata.get('object') == stem + ('.late.o' if late else '.o'),
                'Invalid GPU object record')
        if late:
            require(metadata.get('kind') == 'late' and metadata.get('init_section_removed') is True and
                    metadata.get('text_sha256') == metadata.get('late_text_sha256'),
                    'Deferred GPU object did not preserve its text and drop its initializer: ' + stem)
        else:
            require(metadata.get('kind') is None and metadata.get('late_text_sha256') is None,
                    'Unexpected GPU object mode: ' + stem)
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
                                  'source': selected, 'source_sha256': sha(merged),
                                  'kind': 'late' if late else 'direct'}
    if metal:
        binding_object = read(OUTPUT + BINDINGS_OBJECT)
        binding_record = report.get('bindings')
        require(isinstance(binding_record, dict) and
                binding_record.get('object') == BINDINGS_OBJECT and
                sha(binding_object) == binding_record.get('object_sha256') and
                binding_object == members[BINDINGS_OBJECT] and
                len(binding_object) >= 16 and
                struct.unpack_from('<4I', binding_object) == (0xfeedfacf, 0x100000c, 0, 1),
                'GPU bindings object/archive identity mismatch')
    require(identity.encode() + b'\0' in candidate, 'Final GPU candidate lacks its source identity banner')
    pmap = read(PMAP_SOURCE)
    require(sha(pmap) == report.get('pmap_source_sha256'), 'GPU pmap source hash mismatch')
    function = re.search(rb'pmap_sync_page_attributes_phys\s*\(\s*ppnum_t\s+pp\s*\)\s*\{([^}]+)\}', pmap)
    require(function is not None, 'GPU pmap cache-attribute function is absent')
    body = re.sub(rb'/\*.*?\*/|//[^\n]*', b'', function[1], flags=re.S)
    require(re.search(rb'flush_dcache\s*\(\s*\(vm_offset_t\)\s*ptoa\(pp\)\s*,\s*PAGE_SIZE\s*,\s*TRUE\s*\)', body),
            'GPU pmap cache-attribute source does not preserve 64-bit physical addresses')
    definitions, bound = candidate_definitions(candidate, profile)
    result = {**contract, 'hardware_tested': False, 'candidate_sha256': sha(candidate),
              'source_identity': identity, 'source_count': len(sources),
              'archive': OUTPUT + 'libNativeAdreno.a', 'archive_sha256': sha(archive),
              'build_report': OUTPUT + 'build-report.json', 'build_report_sha256': sha(raw_report),
              'generated_header_sha256': sha(generated),
              'compile_commands_sha256': sha(read(OUTPUT + 'compile-command.json')), 'sources': sources,
              'objects': objects_verified, 'merged_headers': merged_headers, 'logging_headers': logging,
              'pmap_source': PMAP_SOURCE, 'pmap_source_sha256': sha(pmap),
              'pmap_sync_64bit_verified': True, 'final_definitions': definitions}
    if metal:
        bindings = accelerator_bindings(read, candidate, report)
        require(bindings['symbols'] == bound,
                'Accelerator original-base bindings do not match the candidate symbol table')
        result['bindings'] = bindings
        result['final_bindings'] = bound
    return result


def qualify_gpu_candidate(upstream, device, candidate, expected_profile=PROFILE):
    require(expected_profile in GPU_PROFILES, 'GPU qualification requires its explicit profile')
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
    names.extend(source_scripts(expected_profile))
    return qualify_gpu_bundle(read, candidate.read_bytes(), names, expected_profile)
