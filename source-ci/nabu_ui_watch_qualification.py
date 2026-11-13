"""Qualify the separately enabled UI observer from real private build inputs."""
import ast
import hashlib
import re
import struct


def require(value, reason):
    if not value:
        raise ValueError(reason)


# v5 wait-owner record: exact code-level limits and gates the generator must carry.
WAIT_EXEC_REQUIRED = (
    'NABU_UI_WAIT_TARGET_LINES = 16, NABU_UI_WAIT_SAMPLE_LINES = 48',
    'NABU_UI_WAIT_TOTAL_LINES = 1536',
    'if (nabu_ui_task_enabled_cache == 1 && nabu_ui_wait_enabled_cache < 0) {',
)
WAIT_THREAD_REQUIRED = (
    'waitq_lock_try(', 'thread_get_waiting_turnstile(', 'NABU_UI_WAIT_MAX_HOPS = 3',
    'simple_lock_try(&holder->sched_lock',
    'return hint == 2 || hint == 4 || hint == 5 || hint == 10 || hint == 16 || hint == 18;',
)
WAIT_THREAD_FORBIDDEN = (
    'waitq_lock(', 'thread_lock(', 'kdp_', 'ull_owner', 'turnstile_reference',
    'thread_reference', 'copyin', 'kalloc', 'zalloc', 'lck_mtx_lock')
# Blocking lock entry points matched as whole call tokens: an identifier boundary on the
# left, and for bare names no '_try' continuation, so the helper's simple_lock_try(,
# task_lock_try( and waitq_lock_try( remain allowed.
WAIT_THREAD_FORBIDDEN_CALLS = (
    'simple_lock(', 'task_lock(', 'hw_lck_ticket_lock(', 'lck_spin_lock',
    'waitq_lock_allow_invalid', 'waitq_lock_reserve', 'waitq_lock_wait')
_FORBIDDEN_CALL = re.compile('|'.join(
    r'(?<![A-Za-z0-9_])' + re.escape(name) + ('' if name.endswith('(') else r'(?!_try)')
    for name in WAIT_THREAD_FORBIDDEN_CALLS))


def wait_helpers_ok(exec_helper, thread_helper):
    """Static v5 gate over the generator's helper text (try-only, bounded, default-off)."""
    return (all(name in exec_helper for name in WAIT_EXEC_REQUIRED) and
            all(name in thread_helper for name in WAIT_THREAD_REQUIRED) and
            not any(name in thread_helper for name in WAIT_THREAD_FORBIDDEN) and
            _FORBIDDEN_CALL.search(thread_helper) is None)


# v6 owner chain: exact code-level limits and identity readers the generator must carry.
CHAIN_EXEC_REQUIRED = (
    'NABU_UI_CHAIN_SAMPLE_LINES = 12', 'NABU_UI_CHAIN_TOTAL_LINES = 512',
    'NABU_UI_CHAIN_DEDUP = 16', 'requested == 1 || requested == 2',
    'NabuUIOwner: sample=', 'NabuUIOwner: budget sample=')
CHAIN_THREAD_REQUIRED = (
    'NABU_UI_CHAIN_FIELDS = 10', 'NABU_UI_CHAIN_LINKS = 3',
    'nabu_ui_wait_chain_locked', 'task_pid(', 'task_best_name(',
    'get_task_uniqueid(', 'get_bsdtask_info(', 'NABU_UI_CHAIN_NEXT_LINK_MAX = 11')


def chain_helpers_ok(exec_helper, thread_helper):
    """Static v6 gate: the v5 gate plus the bounded cross-task chain tokens."""
    return (wait_helpers_ok(exec_helper, thread_helper) and
            all(name in exec_helper for name in CHAIN_EXEC_REQUIRED) and
            all(name in thread_helper for name in CHAIN_THREAD_REQUIRED))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_constants(generator):
    """Read data only; accept old literal pairs or reconstruct the single-source form."""
    required = {'CONTRACT', 'EXEC_HELPER', 'EXEC_PAIRS', 'EXIT_PAIRS', 'THREAD_HELPER'}
    forms = {'THREAD_PAIRS', 'THREAD_ANCHORS'}
    constants = {}
    for item in ast.parse(generator.decode('utf-8')).body:
        if not (isinstance(item, ast.Assign) and len(item.targets) == 1 and
                isinstance(item.targets[0], ast.Name)):
            continue
        name = item.targets[0].id
        if name not in required | forms:
            continue
        require(name not in constants, 'Duplicate UI source constant: ' + name)
        try:
            constants[name] = ast.literal_eval(item.value)
        except (ValueError, TypeError) as error:
            raise ValueError('UI source constant must be literal: ' + name) from error
    require(required <= constants.keys() and len(forms & constants.keys()) == 1,
            'UI source contract incomplete or ambiguous')
    if 'THREAD_ANCHORS' in constants:
        anchors = constants.pop('THREAD_ANCHORS')
        require(isinstance(anchors, tuple) and len(anchors) == 1 and
                isinstance(anchors[0], str) and bool(anchors[0]) and
                isinstance(constants['THREAD_HELPER'], str), 'Invalid UI thread anchor')
        constants['THREAD_PAIRS'] = tuple(
            (before, constants['THREAD_HELPER'] + before) for before in anchors)
    require(isinstance(constants['THREAD_PAIRS'], tuple) and len(constants['THREAD_PAIRS']) == 1 and
            all(isinstance(pair, tuple) and len(pair) == 2 and
                isinstance(pair[0], str) and isinstance(pair[1], str) and
                pair[1] == constants['THREAD_HELPER'] + pair[0]
                for pair in constants['THREAD_PAIRS']),
            'UI thread replacement must be the helper followed by its anchor')
    return constants


def object_symbols(data, prefix='_nabu_ui_watch_'):
    require(len(data) >= 32 and struct.unpack_from('<4I', data) == (0xfeedfacf, 0x100000c, 0, 1),
            'UI observer object must be ordinary ARM64 Mach-O')
    count, extent = struct.unpack_from('<II', data, 16)
    require(0 < count <= 65536 and extent <= len(data) - 32, 'UI object command bounds')
    at, table, sections = 32, None, []
    for _ in range(count):
        require(at + 8 <= 32 + extent, 'UI object command header bounds')
        command, size = struct.unpack_from('<II', data, at)
        require(size >= 8 and at + size <= 32 + extent, 'UI object load command bounds')
        if command == 0x19:
            require(size >= 72, 'UI object segment bounds')
            number = struct.unpack_from('<I', data, at + 64)[0]
            require(72 + number * 80 <= size, 'UI object section bounds')
            for i in range(number):
                pos = at + 72 + i * 80
                va, length, offset = struct.unpack_from('<QQI', data, pos + 32)
                flags = struct.unpack_from('<I', data, pos + 64)[0]
                sections.append((va, length, offset, flags))
        elif command == 2:
            require(size >= 24 and table is None, 'UI object symbol table bounds')
            table = struct.unpack_from('<4I', data, at + 8)
        at += size
    require(at == 32 + extent and table is not None, 'UI object lacks symbols')
    offset, number, strings, length = table
    require(offset + number * 16 <= len(data) and strings + length <= len(data),
            'UI object symbol extent')
    found = {}
    for i in range(number):
        name, kind, section, _, address = struct.unpack_from('<IBBHQ', data, offset + i * 16)
        if kind & 0xe0 or kind & 0xe != 0xe:
            continue
        require(name < length and 0 < section <= len(sections), 'UI object definition bounds')
        end = data.find(b'\0', strings + name, strings + length)
        require(end >= 0, 'UI object unterminated symbol')
        name = data[strings + name:end].decode()
        if not name.startswith(prefix):
            continue
        va, backed, fileoff, flags = sections[section - 1]
        if not flags & 0x80000000:
            continue  # Private state symbols are not emitted function definitions.
        if (prefix == '' and kind == 0xe and re.fullmatch(r'ltmp[0-9]+', name) and
                backed == 0 and address == va and flags & 0xff == 0 and fileoff <= len(data)):
            continue  # LLVM local section marker in a data-only object's empty text section.
        require(va <= address < va + backed and fileoff + backed <= len(data),
                'UI observer unbacked code')
        require(name not in found, 'UI observer entry must be unique instructions')
        pos = fileoff + address - va
        require(any(data[pos:min(pos + 16, fileoff + backed)]),
                'UI observer entry has no emitted code')
        found[name] = address
    return found


def smp_configuration_trigger(read, candidate):
    """Recognize the bound SMP configuration logger's UI flag string."""
    from nabu_gpu_ci import json_object
    base = 'outputs/tree/build/native-ufs/'
    try:
        original = read('device/ufs/NabuLogEarlySmp.h')
        compiled = read(base + 'source/NabuLogEarlySmp.h')
        source = read(base + 'source/NativeUfs.cpp')
        writer = read(base + 'source/NabuLogUfs.h')
        obj = read(base + 'NativeUfs.o')
        report = json_object(read(base + 'build-report.json'))
    except (KeyError, OSError):
        return False
    identity = report.get('source_files', {})
    trigger = b'nabu-ui-watch\0'
    return (original == compiled and sha(compiled) == identity.get('NabuLogEarlySmp.h') and
            sha(source) == identity.get('NativeUfs.cpp') and sha(writer) == identity.get('NabuLogUfs.h') and
            sha(obj) == report.get('object_sha256') and
            b'#include "NabuLogUfs.h"' in source and b'#include "NabuLogEarlySmp.h"' in writer and
            b'nabuLogEarlySmpPoll();' in writer and
            b'enabled=PE_parse_boot_argn("nabu-smp-watch",&flag,sizeof(flag)) && flag==1;' in compiled and
            b'if(!enabled) return;' in compiled and
            b'PE_parse_boot_argn("nabu-ui-watch",&ui_watch,4);' in compiled and
            compiled.count(b'"nabu-ui-watch"') == 1 and
            obj.count(trigger) == candidate.count(trigger) == 1)


def qualify(read, candidate):
    from nabu_gpu_ci import candidate_definitions, json_object, METAL_PROFILE
    capture = json_object(read('outputs/tree/build/nabu-log/source-report.json'))
    exec_path = 'outputs/tree/.cache/xnu-work/bsd/kern/kern_exec.c'
    exit_path = 'outputs/tree/.cache/xnu-work/bsd/kern/kern_exit.c'
    thread_path = 'outputs/tree/.cache/xnu-work/osfmk/kern/thread.c'
    exec_source, exit_source = read(exec_path), read(exit_path)
    enabled = capture.get('ui_watch', False)
    require(type(enabled) is bool, 'UI watch build flag must be Boolean')
    if not enabled:
        try:
            thread_source = read(thread_path)
        except KeyError:
            # Evidence from a build that predates the osfmk sampler has no such hook.
            thread_source = b''
        require(b'NABU_UI_WATCH' not in exec_source and b'NABU_UI_WATCH' not in exit_source and
                b'NABU_UI_WATCH' not in thread_source and
                (b'nabu-ui-watch' not in candidate or smp_configuration_trigger(read, candidate)) and
                b'_nabu_ui_watch_' not in candidate and
                b'nabu-ui-wait-owner' not in candidate and b'NabuUIWait' not in candidate and
                b'NabuUIOwner' not in candidate,
                'Disabled kernel retains UI observer definitions or dependencies')
        return {'compiled': False, 'runtime_qualified': False}
    thread_source = read(thread_path)
    require(capture.get('gpu_userprobe_boot') is True, 'UI observer needs the original callback')
    generator = read('device/scripts/nabu_ui_watch_source.py')
    require(capture.get('ui_watch_generator_sha256') == sha(generator),
            'UI generator identity mismatch')
    constants = source_constants(generator)
    contract = constants['CONTRACT']
    version = contract.get('version', 1)
    targets = ['SpringBoard', 'backboardd', 'runningboardd'] + (['profiled'] if version >= 7 else [])
    if version >= 8:
        targets.append('nehelper')
    require(contract.get('max_samples') == 64 and contract.get('interval_us') == 10000000 and
            contract.get('max_threads') == len(targets) and contract.get('targets') == targets,
            'UI scope or budget changed')
    require(type(version) is int and version in (1, 2, 3, 4, 5, 6, 7, 8),
            'Unknown UI observer contract version')
    if version >= 7:
        require(contract.get('paths', [])[3:4] == ['/usr/libexec/profiled'] and
                b'"/usr/libexec/profiled"' in constants['EXEC_HELPER'].encode(),
                'UI v7 requires the real profiled executable path')
    if version >= 8:
        require(contract.get('paths', [])[4:] == ['/usr/libexec/nehelper'] and
                b'"/usr/libexec/nehelper"' in constants['EXEC_HELPER'].encode(),
                'UI v8 requires the real nehelper executable path')
    if version >= 2:
        require(contract.get('target_association') == 'activation-call-output' and
                contract.get('max_exec_contexts') == 0 and
                '_nabu_ui_watch_activate_image_v2' in contract.get('symbols', []) and
                b'nabu_ui_context' not in exec_source,
                'UI v2 requires direct activation target association without a context table')
    if version >= 3:
        require(contract.get('spawn_branch_observation') is True and
                b'nabu_ui_watch_signature(p, nabu_ui_exec_target, error, 0);' in exec_source and
                b'nabu_ui_watch_signature(p, nabu_ui_exec_target, error, spawn_no_exec);' in exec_source and
                b'spawn_release_ready' in constants['EXEC_HELPER'].encode() and
                b'spawn_released' in constants['EXEC_HELPER'].encode(),
                'UI v3 requires explicit spawn signature/release observation')
    if version >= 4:
        require(contract.get('task_trigger') == 'nabu-ui-task-watch=1' and
                contract.get('task_scan_limit') == 128 and contract.get('task_row_limit') == 32 and
                contract.get('task_new_references') == 0 and
                contract.get('task_wait_tag_scope') == 'thread-specific' and
                contract.get('task_snapshot_atomic') is False and
                '_nabu_ui_watch_task_snapshot' in contract.get('symbols', []) and
                b'nabu-ui-task-watch' in exec_source and b'NabuUITask:' in exec_source,
                'UI v4 requires separately enabled bounded task-thread snapshots')
    if version >= 5:
        thread_helper = constants['THREAD_HELPER']
        require(contract.get('wait_trigger') == 'nabu-ui-wait-owner=1' and
                contract.get('wait_requires') == ['nabu-ui-watch=1', 'nabu-ui-task-watch=1'] and
                contract.get('wait_hints') == [2, 4, 5, 10, 16, 18] and
                contract.get('wait_max_hops') == 3 and contract.get('wait_target_line_limit') == 16 and
                contract.get('wait_sample_line_limit') == 48 and
                contract.get('wait_total_line_limit') == 1536 and contract.get('wait_name_bytes') == 15 and
                contract.get('wait_lock_mode') == 'try-only' and contract.get('wait_new_references') == 0 and
                contract.get('wait_owner_field_read') is False and
                contract.get('wait_debugger_helpers') is False and
                {'_nabu_ui_watch_thread_wait_owner', '_nabu_ui_watch_task_wait_snapshot'} <=
                set(contract.get('symbols_by_object', {}).get('thread.c', [])) and
                b'"nabu-ui-wait-owner"' in exec_source and b'NabuUIWait: sample=' in exec_source and
                b'NabuUIWait: budget sample=' in exec_source and
                b'nabu_ui_watch_task_wait_snapshot(' in exec_source and
                b'NABU_UI_WATCH_WAIT_V1' in thread_source and
                wait_helpers_ok(constants['EXEC_HELPER'], thread_helper),
                'UI v5 requires a separately enabled, try-only, bounded wait-owner record')
    if version >= 6:
        require(contract.get('wait_chain_trigger') == 'nabu-ui-wait-owner=2' and
                contract.get('wait_chain_links') == 3 and
                contract.get('wait_chain_fields') == 10 and
                contract.get('wait_chain_sample_line_limit') == 12 and
                contract.get('wait_chain_total_line_limit') == 512 and
                contract.get('wait_chain_dedup_table') == 16 and
                contract.get('wait_chain_max_turnstile_locks') == 12 and
                contract.get('wait_chain_max_thread_locks') == 3 and
                {'_nabu_ui_watch_thread_wait_chain', '_nabu_ui_watch_task_wait_chain_snapshot'} <=
                set(contract.get('symbols_by_object', {}).get('thread.c', [])) and
                b'nabu_ui_watch_task_wait_chain_snapshot(' in exec_source and
                b'NabuUIOwner: sample=' in exec_source and
                b'NabuUIOwner: budget sample=' in exec_source and
                b'NABU_UI_WATCH_CHAIN_V1' in thread_source and
                chain_helpers_ok(constants['EXEC_HELPER'], thread_helper),
                'UI v6 requires a separately enabled, try-only, bounded owner chain')
    require(exec_source.count(constants['EXEC_HELPER'].encode()) == 1 and
            all(exec_source.count(after.encode()) == 1 for _, after in constants['EXEC_PAIRS']) and
            all(exit_source.count(after.encode()) == 1 for _, after in constants['EXIT_PAIRS']) and
            thread_source.count(constants['THREAD_HELPER'].encode()) == 1 and
            all(thread_source.count(after.encode()) == 1 for _, after in constants['THREAD_PAIRS']),
            'Actual XNU sources lack the exact UI hooks')
    require(capture.get('hooks', {}).get('bsd/kern/kern_exec.c') == sha(exec_source) and
            capture.get('hooks', {}).get('bsd/kern/kern_exit.c') == sha(exit_source) and
            capture.get('hooks', {}).get('osfmk/kern/thread.c') == sha(thread_source),
            'UI XNU sources differ from the capture report')
    symbols = contract.get('symbols')
    require(isinstance(symbols, list) and symbols and len(set(symbols)) == len(symbols) and
            all(name.startswith('_nabu_ui_watch_') for name in symbols),
            'UI exported symbol contract malformed')
    mapping = contract.get('symbols_by_object')
    require(isinstance(mapping, dict) and set(mapping) == {'kern_exec.c', 'thread.c'} and
            sorted(sum(mapping.values(), [])) == sorted(symbols), 'UI per-object symbol map malformed')
    objects = {}
    for name, wanted in mapping.items():
        relative = ('osfmk/DEVELOPMENT/thread.o' if name == 'thread.c'
                    else 'bsd/DEVELOPMENT/kern_exec.o')
        object_path = ('outputs/tree/build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/' + relative)
        obj = read(object_path)
        actual = object_symbols(obj)
        require(set(wanted) <= set(actual), 'Actual XNU object lacks UI emitted entries: ' + name)
        objects[name] = {'path': object_path, 'sha256': sha(obj),
                         'definitions': {symbol: actual[symbol] for symbol in wanted}}
    final, _ = candidate_definitions(candidate, METAL_PROFILE, symbols)
    return {'compiled': True, 'trigger': 'nabu-ui-watch=1', 'contract': contract,
            **({'target_association': contract['target_association']} if version >= 2 else {}),
            'generator_sha256': sha(generator), 'exec_source_sha256': sha(exec_source),
            'exit_source_sha256': sha(exit_source), 'thread_source_sha256': sha(thread_source),
            'objects': objects,
            'final_definitions': {name: final[name] for name in symbols},
            'first_incarnation_only': True, 'runtime_qualified': False, 'hardware_tested': False}
