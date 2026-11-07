"""Bind the optional post-mmap service observer to actual source and linked objects."""
import ast
import hashlib

SOURCE = 'outputs/tree/.cache/xnu-work/osfmk/kern/thread.c'
OBJECT = 'outputs/tree/build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/osfmk/DEVELOPMENT/thread.o'
SYMBOLS = ('_nabu_service_wait_start', '_nabu_service_wait_snapshot')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def qualify(read, candidate):
    from nabu_gpu_ci import candidate_definitions, json_object, METAL_PROFILE
    from nabu_ui_watch_qualification import object_symbols
    capture = json_object(read('outputs/tree/build/nabu-log/source-report.json'))
    enabled = capture.get('service_wait_watch', False)
    require(type(enabled) is bool, 'Service observer build flag must be Boolean')
    if not enabled:
        require(b'NabuService:' not in candidate and not any(symbol.encode() in candidate for symbol in SYMBOLS),
                'Disabled kernel retains the service worker')
        return dict(compiled=False, runtime_qualified=False)
    require(capture.get('ui_watch') is True and capture.get('ls_mmap_watch') is True,
            'Service worker requires the LS diagnostic build')
    generator = read('device/scripts/nabu_service_wait_source.py')
    constants = {}
    for node in ast.parse(generator.decode()).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in ('CONTRACT', 'HELPER'):
                require(name not in constants, 'Duplicate service observer constant')
                constants[name] = ast.literal_eval(node.value)
    require(set(constants) == {'CONTRACT', 'HELPER'}, 'Missing service observer constants')
    contract = constants['CONTRACT']
    require(contract.get('version') == 3 and contract.get('symbols') == list(SYMBOLS) and
            contract.get('targets') == ['SpringBoard', 'backboardd', 'runningboardd', 'lsd'] and
            contract.get('detail_trigger') == 'nabu-service-wait=2' and
            contract.get('detail_targets') == ['SpringBoard', 'backboardd', 'runningboardd', 'lsd', 'peer', 'nehelper'] and
            contract.get('fallback_peer_name') == 'profiled' and
            contract.get('stack_thread_filter') == 'blocked except workqueue return (trap 368, hint 15)' and
            contract.get('named_peer_detail') is True and
            contract.get('peer_identity') == 'pid and proc_uniqueid, checked under proc_lock' and
            contract.get('stack_signature') == 'proc_uniqueid, tid, pc, lr, trap, receive_name, sp, fp, options, send_name' and
            contract.get('reply_copyout_pid') == 'historical PID only; current lookup does not prove historical process identity' and
            contract.get('stack_read_attempts_per_signature') == 2 and
            contract.get('max_passes') == 16 and contract.get('interval_seconds') == 10 and
            contract.get('max_threads_scanned') == 128 and contract.get('max_rows_per_process') == 32 and
            contract.get('first_thread_always_sampled') is True and
            contract.get('priority_stack_rows') == 'first row of every target before remaining threads, nehelper and peer first' and
            contract.get('max_processes_per_pass') == 6 and contract.get('new_worker') is True and
            contract.get('max_frames') == 24 and contract.get('max_stack_walks_per_pass') == 48 and
            contract.get('publication_bytes') == 131072 and contract.get('maximum_line_bytes') == 255 and
            contract.get('worker_may_block') is True and
            str(contract.get('user_memory_read', '')).startswith('detail only:') and
            contract.get('changes_syscall_result') is False,
            'Unexpected service observer contract')
    identity = sha(generator.replace(b'\r\n', b'\n'))
    helper = constants['HELPER'].replace('__NABU_SERVICE_SOURCE_ID__', identity).encode()
    source, obj = read(SOURCE), read(OBJECT)
    require(source.endswith(helper) and source.count(helper) == 1 and
            capture.get('hooks', {}).get('osfmk/kern/thread.c') == sha(source) and
            capture.get('service_wait_generator_sha256') == sha(generator), 'Service source binding mismatch')
    stamp = ('NABUSERVICE_SOURCE_SHA256=' + identity).encode()
    require(stamp in obj and stamp in candidate, 'Service worker object/kernel identity mismatch')
    definitions = object_symbols(obj, prefix='_nabu_service_')
    require(set(SYMBOLS) <= set(definitions), 'Service worker object lacks real code')
    final, _ = candidate_definitions(candidate, METAL_PROFILE, SYMBOLS)
    mmap_source = read('outputs/tree/.cache/xnu-work/bsd/kern/kern_mman.c')
    mmap_object = read('outputs/tree/build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/bsd/DEVELOPMENT/kern_mman.o')
    require(b'        nabu_service_wait_start();' in mmap_source and SYMBOLS[0].encode() in mmap_object,
            'Actual mmap caller lacks the service worker hook')
    exec_source = read('outputs/tree/.cache/xnu-work/bsd/kern/kern_exec.c')
    exec_object = read('outputs/tree/build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/bsd/DEVELOPMENT/kern_exec.o')
    require(b'    nabu_service_wait_snapshot();' in exec_source and SYMBOLS[1].encode() in exec_object,
            'Actual writer callback lacks the service snapshot hook')
    require(b'NabuService: row' in candidate and b'NabuService: pulse' in candidate and
            b'NabuService: port' in candidate and b'NabuService: frames' in candidate and
            b'NabuService: copyout' in candidate,
            'Final kernel lacks the service record formats')
    return dict(compiled=True, contract=contract, source_sha256=sha(source), generator_sha256=sha(generator),
                embedded_source_identity=identity, object_sha256=sha(obj),
                object_definitions={symbol: definitions[symbol] for symbol in SYMBOLS},
                final_definitions={symbol: final[symbol] for symbol in SYMBOLS}, runtime_qualified=False)
