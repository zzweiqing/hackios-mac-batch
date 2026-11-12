"""Generate the pinned Wi-Fi network host archive sources for XNU 10063.

make(inputs, headers) is an in-memory preparation step. Input keys are the
origin-prefixed paths returned by dependency_manifest(). Header keys are paths
relative to the actual .cache/xnu-work tree, before compilation.
apply(root, inputs=None) stages only build/nabu-wifi-network/source and its
receipt inside an assembled UniXNU build tree. CI can fetch each declared input
by its commit and SHA, without checking a vendor tree into the project.
qualify(inputs, headers, files, report, objects=None) reproduces preparation and
optionally checks every compiled ARM64/iOS17 object. It leaves link, hardware,
and the 21H16 Apple80211 userland ABI qualifications pending.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import struct
import urllib.request


UPSTREAM_REPOSITORY = 'oosexgang/hakios-xnu-kernel'
UPSTREAM_COMMIT = '96ffbc532e970f3540885755d457e401e04d4707'
DONOR_REPOSITORY = 'buhuo666/XIAOMI-PAD-5_nabu-on-IOS'
DONOR_COMMIT = '56c7364f5c083583b07eea24dded38a9ee932e5f'
XNU_COMMIT = 'd8b80295118ef25ac3a784134bcf95cd8e88109f'
VERSION = 1
OUTPUT = 'build/nabu-wifi-network'

# These are the entire external source/notice set consumed by this generator.
# The platform-wide hakios.input.h and MiniDrivers.h dependencies are removed
# by the exact local patches. Their other devices have no role in this archive.
UPSTREAM_FILES = {
    'LICENSE': ('licenses/hakios/LICENSE', '15c02b5b5f49938db79fbc85ff1905ece5d3da7a2c32db5de5b9897eb4fa5f4a'),
    'LICENSE.APSL': ('licenses/hakios/LICENSE.APSL', 'e5881019d8766c1e88a5fe1dbca4ba40c78011d41fcb18f6e9f50df60182685b'),
    'NOTICE': ('licenses/hakios/NOTICE', 'eebf042546bef730eeab9648b8ff8faaf290af0af66e8b27c99af59b11e72234'),
    'drivers/net/hakios.net.c': ('bsd/dev/hakios.net.c', '5ed99766af4858137fc41f39498fb384e8d142220411159522fd8b8bdb5507e5'),
    'drivers/wifi/hakios.lx.c': ('bsd/dev/hakios.lx.c', '7ee76d56202c9c5529842d45ee20c9ea2410940719b365c95db08207fb809f84'),
    'drivers/wifi/hakios.sta.c': ('bsd/dev/hakios.sta.c', '9ea972a32152402badbbcc162846fe00e61f02f2de355ea8cd770cfd2b462174'),
    'drivers/wifi/hakios.apple80211.c': ('bsd/dev/hakios.apple80211.c', 'd4763a51413998c0c46a0eff0c8bcef5716b59402ceab6d473e524b4431e86b9'),
    'drivers/wifi/hakios.wlan.cpp': ('iokit/Kernel/hakios.wlan.cpp', 'c09833d2d1f486f0623fa588985bde692434b0e8023f99e23869bf0895aad551'),
    'drivers/modem/hakios.qmi.c': ('bsd/dev/hakios.qmi.c', '5feb3ddc9c4244701e2f462e77500a732a3fe1f55d43127a2341ca9a55c1c0a1'),
    'xnu/files/bsd/sys/hakios.lx.h': ('bsd/sys/hakios.lx.h', 'f323a4adfb7a459ad1f3d83cdbdda5110df051ad9293d2c2a63c4220db961f99'),
    'xnu/files/bsd/sys/hakios.sta.h': ('bsd/sys/hakios.sta.h', 'd98aa48457d2b1b63779b37a39878539a13f22a924161e6526e3568f0759798f'),
    'xnu/files/bsd/sys/hakios.net.h': ('bsd/sys/hakios.net.h', '05d377ba6b71cc485676fe3632f49bfa30d2cbc1a6476ec723abb0f8ed12fff4'),
    'xnu/files/bsd/sys/hakios.qmi.h': ('bsd/sys/hakios.qmi.h', 'a9c358f7a797a534c84c77b7f05f43f507345160e72ad366ff739213214f0648'),
    'xnu/files/bsd/sys/hakios.qrtr.h': ('bsd/sys/hakios.qrtr.h', 'd9658ba4ddbc941cf201edfadbfdb38248c4939641d394eb7fecb50be1180e66'),
    'xnu/files/iokit/Kernel/MiniIONetworkStack.cpp': ('iokit/Kernel/MiniIONetworkStack.cpp', '3b7cdf77ac3e2a472c55f7dd622d04979782e46d8bd3589c535a5d97a252ef12'),
}
DONOR_FILES = {
    'patches/8796/nabu-wifi-station-lifecycle.patch': '8e0fd0c6403b55bb43c38b8acbe0cd0cbfff6e418fcf7b277546ee5bf06e3717',
    'patches/8796/nabu-wifi-control-state.patch': '48ec2501f3e7ff43a5c2be96b3b8adb629f0fb7a3c384f4c537f52be48d5073e',
}
LOCAL_PATCHES = {
    'nabu-wifi-network-xnu10063.patch': '3e783ecff0ed9bab74219019107ba40acdd4c13958618881790fd85c0fa08d21',
    'nabu-wifi-network-apple80211-disabled.patch': '1fe660664e8befa6ec639b1718f4164c6897d08f23b06f4c1b8e36d059490af9',
    'nabu-wifi-network-registry.patch': 'd2d0dc66d3f77a1e7438ae9dc13b2d07e8d291ed0ccbac2a3ef0868168935fbb',
}
# Check actual prepared headers, rather than supplying an old exported SDK.
# apply checks the actual prepared tree against these API header pins.
XNU_HEADERS = {
    'bsd/net/kpi_interface.h': 'e8356b426a0c8f5bbb77831f424240e60cd4db4cc99d8ed4c3f69d8688dcd1d1',
    'bsd/sys/kpi_mbuf.h': 'eedca05854340d642a3f63638244211aa155407226c3617494fff231a71ec7a4',
    'bsd/sys/random.h': 'e9bd91c0eece75af7c44d0c89ceb2911da6929e884329c5777c870a9aa11573c',
    'bsd/sys/kern_event.h': 'b945de0f064db8028e2f96d6146ec30a7db6323bd397170c2c76c69cfe064a51',
    'bsd/net/if_ether.h': 'a19d8b01f66c873fb0d910be1e388474a7b1fd842fbbfd01df7394e91f4ced0d',
    'osfmk/kern/thread.h': 'daecd6003e7048356b3eb0f7dd17587b2a7f0e30fd9e0904bb489f3aeb3f5068',
    'osfmk/kern/clock.h': 'a2657effae6e918f73f815d9c53e73054cd0a716a38a3ccd77b71050e957afe6',
    'osfmk/kern/locks.h': '9fe6c3169d91077f51c9864f3372f87981763e958b95934f91a82d5d7ddeab63',
    'osfmk/kern/kalloc.h': '1c44d54ce13549d24fb11fb31fafe3678be43daf15e237b5382dc4dd625afa0c',
    'osfmk/kern/sched_prim.h': '44d7b5b2df700913c933ae7f22e3bf9131410273e56a103adfe1b508b2d5c1ea',
    'iokit/IOKit/IOService.h': '4ab37d4968a4def538eaefc730ee09232182c66e378a5ec89b4c8fede848642d',
    'iokit/IOKit/IOUserClient.h': '01c419c05d471eac01292153afb650dd6abfccd30e0cc3b48ad8ffe6e7793cf9',
    'libkern/libkern/OSReturn.h': '1019477a9f4505a137be2ed14613b9aab1fff1d886b52f06c85ae7ad5cb317d2',
    'libkern/libkern/c++/OSMetaClass.h': '0b47cb07db5854013123fce2972592d63997c8a7bced80b7365bb04af4614647',
}

LX_HOST_FUNCTIONS = (
    'alloc', 'free', 'panic', 'nanoseconds', 'thread_self', 'thread',
    'lock', 'unlock', 'sleep', 'wakeup', 'random',
)
EXPORTS = {
    'bsd/dev/hakios.lx.c': ['lx_os_' + name for name in LX_HOST_FUNCTIONS],
    'bsd/dev/hakios.net.c': ['hakios_net_' + name for name in (
        'attach', 'input', 'input_unit', 'link_state', 'link_state_unit', 'init')],
    'bsd/dev/hakios.sta.c': ['hakios_sta_' + name for name in (
        'attach', 'invalidate', 'join_commit', 'lost', 'present', 'powered', 'busy',
        'ask_power', 'ask_scan', 'ask_join', 'ask_join_standing', 'ask_leave',
        'heard', 'state', 'sample_signal', 'channels', 'address')],
    'bsd/dev/hakios.qmi.c': [
        'hakios_qmi_encode', 'hakios_qmi_decode', 'hakios_qmi_set_transport',
        'hakios_qmi_handle_init_transport', 'qmi_handle_init', 'qmi_handle_release',
        'qmi_add_lookup', 'hakios_qmi_connect', 'qmi_txn_init', 'qmi_send_request',
        'qmi_txn_cancel', 'hakios_qmi_txn_wait_ms', 'qmi_response_type_v01_ei'],
    'bsd/dev/hakios.apple80211.c': ['hakios_apple80211_' + name for name in (
        'ioctl', 'event', 'signal', 'summary')],
    'bsd/dev/NabuWifiNetworkAbi.c': ['nabu_wifi_network_abi_identity'],
    'iokit/Kernel/hakios.wlan.cpp': ['HakiosWLANStart'],
    'iokit/Kernel/MiniIONetworkStack.cpp': ['nabu_wifi_network_stack_start'],
    'iokit/Kernel/NabuWifiNetwork.cpp': [
        'nabu_wifi_network_register_classes', 'nabu_wifi_network_classes_ready'],
}
CONTRACT = {
    'version': VERSION,
    'xnu': '10063.141.1',
    'xnu_commit': XNU_COMMIT,
    'license': 'APSL-2.0 for the derived kernel sources; fetched notices accompany the output',
    'apple80211_21h16_abi': {'enabled': False, 'qualified': False,
                           'reason': '20F66 reference layouts lack original 21H16 evidence'},
    'runtime_qualified': False,
    'link_qualified': False,
    'hardware_hooks_defined': False,
    'station': 'donor generation/invalidation/join-commit semantics; serialized worker',
    'registry': 'property-only HakiOS classes and explicit post-IOKit board-class registration',
    'backend': 'separately supplied ath10k object and remapped nabu platform callbacks',
    'backend_dependencies': ['lx_os_network and all radio/firmware/IRQ hooks remain external',
                             'hakios_qrtr_ops transport must be supplied by the control owner'],
}

BRIDGE_HEADER = '''/* Nabu network host registration, derived kernel code under APSL-2.0. */
#ifndef NABU_WIFI_NETWORK_H
#define NABU_WIFI_NETWORK_H
#include <stdbool.h>
#include <libkern/OSReturn.h>
#ifdef __cplusplus
extern "C" {
#endif
OSReturn nabu_wifi_network_register_classes(const char *, void (*)(void));
bool nabu_wifi_network_classes_ready(void);
bool nabu_wifi_network_stack_start(void);
#ifdef __cplusplus
}
#endif
#endif
'''
BRIDGE_SOURCE = '''/* Nabu network host registration, derived kernel code under APSL-2.0. */
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSSymbol.h>
#include <sys/nabu_wifi_network.h>

extern "C" OSReturn OSKextRegisterBoardClasses(const char *, void (*)(void));
static unsigned class_state;

extern "C" bool
nabu_wifi_network_classes_ready(void)
{
    return __atomic_load_n(&class_state, __ATOMIC_ACQUIRE) == 2;
}

extern "C" OSReturn
nabu_wifi_network_register_classes(const char *identifier, void (*constructors)(void))
{
    if (identifier == nullptr || identifier[0] == 0 || constructors == nullptr)
        return kOSReturnError;
    unsigned expected = 0;
    if (!__atomic_compare_exchange_n(&class_state, &expected, 1, false,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return expected == 2 ? kOSReturnSuccess : kOSReturnError;
    const char *names[] = {"IONetworkController", "IOEthernetController", "IO80211Controller",
                          "IONetworkInterface", "HakiosWLAN", "IONetworkStack",
                          "IONetworkStackUserClient"};
    for (const char *name : names) {
        const OSSymbol *symbol = OSSymbol::withCString(name);
        if (symbol == nullptr) {
            __atomic_store_n(&class_state, 3, __ATOMIC_RELEASE);
            return kOSReturnError;
        }
        bool exists = OSMetaClass::getMetaClassWithName(symbol) != nullptr;
        symbol->release();
        if (exists) {
            __atomic_store_n(&class_state, 3, __ATOMIC_RELEASE);
            return kOSReturnError;
        }
    }
    OSReturn result = OSKextRegisterBoardClasses(identifier, constructors);
    // A failed constructor transaction can leave partial registrations. Retain
    // the failure for this boot so a retry cannot register those classes again.
    __atomic_store_n(&class_state, result == kOSReturnSuccess ? 2 : 3, __ATOMIC_RELEASE);
    return result;
}
'''
ABI_SOURCE = '''/* Fixed C boundary sizes, derived kernel code under APSL-2.0. */
#include <stddef.h>
#include <sys/hakios.lx.h>
#include <sys/hakios.net.h>
#include <sys/hakios.qmi.h>
_Static_assert(sizeof(void *) == 8 && sizeof(unsigned long) == 8, "arm64 LP64 boundary");
_Static_assert(sizeof(struct hakios_sta_bss) == 1080, "station BSS boundary");
_Static_assert(sizeof(struct hakios_sta_scan) == 168, "station scan boundary");
_Static_assert(sizeof(struct hakios_sta_join) == 144, "station join boundary");
_Static_assert(sizeof(struct hakios_sta_state) == 1088, "station state boundary");
_Static_assert(sizeof(struct hakios_sta_ops) == 64, "station callbacks boundary");
_Static_assert(offsetof(struct hakios_sta_ops, address) == 56, "station address boundary");
_Static_assert(sizeof(struct hakios_net_link) == 40, "network link boundary");
_Static_assert(offsetof(struct hakios_net_link, transmit) == 24, "network TX boundary");
_Static_assert(sizeof(struct qmi_elem_info) == 32, "QMI descriptor boundary");
_Static_assert(sizeof(struct qmi_txn) == 48, "QMI transaction boundary");
_Static_assert(sizeof(struct sockaddr_qrtr) == 12, "QRTR address boundary");
const char nabu_wifi_network_abi_identity[] = "NABU_WIFI_NETWORK_C_ABI_V1";
'''


def sha(content):
    return hashlib.sha256(content).hexdigest()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def dependency_manifest():
    """Return the complete fixed external input set, with source URLs and SHA."""
    result = {}
    for origin, repository, commit, files in (
            ('upstream', UPSTREAM_REPOSITORY, UPSTREAM_COMMIT, UPSTREAM_FILES),
            ('donor', DONOR_REPOSITORY, DONOR_COMMIT, DONOR_FILES)):
        for path, value in files.items():
            digest = value[1] if origin == 'upstream' else value
            result[origin + '/' + path] = dict(
                repository=repository, commit=commit, path=path, sha256=digest,
                url=f'https://raw.githubusercontent.com/{repository}/{commit}/{path}')
    return result


def _validated(content, digest, label):
    require(isinstance(content, bytes), 'Expected raw bytes for ' + label)
    require(sha(content) == digest, 'Pinned input SHA mismatch: ' + label)
    return content


def fetch_inputs():
    """Fetch only the declared public files. Validate bytes before returning."""
    def fetch(item):
        key, record = item
        request = urllib.request.Request(record['url'], headers={'User-Agent': 'nabu-wifi-network-source'})
        with urllib.request.urlopen(request, timeout=60) as response:
            content = response.read(1 << 20)
            require(not response.read(1), 'Oversized source input: ' + key)
        return key, _validated(content, record['sha256'], key)
    with ThreadPoolExecutor(max_workers=4) as pool:
        return dict(pool.map(fetch, dependency_manifest().items()))


def _slice(text, first, last):
    require(text.count(first) == 1 and text.count(last) == 1, 'LinuxKPI section anchor drift')
    begin, end = text.index(first), text.index(last)
    require(begin < end, 'LinuxKPI section order drift')
    return text[begin:end]


def _lx_host(text):
    """Retain exact upstream host blocks, excluding all radio/backend adapters."""
    return (text[:text.index('#include ')] +
            _slice(text, '#include <kern/clock.h>', 'extern vm_offset_t ') +
            _slice(text, 'static LCK_GRP_DECLARE(lx_lock_group', '/* ---- memory ') +
            _slice(text, 'void *\nlx_os_alloc', '/*\n * In one physical piece') +
            _slice(text, 'void\nlx_os_panic', 'unsigned\nlx_os_option'))


def _patch(files, content):
    """Apply this fixed unified-diff subset with exact positions and no fuzz.

    All paths must already exist in the virtual source set. No file additions,
    renames, shell execution, path traversal, or newline recovery are accepted.
    """
    lines = content.decode('utf-8').splitlines(keepends=True)
    result, touched, index = dict(files), set(), 0
    require(lines, 'Empty network patch')
    while index < len(lines):
        require(lines[index].startswith('--- a/'), 'Unexpected network patch header')
        path = lines[index][6:].rstrip('\n')
        require(path in result and path not in touched, 'Unknown or repeated network patch target: ' + path)
        touched.add(path)
        index += 1
        require(index < len(lines) and lines[index] == '+++ b/' + path + '\n', 'Network patch path mismatch')
        index += 1
        original, output, cursor, hunks = result[path].splitlines(keepends=True), [], 0, 0
        while index < len(lines) and lines[index].startswith('@@ '):
            match = re.fullmatch(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n', lines[index])
            require(match is not None, 'Malformed network patch hunk')
            old_start, old_count, new_start, new_count = (
                int(match[1]), int(match[2] or 1), int(match[3]), int(match[4] or 1))
            require(old_start > 0 and new_start > 0, 'Network patch must modify existing lines')
            start = old_start - 1
            require(cursor <= start <= len(original), 'Network patch position drift: ' + path)
            output.extend(original[cursor:start])
            cursor = start
            require(len(output) == new_start - 1, 'Network patch output position drift: ' + path)
            index += 1
            removed = added = 0
            while index < len(lines) and not lines[index].startswith(('@@ ', '--- a/')):
                tag, body = lines[index][:1], lines[index][1:]
                require(tag in (' ', '+', '-') and lines[index].endswith('\n'), 'Invalid network patch line')
                if tag in (' ', '-'):
                    require(cursor < len(original) and original[cursor] == body,
                            'Network patch context drift: ' + path)
                    cursor += 1
                    removed += 1
                if tag in (' ', '+'):
                    output.append(body)
                    added += 1
                index += 1
            require((removed, added) == (old_count, new_count), 'Network patch hunk count drift')
            hunks += 1
        require(hunks > 0, 'Network patch lacks hunks')
        result[path] = ''.join(output + original[cursor:])
    return result


def _patch_directory(directory=None):
    if directory is not None:
        return Path(directory)
    return Path(__file__).resolve().parents[1] / 'nabu-device/patches'


def make(inputs, headers, patch_dir=None):
    """Prepare byte-bound source files and a deterministic compilation receipt."""
    dependencies = dependency_manifest()
    require(set(inputs) == set(dependencies), 'Incomplete or undeclared network source input set')
    require(set(headers) == set(XNU_HEADERS), 'Incomplete or undeclared XNU API header set')
    for path, digest in XNU_HEADERS.items():
        _validated(headers[path], digest, path)
    for key, record in dependencies.items():
        _validated(inputs[key], record['sha256'], key)
    files = {}
    for path, (target, _) in UPSTREAM_FILES.items():
        text = inputs['upstream/' + path].decode('utf-8')
        require('\r' not in text and '\0' not in text, 'Noncanonical upstream source: ' + path)
        files[target] = text if text.endswith('\n') else text + '\n'
    lx_original = files['bsd/dev/hakios.lx.c']
    files['bsd/dev/hakios.lx.c'] = _lx_host(lx_original)
    changes = [dict(operation='LinuxKPI host section selection',
                    before_sha256=sha(lx_original.encode()),
                    after_sha256=sha(files['bsd/dev/hakios.lx.c'].encode()))]
    patches = [('donor/' + path, inputs['donor/' + path]) for path in DONOR_FILES]
    for name, digest in LOCAL_PATCHES.items():
        content = (_patch_directory(patch_dir) / name).read_bytes()
        patches.append((name, _validated(content, digest, name)))
    for name, content in patches:
        before = files
        files = _patch(files, content)
        changes.append(dict(patch=name, sha256=sha(content), targets={
            path: dict(before_sha256=sha(before[path].encode()), after_sha256=sha(text.encode()))
            for path, text in files.items() if text != before[path]}))
    files['bsd/sys/nabu_wifi_network.h'] = BRIDGE_HEADER
    files['iokit/Kernel/NabuWifiNetwork.cpp'] = BRIDGE_SOURCE
    files['bsd/dev/NabuWifiNetworkAbi.c'] = ABI_SOURCE
    generator_sha = sha(Path(__file__).read_bytes())
    units = {}
    for path, exports in EXPORTS.items():
        symbol = 'nabu_wifi_network_unit_' + Path(path).stem.replace('.', '_')
        value = 'NABUWIFI_NETWORK_UNIT_SHA256=' + sha(files[path].encode()) + ';GEN=' + generator_sha
        files[path] += ('\n#ifdef __cplusplus\nextern "C" {\n#endif\n'
                        f'extern const char {symbol}[];\n'
                        f'const char {symbol}[] __attribute__((used)) = "{value}";\n'
                        '#ifdef __cplusplus\n}\n#endif\n')
        units[path] = dict(language='c++' if path.endswith('.cpp') else 'c',
                           exports=['_' + name for name in exports] + ['_' + symbol],
                           source_identity=value)
    encoded = {path: text.encode('utf-8') for path, text in files.items()}
    report = dict(
        version=VERSION, contract=deepcopy(CONTRACT), generator_sha256=generator_sha,
        dependencies=dependencies, xnu_headers=dict(XNU_HEADERS),
        canonicalization='UTF-8 and LF; append a final LF only when the pinned source lacks it',
        outputs={path: sha(content) for path, content in encoded.items()},
        transformations=changes, translation_units=units, compiled=False,
        compile=dict(
            deployment='arm64-apple-ios17.0',
            recipe='current XNU C recipe per C unit; current IOPlatformExpert.cpo.json per C++ unit',
            retarget_helper='existing build-nabu-platform.py compile_command',
            c_standard='gnu17', cxx_standard='current XNU C++ recipe',
            include_directories=['source/bsd', '.cache/xnu-work/osfmk'],
            defines=['KERNEL', 'KERNEL_PRIVATE', 'XNU_KERNEL_PRIVATE', 'MACH_KERNEL_PRIVATE',
                     'BSD_KERNEL_PRIVATE', '__APPLE_API_PRIVATE', '__APPLE_API_UNSTABLE'],
            c_flags=['-mgeneral-regs-only', '-ffreestanding', '-fno-common'],
            constructor_units=['iokit/Kernel/hakios.wlan.cpp', 'iokit/Kernel/MiniIONetworkStack.cpp'],
            constructor_registration='remove __mod_init_func from late objects, retain/globalize its actual '
                                     'constructors, pass their combined callback to '
                                     'nabu_wifi_network_register_classes with the current kmod name',
            kernel_startup_sections='preserve lock-group, mutex and kalloc startup entries; force-load archive',
            header_dependency_closure='actual compilation dependency files must be collected by the builder'),
        qualification_dependencies=['nabu_idle_ci.py', 'nabu_ui_watch_qualification.py'],
    )
    return dict(files=encoded, report=report)


def apply(root, inputs=None, patch_dir=None):
    """Stage a fresh or identical generated set, rejecting any existing drift."""
    root = Path(root).resolve(strict=True)
    xnu = root / '.cache/xnu-work'
    headers = {path: (xnu / path).read_bytes() for path in XNU_HEADERS}
    prepared = make(fetch_inputs() if inputs is None else inputs, headers, patch_dir)
    output = root / OUTPUT
    payloads = {'source/' + path: content for path, content in prepared['files'].items()}
    payloads['source-report.json'] = (json.dumps(prepared['report'], indent=2, sort_keys=True) + '\n').encode()
    # Preflight the complete write set before creating anything. A partial first
    # write can be retried only when all its existing members still match.
    source = output / 'source'
    if source.exists():
        existing = {path.relative_to(output).as_posix() for path in source.rglob('*') if path.is_file()}
        require(existing <= set(payloads), 'Undeclared files in existing network source set')
    for relative, content in payloads.items():
        path = output / relative
        require(path.resolve().is_relative_to(root), 'Network output escaped its build root')
        require(not any(parent.is_symlink() for parent in (path, *path.parents)), 'Network output follows symlink')
        if path.exists():
            require(path.is_file() and path.read_bytes() == content, 'Existing network source drift: ' + relative)
    for relative, content in payloads.items():
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            with path.open('xb') as stream:
                stream.write(content)
    return prepared['report']


def qualify(inputs, headers, files, report, objects=None, patch_dir=None):
    """Reproduce fixed inputs and emitted bytes, then check supplied objects."""
    prepared = make(inputs, headers, patch_dir)
    require(report == prepared['report'], 'Network source receipt drift')
    require(set(files) == set(prepared['files']), 'Network generated file set drift')
    for path, content in prepared['files'].items():
        require(files[path] == content, 'Network generated source drift: ' + path)
    result = dict(source_qualified=True, compiled=False, link_qualified=False,
                  runtime_qualified=False, apple80211_21h16_abi_qualified=False)
    if objects is None:
        return result
    units = report['translation_units']
    require(set(objects) == set(units), 'Incomplete network object set')
    from nabu_idle_ci import _image
    records = {}
    for path, unit in units.items():
        content = objects[path]
        image = _image(content, 1)
        offset, deployment = 32, None
        for _ in range(struct.unpack_from('<I', content, 16)[0]):
            command, size = struct.unpack_from('<II', content, offset)
            if command == 0x32:
                require(deployment is None and size >= 24, 'Network object deployment record drift')
                deployment = struct.unpack_from('<II', content, offset + 8)
            offset += size
        require(deployment == (2, 0x110000), 'Network object needs the current iOS17 deployment: ' + path)
        require(set(unit['exports']) <= set(image['names']), 'Missing network object exports: ' + path)
        require(unit['source_identity'].encode() in content, 'Network compiled source identity mismatch: ' + path)
        defined = set(image['names'])
        require(not any(name.startswith(('_gic_v3_', '_hakios_wifi_', '_lx_start', '_lx_stop', '_lx_prepare',
                                        '_lx_transmit', '_nabu_ath10k_os_')) for name in defined),
                'Network host object defines an external platform/backend hook')
        if path.endswith('hakios.lx.c'):
            require({name for name in defined if name.startswith('_lx_os_')} == set(unit['exports']) -
                    {name for name in unit['exports'] if name.startswith('_nabu_wifi_network_unit_')},
                    'LinuxKPI host object has unexpected platform hooks')
        records[path] = dict(sha256=sha(content), exports=unit['exports'],
                             constructors=[name for name in defined if 'GLOBAL__sub_I_' in name])
    result.update(compiled=True, objects=records)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, help='Directory of origin-prefixed pinned files; otherwise fetch')
    parser.add_argument('--patch-dir', type=Path)
    args = parser.parse_args()
    inputs = None
    if args.inputs is not None:
        inputs = {path: (args.inputs / path).read_bytes() for path in dependency_manifest()}
    report = apply(args.root, inputs, args.patch_dir)
    print(json.dumps(dict(version=report['version'], sources=len(report['translation_units']),
                          compiled=False, apple80211_21h16_abi_qualified=False)))


if __name__ == '__main__':
    main()
