"""Qualify captured nabu Hall resources offline and generate their source header.

The FDT decoder is reused from tools/nabu_wifi_board.py. This helper binds the
fixed vendor register description and the captured SW_LID node. It emits a
source candidate and an ADT digest requirement for the optional polling worker.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[4]
DONOR_COMMIT = '56c7364f5c083583b07eea24dded38a9ee932e5f'
TLMM_COMMIT = '71b6effd2dfa8f703dd1ea17acd1323b2fd3cf6c'
TLMM_SHA256 = '7c32df2250e26f6678f22e6b4f1e9dd791a6b4da796a3b326b7f0837192c92a4'
FDT_PROPERTY = 'nabu-hall-source-fdt-sha256'
ORIGINAL_KERNEL_SHA256 = 'f7d1952c7a21633d212eccf288e77444fff0cc86976db5de292f6819c2ffa1b2'
ORIGINAL_BACKBOARD_SHA256 = '6e362a46a2b46eb2741ecc6fcb50ffecb2fbc299641159045475361e62b34634'
HES_MISSING = [
    'original native HES service class and vtable binding',
    'event-service matching and vendor usage classification',
    'current-state copyEvent response after initial report',
    'initial service discovery and BSSystemHasCapability("hall-effect-sensor") result',
    'termination availability and consumer subscription semantics',
]
PROBE_CLASS = 'NabuHallHesAbiProbe'
HES_PROBE_SOURCE = '''// SPDX-License-Identifier: BSD-2-Clause-Patent
// Actions ABI probe for the original IOHIDDevice report entry. Unregistered.
#include "OriginalHidDeviceABI.h"
class NabuHallHesAbiProbe : public IOHIDDevice {
    OSDeclareDefaultStructors(NabuHallHesAbiProbe)
public:
    IOReturn newReportDescriptor(IOMemoryDescriptor **output) const override
    {
        if (output) *output = nullptr;
        return kIOReturnUnsupported;
    }
    IOReturn submit(IOMemoryDescriptor *report);
};
IOReturn NabuHallHesAbiProbe::submit(IOMemoryDescriptor *report)
{
    if (!report) return kIOReturnBadArgument;
    return IOHIDDevice::handleReport(report, 0, 0);
}
OSDefineMetaClassAndStructors(NabuHallHesAbiProbe, IOHIDDevice)
static_assert(sizeof(NabuHallHesAbiProbe) == 0xd0, "original IOHIDDevice storage");
'''


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fdt_decoder():
    path = ROOT / 'tools/nabu_wifi_board.py'
    spec = importlib.util.spec_from_file_location('nabu_hall_fdt_decoder', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def board_contract(data, tlmm_source):
    require(hashlib.sha256(tlmm_source).hexdigest() == TLMM_SHA256,
            'Hall TLMM source differs from the fixed nabu vendor input')
    source = tlmm_source.decode('utf-8')
    require(len(re.findall(r'\[9\]\s*=\s*PINGROUP\(9,\s*NORTH,', source)) == 1,
            'Hall GPIO9 NORTH group is missing or ambiguous')
    for expression in (r'#define NORTH\s+0x00900000', r'#define REG_SIZE\s+0x1000',
                       r'\.ctl_reg = base \+ REG_SIZE \* id',
                       r'\.io_reg = base \+ 0x4 \+ REG_SIZE \* id',
                       r'\.mux_bit = 2', r'\.oe_bit = 9', r'\.in_bit = 0'):
        require(re.search(expression, source), 'Hall TLMM register description drift')

    decoder = fdt_decoder()
    tree = decoder.Fdt(data)
    require(tree.nodes['/'].get('model') == b'NABU\0', 'Hall input is not the captured NABU model')
    switches = []
    for bus in tree.compatible('gpio-keys'):
        for path, props in tree.nodes.items():
            if path != '/' and decoder.parent(path) == bus and \
                    props.get('linux,input-type') == b'\0\0\0\x05' and \
                    props.get('linux,code') == bytes(4):
                switches.append(path)
    path = tree.one(switches, 'EV_SW / SW_LID Hall switch')
    for node in (path, decoder.parent(path)):
        require(tree.nodes[node].get('status', b'okay\0') in (b'okay\0', b'ok\0'),
                'Hall switch or gpio-keys bus is disabled')
    gpio = decoder.cells(tree.nodes[path].get('gpios', b''))
    require(len(gpio) == 3 and gpio[1:] == [9, 1], 'Hall must select active-low GPIO9')
    require(gpio[0] in tree.phandles, 'Hall GPIO controller phandle is unresolved')
    controller = tree.phandles[gpio[0]]
    props = tree.nodes[controller]
    require('qcom,sm8150-pinctrl' in decoder.strings(props.get('compatible', b'')) and
            'gpio-controller' in props and tree.scalar(controller, '#gpio-cells') == 2 and
            'interrupt-controller' in props and tree.scalar(controller, '#interrupt-cells') == 2,
            'Hall controller is not the nabu TLMM GPIO / interrupt domain')
    require(props.get('status', b'okay\0') in (b'okay\0', b'ok\0'), 'Hall TLMM is disabled')
    names = decoder.strings(props.get('reg-names', b''))
    regs = tree.regs(controller)
    require(len(names) == len(regs) and names.count('pinctrl') == 1,
            'Hall TLMM register names are missing or ambiguous')
    tlmm = regs[names.index('pinctrl')]
    gpio_pa = tlmm['base'] + 0x00900000 + 9 * 0x1000
    require(tlmm['base'] == 0x03000000 and gpio_pa + 0x1000 <= tlmm['base'] + tlmm['bytes'],
            'Hall GPIO9 falls outside the qualified TLMM resource')
    require(tree.scalar(path, 'debounce-interval') == 15 and 'gpio-key,wakeup' in tree.nodes[path],
            'Hall debounce or wake declaration differs from captured nabu')
    require('gpio-key,level-trigger' not in tree.nodes[path] and 'interrupts' not in tree.nodes[path],
            'Hall trigger needs a new qualification')

    ancestor = controller
    while 'interrupt-parent' not in tree.nodes[ancestor]:
        require(ancestor != '/', 'TLMM interrupt parent is missing')
        ancestor = decoder.parent(ancestor)
    interrupt_parent = tree.reference(ancestor, 'interrupt-parent')
    require('qcom,pdc-sm8150' in decoder.strings(tree.nodes[interrupt_parent].get('compatible', b'')) and
            tree.scalar(interrupt_parent, '#interrupt-cells') == 3,
            'TLMM first parent is not the captured PDC domain')
    interrupt_cells = decoder.cells(props.get('interrupts', b''))
    require(interrupt_cells == [0, 208, 0], 'TLMM PDC-domain interrupt specifier drift')
    gic = tree.reference(interrupt_parent, 'interrupt-parent')
    require('arm,gic-v3' in decoder.strings(tree.nodes[gic].get('compatible', b'')) and
            tree.scalar(gic, '#interrupt-cells') == 3, 'PDC parent is not GICv3')

    return dict(
        schema_version=1, result='hall_resources_qualified_host_only',
        source_fdt_sha256=tree.sha256, donor_commit=DONOR_COMMIT,
        tlmm_commit=TLMM_COMMIT, tlmm_source_sha256=TLMM_SHA256,
        hall_node=path, gpio_controller=controller, gpio=9, active_low=True,
        input_type='EV_SW', input_code='SW_LID', debounce_ms=15, poll_ms=16,
        gpio_physical=gpio_pa, map_bytes=0x1000, tlmm_resource=tlmm,
        interrupt_domain=controller, gpio_key_trigger='both edges in fixed vendor gpio_keys.c',
        declared_wakeup=True, tlmm_parent=interrupt_parent,
        tlmm_parent_specifier=interrupt_cells, pdc_parent=gic, gic_intid=None,
        interrupt_routing_qualified=False, register_writes=False,
        adt_requirement=dict(path='/chosen', property=FDT_PROPERTY, bytes=32,
                             value_hex=tree.sha256),
        compiled_default=0, boot_argument='nabu-hall=1',
        output_property='IODeviceTree:/chosen/nabu-hall-closed',
        native_hes_21h16_qualified=False, hardware_tested=False,
        native_hes_missing=HES_MISSING,
    )


def hid_helpers():
    """Reuse the same original HID header/vtable qualifier as nabu touch."""
    def load(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    touch = load('nabu_hall_touch_abi', Path(__file__).with_name('nabu_touch_build.py'))
    prelink = load('nabu_hall_prelink', ROOT / 'device_bringup/ipados17_inputs/tools/NativePrelink-3380d300/native_prelink.py')
    return touch, prelink


def hes_probe_plan(kernel, backboard):
    require(hashlib.sha256(kernel).hexdigest() == ORIGINAL_KERNEL_SHA256,
            'HES probe requires the original 21H16 kernel source pin')
    require(hashlib.sha256(backboard).hexdigest() == ORIGINAL_BACKBOARD_SHA256,
            'HES probe requires the original 21H16 backboardd source pin')
    touch, prelink = hid_helpers()
    methods = touch.original_methods(kernel, prelink)
    return {
        'schema_version': 1, 'result': 'original_hid_abi_probe_prepared',
        'kernel_sha256': ORIGINAL_KERNEL_SHA256, 'backboard_sha256': ORIGINAL_BACKBOARD_SHA256,
        'base_class': 'IOHIDDevice', 'base_bytes': 0xd0, 'virtual_slots': len(methods),
        'report_slot': 181, 'report_original_address': hex(methods[181]),
        'report_native_address': hex(methods[181] + touch.SLIDE),
        'prototype': 'IOReturn IOHIDDevice::handleReport(IOMemoryDescriptor *, unsigned, IOOptionBits)',
        'probe_class': PROBE_CLASS, 'source': 'NabuHallHesAbiProbe.cpp',
        'touch_abi_source_sha256': hashlib.sha256(Path(touch.__file__).read_bytes()).hexdigest(),
        'original_header_sha256': hashlib.sha256(touch.abi_header().encode()).hexdigest(),
        'probe_source_sha256': hashlib.sha256(HES_PROBE_SOURCE.encode()).hexdigest(),
        'consumer': {'event_type': 3, 'usage_page': 0xff09, 'usage': 1, 'down_field': 0x30002,
                     'capability_api': 'BSSystemHasCapability', 'capability_key': 'hall-effect-sensor'},
        'native_hes_21h16_qualified': False, 'native_hes_missing': HES_MISSING,
        'probe_registered': False, 'hardware_tested': False,
        'build_executor': 'existing GitHub Actions XNU compilation record and Apple compiler',
    }, touch.abi_header()


def qualify_hes_probe_object(kernel, raw):
    """Actions calls this on its actual compiled object before making aliases."""
    touch, prelink = hid_helpers()
    require(hashlib.sha256(kernel).hexdigest() == ORIGINAL_KERNEL_SHA256,
            'HES object qualification requires the original kernel pin')
    methods = touch.original_methods(kernel, prelink)
    symbols, compiled = touch.object_vtable(prelink, raw, f'__ZTV{len(PROBE_CLASS)}{PROBE_CLASS}')
    own = (f'__ZN{len(PROBE_CLASS)}{PROBE_CLASS}', f'__ZNK{len(PROBE_CLASS)}{PROBE_CLASS}')
    bindings = {
        '__ZN11IOHIDDeviceC2EPK11OSMetaClass': touch.IOHIDDEVICE_CTOR + touch.SLIDE,
        '__ZN11IOHIDDeviceD2Ev': touch.IOHIDDEVICE_DTOR + touch.SLIDE,
        '__ZN11IOHIDDevice10gMetaClassE': touch.IOHIDDEVICE_META + touch.SLIDE,
        '__ZTV11IOHIDDevice': touch.IOHIDDEVICE_VTABLE - 16 + touch.SLIDE,
    }
    owned = []
    for slot, name in enumerate(compiled):
        if name.startswith(own):
            owned.append(slot)
        elif '11IOHIDDevice' in name:
            bindings[name] = methods[slot] + touch.SLIDE
        elif slot >= touch.IOSERVICE_SLOTS or slot in touch.ORIGINAL_OVERRIDES:
            raise ValueError('HES probe has an unqualified original slot ' + str(slot))
    require(owned == [0, 1, 7, 180], 'HES ABI probe overrides unexpected slots')
    undefined = {name for name, _, kind in symbols if kind == 1 and '11IOHIDDevice' in name}
    require(undefined <= bindings.keys() and any('12handleReport' in name for name in undefined),
            'HES probe is missing its real handleReport import or has an unbound import')
    return dict(result='original_hid_probe_object_qualified', object_sha256=hashlib.sha256(raw).hexdigest(),
                owned_slots=owned, bindings={name: hex(bindings[name]) for name in sorted(undefined)},
                native_hes_21h16_qualified=False, native_hes_missing=HES_MISSING)


def resources_header(contract):
    require(contract.get('result') == 'hall_resources_qualified_host_only' and
            contract.get('gpio_physical') == 0x03909000 and contract.get('map_bytes') == 0x1000 and
            re.fullmatch('[0-9a-f]{64}', contract.get('source_fdt_sha256', '')),
            'Hall resource header requires a qualified contract')
    digest = bytes.fromhex(contract['source_fdt_sha256'])
    rows = ['    ' + ', '.join(f'0x{byte:02x}' for byte in digest[at:at + 8]) + ','
            for at in range(0, len(digest), 8)]
    return '\n'.join([
        '// SPDX-License-Identifier: BSD-2-Clause-Patent',
        '// Generated by nabu_hall_source.py from a captured FDT and fixed vendor source.',
        '// Donor Hall source commit ' + DONOR_COMMIT,
        '// Vendor TLMM source commit ' + TLMM_COMMIT,
        '// Vendor TLMM SHA-256 ' + TLMM_SHA256,
        '#pragma once', '#include <stdint.h>', '', 'namespace nabu_hall {',
        'constexpr uint64_t GpioPhysical = 0x03909000ULL;',
        'constexpr unsigned MapBytes = 0x1000;',
        'constexpr uint8_t SourceFdtSha256[32] = {', *rows, '};',
        '} // namespace nabu_hall', '',
    ])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fdt', type=Path)
    parser.add_argument('--tlmm-source', type=Path)
    parser.add_argument('--hes-abi-probe', action='store_true')
    parser.add_argument('--original-kernel', type=Path)
    parser.add_argument('--original-backboard', type=Path)
    parser.add_argument('--hes-probe-object', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.hes_abi_probe:
        require(args.original_kernel and args.original_backboard and not args.fdt and not args.tlmm_source,
                'HES probe requires original kernel/backboard inputs and its own output')
        kernel = args.original_kernel.read_bytes()
        report, header = hes_probe_plan(kernel, args.original_backboard.read_bytes())
        qualified = qualify_hes_probe_object(kernel, args.hes_probe_object.read_bytes()) if args.hes_probe_object else None
        args.output.mkdir(parents=True, exist_ok=False)
        (args.output / 'OriginalHidDeviceABI.h').write_text(header, encoding='utf-8', newline='\n')
        (args.output / 'NabuHallHesAbiProbe.cpp').write_text(HES_PROBE_SOURCE, encoding='utf-8', newline='\n')
        (args.output / 'hes-probe-plan.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        if qualified:
            (args.output / 'object-qualification.json').write_text(json.dumps(qualified, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report, indent=2))
        return
    require(args.fdt and args.tlmm_source and not args.hes_probe_object and
            not args.original_kernel and not args.original_backboard,
            'Hall resources require FDT/TLMM inputs')
    contract = board_contract(args.fdt.read_bytes(), args.tlmm_source.read_bytes())
    header = resources_header(contract)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'NabuHallResources.h').write_text(header, encoding='utf-8', newline='\n')
    (args.output / 'hall-contract.json').write_text(json.dumps(contract, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(contract, indent=2))


if __name__ == '__main__':
    main()
