#!/usr/bin/env python3
"""Convert pinned speaker protocol sources and inventory a captured nabu FDT.

All input is offline. The converter imports three standalone APR/AFE/ASM
state machines, preserving their source license and wire behavior. Resource
inventory reports captured declarations, independently of driver qualification.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'tools'))
from nabu_wifi_board import Fdt, cells, parent, require, strings


DONOR_REPOSITORY = 'https://github.com/buhuo666/XIAOMI-PAD-5_nabu-on-IOS'
DONOR_SHA = '56c7364f5c083583b07eea24dded38a9ee932e5f'
IMPORTS = {
    'NabuAfeTdm.h': ('97d4b908f9a8a8dd0cb97cdf5456360589e26d6f10b6f70f930b1b51a005ec00',
                     'NabuAudioAfeTdm.h', 'NabuAfeTdm', 'NabuAudioAfeTdm'),
    'NabuAsmPcm.h': ('1597da2526c22f7e53e1ea73184dd16b0bbdadc6ea0fc8eea08b7bb5fa1d0431',
                     'NabuAudioAsmPcm.h', 'NabuAsmPcm', 'NabuAudioAsmPcm'),
    'NabuAsmPlayback.h': ('c40b9ba24e8cec56413d4e60c5e845ceb74bc7631a80e1e9131920c5ae278bfe',
                          'NabuAudioPlayback.h', 'NabuAsmPlayback', 'NabuAudioPlayback'),
}
FORMATTING = {
    'NabuAfeTdm.h': (
        '            for(unsigned i=2;i<8;++i)put16(p+12+i*2,0xffff);break;\n',
        '            for (unsigned i = 2; i < 8; ++i) {\n'
        '                put16(p + 12 + i * 2, 0xffff);\n'
        '            }\n'
        '            break;\n',
    ),
}
MISSING = {
    'adsp_firmware': ['adsp.mdt and original-index adsp.bNN sizes and SHA-256',
                      'read-only provider and PAS1 metadata lifetime'],
    'shared_power_owner': ['serialized AOP adsp load-state mailbox',
                           'CX level 385 and XO0 vote ownership with GPU/Wi-Fi'],
    'adsp_transport': ['SMEM host2 allocation under lock3 and APPS allocator lock',
                       'fresh SMP2P readiness/fatal/stop generation',
                       'APR GET_STATE and framework/AFE/ASM/ADM API versions'],
    'audio_dma_owner': ['SID0x1b21 exact stream ownership and shared fault IRQ',
                        'owned page/I/O VA bounds and publication',
                        'live firmware address-tag convention and stop-before-release'],
    'speaker_protection': ['per-amplifier DEVID/REVID/OTP status',
                           'WMFW and TL/TR/BL/BR coefficients with SHA-256',
                           'this unit CAL_R/CAL_STATUS/CAL_CHECKSUM/CH_BAL'],
    'speaker_bus': ['GENI SE7 or validated GPIO98/99 control implementation',
                    'GPIO92 reset owner and QUAT TDM pin/clock owner',
                    'actual mixer route, TDM slots and AFE instance-ID support'],
    'target_audio_abi': ['21H16 AudioServerPlugIn driver/host interface layouts',
                         '21H16 Speaker UID, VirtualAudio route and J171 tuning acceptance',
                         'native PCM character-device sink attach/detach lifecycle'],
    'current_kernel_bindings': ['current XNU build headers and kernel symbol identities',
                                'IOKit mapping/unmapping, cache and lock signatures',
                                'current device personality and explicit build roots'],
}


def convert_sources(source_root):
    """Fail on donor drift before returning any converted header."""
    converted, records = {}, []
    for name, (digest, output, old_namespace, new_namespace) in IMPORTS.items():
        relative = Path('patches/nabu-audio') / name
        data = (source_root / relative).read_bytes()
        require(hashlib.sha256(data).hexdigest() == digest, 'Pinned audio source drift ' + name)
        text = data.decode('utf-8')
        require(text.count('#pragma once\n') == 1 and
                text.startswith('// SPDX-License-Identifier: BSD-2-Clause-Patent\n'),
                'Unexpected audio source license/header ' + name)
        require(text.count(old_namespace) == 2, 'Unexpected audio namespace ' + name)
        text = text.replace(old_namespace, new_namespace)
        edits = ['namespace', 'compile gate', 'source identity']
        if name in FORMATTING:
            original, formatted = FORMATTING[name]
            require(text.count(original) == 1, 'Audio formatting source drift ' + name)
            text = text.replace(original, formatted, 1)
            edits.append('separate loop and switch break for GCC warning checks')
        binding = ('#pragma once\n#include "NabuAudio.h"\n'
                   '// Imported from ' + DONOR_REPOSITORY + '\n'
                   '// Commit ' + DONOR_SHA + '\n'
                   '// Source SHA-256 ' + digest + '\n'
                   '#if XNU_NABU_AUDIO\n')
        text = text.replace('#pragma once\n', binding, 1) + '#endif\n'
        result = text.encode('utf-8')
        converted[output] = result
        records.append(dict(source=relative.as_posix(), source_sha256=digest,
                            output=output, output_sha256=hashlib.sha256(result).hexdigest(),
                            license='BSD-2-Clause-Patent',
                            edits=edits))
    return converted, records


def provider_arguments(dt, path, key, count_key):
    """Resolve phandles by each provider's declared argument width."""
    raw, at, result = cells(dt.nodes[path][key]), 0, []
    while at < len(raw):
        handle = raw[at]
        require(handle in dt.phandles, 'Unresolved audio phandle ' + key)
        provider = dt.phandles[handle]
        width = dt.scalar(provider, count_key)
        require(width <= 16 and at + 1 + width <= len(raw), 'Truncated audio provider ' + key)
        result.append(dict(provider=provider, arguments=raw[at + 1:at + 1 + width]))
        at += 1 + width
    require(result, 'Empty audio provider list ' + key)
    return result


def inherited_interrupts(dt, path):
    ancestor = path
    while 'interrupt-parent' not in dt.nodes[ancestor]:
        require(ancestor != '/', 'Missing audio interrupt parent')
        ancestor = parent(ancestor)
    controller = dt.reference(ancestor, 'interrupt-parent')
    width = dt.scalar(controller, '#interrupt-cells')
    raw = cells(dt.nodes[path]['interrupts'])
    require(width > 0 and len(raw) % width == 0, 'Invalid audio interrupt cells')
    return dict(controller=controller,
                specifiers=[raw[at:at + width] for at in range(0, len(raw), width)])


def pin_states(dt, path):
    result = []
    for index, name in enumerate(strings(dt.nodes[path]['pinctrl-names'])):
        states = []
        for handle in cells(dt.nodes[path]['pinctrl-' + str(index)]):
            require(handle in dt.phandles, 'Unresolved audio pinctrl state')
            node = dt.phandles[handle]
            properties = {child: {key: value.hex() for key, value in props.items()}
                          for child, props in dt.nodes.items()
                          if child == node or child.startswith(node + '/')}
            states.append(dict(path=node, properties=properties))
        result.append(dict(name=name, states=states))
    return result


def board_inventory(data):
    dt = Fdt(data)
    root = dt.nodes['/']
    require('qcom,sm8150' in strings(root['compatible']) and
            (strings(root.get('model', b'\0')) == ['NABU'] or
             any('nabu' in value.lower() for value in strings(root['compatible']))),
            'Audio FDT is not nabu/SM8150')
    adsp = dt.one([path for path in dt.compatible('qcom,pil-tz-generic')
                   if dt.nodes[path].get('qcom,firmware-name') == b'adsp\0'], 'ADSP PIL')
    require(dt.scalar(adsp, 'qcom,pas-id') == 1, 'Unexpected ADSP PAS ID')
    memory = dt.reference(adsp, 'memory-region')
    glink = dt.one([path for path, props in dt.nodes.items()
                    if props.get('label') == b'adsp\0' and props.get('transport') == b'smem\0'],
                   'ADSP SMEM GLINK edge')
    require(dt.scalar(glink, 'qcom,remote-pid') == 2, 'Unexpected ADSP GLINK host')
    apr = dt.one([path for path, props in dt.nodes.items()
                  if path.startswith(glink + '/') and
                  props.get('qcom,glink-channels') == b'apr_audio_svc\0'], 'APR GLINK channel')
    smp2p = dt.one([path for path in dt.compatible('qcom,smp2p')
                    if dt.scalar(path, 'qcom,remote-pid') == 2], 'ADSP SMP2P')
    ipc = cells(dt.nodes[smp2p]['qcom,ipc'])
    require(len(ipc) == 3 and ipc[0] in dt.phandles, 'Invalid ADSP IPC tuple')
    ipc_path = dt.phandles[ipc[0]]
    ion = dt.one(dt.compatible('qcom,msm-audio-ion'), 'audio ION')
    iommus = provider_arguments(dt, ion, 'iommus', '#iommu-cells')
    sound = dt.one(dt.compatible('qcom,sm8150-asoc-snd-tavil'), 'Tavil sound card')
    require(dt.nodes[sound].get('status', b'okay\0') in (b'ok\0', b'okay\0'),
            'Captured Tavil sound card disabled')
    amplifiers = []
    for path in dt.compatible('cirrus,cs35l41'):
        props = dt.nodes[path]
        bus = parent(path)
        require('qcom,i2c-geni' in strings(dt.nodes[bus]['compatible']), 'Unexpected amplifier bus')
        address = dt.scalar(path, 'reg')
        require(address < 128, 'Invalid amplifier I2C address')
        amplifiers.append(dict(path=path, address=address, bus=bus, bus_reg=dt.regs(bus),
                               bus_clocks=provider_arguments(dt, bus, 'clocks', '#clock-cells'),
                               bus_interrupts=inherited_interrupts(dt, bus),
                               bus_pins=pin_states(dt, bus),
                               reset=provider_arguments(dt, path, 'reset-gpios', '#gpio-cells'),
                               interrupts=inherited_interrupts(dt, path),
                               fast_switch=strings(props['cirrus,fast-switch']),
                               properties={key: value.hex() for key, value in props.items()}))
    require(len(amplifiers) == 4 and sorted(item['address'] for item in amplifiers) == list(range(0x40, 0x44)),
            'Expected four distinct nabu speaker amplifiers')
    for path in (adsp, glink, ion, *(item['bus'] for item in amplifiers)):
        require(dt.nodes[path].get('status', b'okay\0') in (b'ok\0', b'okay\0'),
                'Captured audio resource disabled ' + path)
    return dict(schema_version=1, fdt_sha256=dt.sha256, declaration_only=True,
                adsp=dict(path=adsp, pas_id=1, memory_path=memory, memory_reg=dt.regs(memory),
                          cx_supply=dt.reference(adsp, 'vdd_cx-supply'),
                          cx_vote=cells(dt.nodes[adsp]['qcom,vdd_cx-uV-uA']),
                          clocks=provider_arguments(dt, adsp, 'clocks', '#clock-cells'),
                          mailbox=provider_arguments(dt, adsp, 'mboxes', '#mbox-cells'),
                          interrupts=provider_arguments(dt, adsp, 'interrupts-extended', '#interrupt-cells')),
                glink=dict(path=glink, host=2, apr_path=apr,
                           intents=cells(dt.nodes[apr]['qcom,intents']),
                           mailbox=provider_arguments(dt, glink, 'mboxes', '#mbox-cells'),
                           interrupts=inherited_interrupts(dt, glink)),
                smp2p=dict(path=smp2p, items=cells(dt.nodes[smp2p]['qcom,smem']),
                           local_pid=dt.scalar(smp2p, 'qcom,local-pid'), remote_pid=2,
                           ipc=dict(path=ipc_path, reg=dt.regs(ipc_path), offset=ipc[1], bit=ipc[2]),
                           interrupts=inherited_interrupts(dt, smp2p)),
                dma=dict(path=ion, iommus=iommus,
                         address_tag_mask=cells(dt.nodes[ion]['qcom,smmu-sid-mask']),
                         smmu_reg=[dict(path=item['provider'], reg=dt.regs(item['provider'])) for item in iommus]),
                sound=dict(path=sound, model=strings(dt.nodes[sound]['qcom,model']),
                           wsa_max_devices=dt.scalar(sound, 'qcom,wsa-max-devs'),
                           pins=pin_states(dt, sound),
                           slim_controllers=dt.compatible('qcom,slim-ngd'),
                           tavil_codecs=dt.compatible('qcom,tavil-slim-pgd'),
                           soundwire_masters=dt.compatible('qcom,swr-wcd')),
                amplifiers=sorted(amplifiers, key=lambda item: item['address']),
                qualification=dict(hardware_qualified=False, default_enabled=False,
                                   decision='reject_hardware_integration', missing=MISSING))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--fdt', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    converted, sources = convert_sources(args.source_root)
    inventory = board_inventory(args.fdt.read_bytes())
    require(not args.output.exists(), 'Audio output already exists')
    args.output.mkdir(parents=True)
    for name, data in converted.items():
        (args.output / name).write_bytes(data)
    report = dict(schema_version=1, donor_repository=DONOR_REPOSITORY, donor_sha=DONOR_SHA,
                  converter_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  sources=sources, board=inventory)
    (args.output / 'source-receipt.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(result='protocol_sources_converted_hardware_rejected',
                         output=str(args.output.resolve()), sources=len(sources)), indent=2))


if __name__ == '__main__':
    main()
