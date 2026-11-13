"""Generate the pinned Wi-Fi network host archive sources for XNU 10063.

make(inputs, headers) is an in-memory preparation step. Input keys are the
origin-prefixed paths returned by dependency_manifest(). Header keys are paths
relative to the actual .cache/xnu-work tree, before compilation.
apply(root, inputs=None) stages only build/nabu-wifi-network/source and its
receipt inside an assembled UniXNU build tree. CI can fetch each declared input
by its commit and SHA, without checking a vendor tree into the project.
qualify(inputs, headers, files, report, objects=None) reproduces preparation and
optionally checks every compiled ARM64/iOS17 object. The original-bound core
21H16 layouts are enabled. Extended events, remaining ioctl layouts, final
linking and hardware execution retain separate pending qualifications.
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
VERSION = 2
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
    'nabu-wifi-network-xnu10063.patch': 'c06fd9c04896a88d3da2e5b2b2c7bb221220db5574d798eeb23e137aa737dbf6',
    'nabu-wifi-network-apple80211-disabled.patch': 'f7bf478854dfb3c76d7b498e2f624d0926c80a40d3a951995aecb8e0d1c11b65',
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

ABI_EVIDENCE = {'product_version': '17.7',
 'product_build': '21H16',
 'device_class': 'j171ap',
 'io80211_image': {'path': '/System/Library/PrivateFrameworks/IO80211.framework/IO80211',
                   'address': 8050970624,
                   'size': 323584,
                   'uuid': '155a5c63-5ba1-34f2-86a5-672ed429db23'},
 'cache_uuid': '5eb3de32-eed3-377b-9a3b-572b08c888cf',
 'symbols_uuid': '164b858d-ca6f-3d24-a6f6-5b9aaef35a54',
 'facts_path': 'device_bringup/out/nabu-wifi-21h16-abi-20261113-01/abi-instruction-facts-02.json',
 'facts_sha256': '5dbd78d5fad20c058452f1b33c793a840475efea24104a414c944931673679be',
 'bound_files': {'input-binding.json': '7eea51458cc6056bfe862cd7f2b151e010abbf4fb63f1cd85cfcf1cf5c850e0d',
                 'wifid-binding.json': '1932fa22f52de83bd4aaf8bbadb55f0678f85e913c3912b6db658f7d3b3c2e72',
                 'consumer-metadata.json': '0f43395b4d19345ebb9e9bb0a07a31cfc25e9cf99874835911c4666f35e73260',
                 'consumers-02/receipt.json': '43c6bd266dec5bb7cbea5b77c59d535ac6b6004d2c569071a5c06c6c494d2d3f'},
 'build_manifest_sha256': '8dfc8f210a98d30ef9a88818efeffe060970016e7ccb2d10a4a9d9e31a64e882',
 'os_volume_uuid': 'F577F6BD-3BB9-4864-BBDF-972FC2E94AE3',
 'systemos_volume_uuid': 'C374ACD3-75FE-4FAD-B02E-FC3C9A86DA11',
 'wifid': {'path': '/usr/sbin/wifid',
           'uuid': 'f94c4b50-df8f-3ff9-803f-4ccaf765d557',
           'bytes': 2593808,
           'sha256': '6b5d8cb46865552511c6c028a2c9d55878f3844fe4cbf1d012051cf8f275293b'}}

ABI_FUNCTIONS = {'performAssociation': {'address': '0x1dfe1d31c',
                        'bytes': 8420,
                        'sha256': '87ad1a96db6f4aa9637554b8bd68b8c76cb0b6a7989b71c6f395eec20184a81d'},
 'Apple80211ScanAsync': {'address': '0x1dfe116cc',
                         'bytes': 636,
                         'sha256': '6a7ace373dea4cc90bd264f49fb54005e51f3c926bc1fefdc69c4bee75939f34'},
 'getScanData': {'address': '0x1dfe11948',
                 'bytes': 2800,
                 'sha256': '597c96860a800160ba719193b68cfb8c4729486ccf121b09ed7bf7b00af98795'},
 'dispatchAsyncScanEvent': {'address': '0x1dfe07948',
                            'bytes': 1332,
                            'sha256': '692645fa183395d199fb2f17cd9105bbb58627657dd258c249be0e07aa1d68f5'},
 'addScanResultToList': {'address': '0x1dfe03be4',
                         'bytes': 5100,
                         'sha256': '31cb4ce7c2068668f68d68d8d9788c877e7933521712cc7483587942dfeabf3e'},
 'dispatchLinkChangedEvent': {'address': '0x1dfe2a1f4',
                              'bytes': 728,
                              'sha256': 'fa29ac83e34ab62f501edebe8b8c13b1cf0e8675894a0eb049151c45c7d1d63e'},
 'eventRead': {'address': '0x1dfe02ae4',
               'bytes': 4328,
               'sha256': 'e2510dc17b23174e2e82d1be6b21560002d19ccf9c807006259bfb447d366630'},
 'dispatchAsyncAssocEvent': {'address': '0x1dfe2b1d8',
                             'bytes': 2952,
                             'sha256': '0815f6d2d9bfe2f37241f3dcbe54c4dc58115937698ec3b685d7b66d086877bd'},
 'Apple80211IOCTLSetWrapper': {'address': '0x1dfe09008',
                               'bytes': 2952,
                               'sha256': '4bda7d75cdfc662428ca672c4245d0a7478ec1279042ccf76a0c09702965bf02'}}

ABI_INSTRUCTIONS = {'assoc_request_type': ['performAssociation', '0x1dfe1d9c4', '88028052', 'mov', 'w8, #0x14'],
 'assoc_request_bytes': ['performAssociation', '0x1dfe1d9c8', '096b8052', 'mov', 'w9, #0x358'],
 'assoc_length_store': ['performAssociation', '0x1dfe1d9d0', 'e91b02b9', 'str', 'w9, [sp, #0x218]'],
 'assoc_payload_base': ['performAssociation', '0x1dfe1d9d4', 'e8c30891', 'add', 'x8, sp, #0x230'],
 'assoc_ssid_length': ['performAssociation', '0x1dfe1d40c', 'f73f02b9', 'str', 'w23, [sp, #0x23c]'],
 'assoc_ssid_bytes': ['performAssociation', '0x1dfe1d434', '03410091', 'add', 'x3, x8, #0x10'],
 'assoc_bssid_low4': ['performAssociation', '0x1dfe1d7c8', 'e86302b9', 'str', 'w8, [sp, #0x260]'],
 'assoc_bssid_high2': ['performAssociation', '0x1dfe1d7c4', 'e9cb0479', 'strh', 'w9, [sp, #0x264]'],
 'assoc_mode': ['performAssociation', '0x1dfe1da18', 'e86b0479', 'strh', 'w8, [sp, #0x234]'],
 'assoc_auth_lower': ['performAssociation', '0x1dfe1de78', 'e86f0479', 'strh', 'w8, [sp, #0x236]'],
 'assoc_auth_upper': ['performAssociation', '0x1dfe1db4c', 'e8730479', 'strh', 'w8, [sp, #0x238]'],
 'assoc_key_version': ['performAssociation', '0x1dfe1dfdc', 'e86b02b9', 'str', 'w8, [sp, #0x268]'],
 'assoc_key_length': ['performAssociation', '0x1dfe1edfc', 'f96f02b9', 'str', 'w25, [sp, #0x26c]'],
 'assoc_key_cipher': ['performAssociation', '0x1dfe1edd0', 'e87302b9', 'str', 'w8, [sp, #0x270]'],
 'assoc_key_material': ['performAssociation', '0x1dfe1edd8', 'a0220191', 'add', 'x0, x21, #0x48'],
 'assoc_rsn_data': ['performAssociation', '0x1dfe1f12c', '01390391', 'add', 'x1, x8, #0xce'],
 'assoc_rsn_length': ['performAssociation', '0x1dfe1f130', '02310391', 'add', 'x2, x8, #0xcc'],
 'assoc_wsec_flags': ['performAssociation', '0x1dfe1dab4', 'e88304b9', 'str', 'w8, [sp, #0x480]'],
 'scan_async_request_bytes': ['Apple80211ScanAsync', '0x1dfe117e4', '08b28252', 'mov', 'w8, #0x1590'],
 'scan_async_length_store': ['Apple80211ScanAsync', '0x1dfe117e8', 'a8831ab8', 'stur', 'w8, [x29, #-0x58]'],
 'scan_async_request_type': ['Apple80211ScanAsync', '0x1dfe117c8', '48018052', 'mov', 'w8, #0xa'],
 'scan_correlation_offset': ['Apple80211ScanAsync', '0x1dfe11790', '88a98252', 'mov', 'w8, #0x154c'],
 'scan_correlation_copy_bytes': ['Apple80211ScanAsync', '0x1dfe11808', '02088052', 'mov', 'w2, #0x40'],
 'scan_constructor_bytes': ['getScanData', '0x1dfe119a0', '01b28252', 'mov', 'w1, #0x1590'],
 'scan_channel_entry_base': ['getScanData', '0x1dfe12264', '4b250929', 'stp', 'w11, w9, [x10, #0x48]'],
 'scan_flags': ['getScanData', '0x1dfe11db0', 'a88609f9', 'str', 'x8, [x21, #0x1308]'],
 'scan_named_ssid_entries': ['getScanData', '0x1dfe11b5c', '09638252', 'mov', 'w9, #0x1318'],
 'scan_result_request_type': ['dispatchAsyncScanEvent', '0x1dfe07a94', '68018052', 'mov', 'w8, #0xb'],
 'scan_result_bytes': ['dispatchAsyncScanEvent', '0x1dfe07a98', '89998052', 'mov', 'w9, #0x4cc'],
 'scan_result_length_store': ['dispatchAsyncScanEvent', '0x1dfe07aa4', 'a98318b8', 'stur', 'w9, [x29, #-0x78]'],
 'scan_result_correlation_offset': ['dispatchAsyncScanEvent', '0x1dfe07ab0', '55311291', 'add', 'x21, x10, #0x48c'],
 'scan_result_correlation_copy_bytes': ['dispatchAsyncScanEvent', '0x1dfe07adc', '02088052', 'mov', 'w2, #0x40'],
 'scan_result_ssid_length': ['addScanResultToList', '0x1dfe03ca4', '88834139', 'ldrb', 'w8, [x28, #0x60]'],
 'scan_result_ssid': ['addScanResultToList', '0x1dfe03d2c', '82870191', 'add', 'x2, x28, #0x61'],
 'scan_result_bssid': ['addScanResultToList', '0x1dfe03d4c', '80730091', 'add', 'x0, x28, #0x1c'],
 'scan_result_age': ['addScanResultToList', '0x1dfe046b4', '82130291', 'add', 'x2, x28, #0x84'],
 'scan_result_ie_length': ['addScanResultToList', '0x1dfe04388', '8a174179', 'ldrh', 'w10, [x28, #0x8a]'],
 'scan_result_ie_data': ['addScanResultToList', '0x1dfe04384', '97330291', 'add', 'x23, x28, #0x8c'],
 'link_event_minimum': ['dispatchLinkChangedEvent', '0x1dfe2a210', '5f800071', 'cmp', 'w2, #0x20'],
 'link_event_rssi': ['dispatchLinkChangedEvent', '0x1dfe2a27c', '02130091', 'add', 'x2, x24, #4'],
 'link_event_reason': ['dispatchLinkChangedEvent', '0x1dfe2a2dc', '02530091', 'add', 'x2, x24, #0x14'],
 'link_event_subreason': ['dispatchLinkChangedEvent', '0x1dfe2a308', '02630091', 'add', 'x2, x24, #0x18'],
 'event_payload_offset': ['eventRead', '0x1dfe02bcc', 'a8a20091', 'add', 'x8, x21, #0x28'],
 'event_interface_offset': ['eventRead', '0x1dfe02b24', '20600091', 'add', 'x0, x1, #0x18'],
 'event_interface_bytes': ['eventRead', '0x1dfe02b30', '02028052', 'mov', 'w2, #0x10'],
 'event_code_offset': ['eventRead', '0x1dfe02b80', 'a21640b9', 'ldr', 'w2, [x21, #0x14]'],
 'assoc_done_scalar_length_branch': ['eventRead', '0x1dfe02fd0', '9f120071', 'cmp', 'w20, #4'],
 'assoc_done_scalar_payload': ['eventRead', '0x1dfe02fdc', 'b72a40b9', 'ldr', 'w23, [x21, #0x28]'],
 'scan_done_scalar_length_branch': ['eventRead', '0x1dfe02fe4', '9f120071', 'cmp', 'w20, #4'],
 'scan_done_scalar_payload': ['eventRead', '0x1dfe02ff0', 'b42a40b9', 'ldr', 'w20, [x21, #0x28]'],
 'assoc_result_request_type': ['dispatchAsyncAssocEvent', '0x1dfe2b61c', 'a8028052', 'mov', 'w8, #0x15'],
 'assoc_result_request_value': ['dispatchAsyncAssocEvent', '0x1dfe2b634', 'e06740b9', 'ldr', 'w0, [sp, #0x64]'],
 'assoc_extended_event_observed_offset': ['dispatchAsyncAssocEvent',
                                          '0x1dfe2b4f0',
                                          'c89640b9',
                                          'ldr',
                                          'w8, [x22, #0x94]'],
 'ioctl_request_type_offset': ['Apple80211IOCTLSetWrapper', '0x1dfe090ac', '781240b9', 'ldr', 'w24, [x19, #0x10]'],
 'ioctl_request_length_offset': ['Apple80211IOCTLSetWrapper',
                                 '0x1dfe0994c',
                                 '6d1a40b9',
                                 'ldr',
                                 'w13, [x19, #0x18]']}


ABI_SCAN_WRAPPER_INSTRUCTIONS = {'scan_request_uuid_generate': ['Apple80211ScanAsync', '0x1dfe117a8', 'bdb39194', 'bl', '#0x1e227e69c'],
 'scan_request_uuid_unparse': ['Apple80211ScanAsync', '0x1dfe117b4', 'bdb39194', 'bl', '#0x1e227e6a8'],
 'scan_result_clear_address': ['dispatchAsyncScanEvent', '0x1dfe07abc', 'e0430191', 'add', 'x0, sp, #0x50'],
 'scan_result_clear_bytes': ['dispatchAsyncScanEvent', '0x1dfe07ac0', '81998052', 'mov', 'w1, #0x4cc'],
 'scan_result_clear_call': ['dispatchAsyncScanEvent', '0x1dfe07ac4', 'f1d99194', 'bl', '#0x1e227e288'],
 'scan_result_ie_capacity': ['dispatchAsyncScanEvent', '0x1dfe07ab8', '18808052', 'mov', 'w24, #0x400'],
 'scan_result_uuid_copy': ['dispatchAsyncScanEvent', '0x1dfe07ae4', 'd1d99194', 'bl', '#0x1e227e228'],
 'scan_result_raw_get': ['dispatchAsyncScanEvent', '0x1dfe07af0', 'e3000094', 'bl', '#0x1dfe07e7c']}


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
    'apple80211_21h16_abi': {
        'enabled': True, 'qualified': True, 'complete_abi_qualified': False,
        'get_requests': [11, 21], 'set_requests': [10, 20],
        'assoc_request_bytes': 856, 'scan_request_bytes': 5520, 'scan_result_bytes': 1228,
        'scan_request_uuid': {'offset': 0x154c, 'bytes': 64, 'following_reserved_bytes': 4},
        'scan_result_uuid': {'offset': 0x48c, 'bytes': 64, 'preserved_from_caller': True},
        'assoc_wsec_flags': {'offset': 0x250, 'bytes': 4, 'supported_value': 0},
        'events': {'4': {'bytes': 32}, '9': {'bytes': 4}, '10': {'bytes': 4}},
        'scalar_semantics': 'zero success, backend errno on failure; independent request-21 result',
        'unqualified': ['other ioctl layouts', 'nonzero WSEC_FLAGS semantics',
                        'extended ASSOC_DONE', 'RSSI_CHANGED event 39',
                        'POWER_CHANGED, SSID_CHANGED and BSSID_CHANGED payloads',
                        'conversion of failure errno to private Apple80211 error codes'],
    },
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


def verify_abi_evidence(directory):
    """Recheck the retained original consumer fragments without mounting images."""
    directory = Path(directory)
    facts_bytes = _validated((directory / 'abi-instruction-facts-02.json').read_bytes(),
                             ABI_EVIDENCE['facts_sha256'], '21H16 instruction facts')
    facts = json.loads(facts_bytes)
    require(facts['result'] == 'original_21h16_abi_instruction_facts_verified', 'Unverified ABI facts')
    require(facts['image'] == ABI_EVIDENCE['io80211_image'] and
            facts['cache_uuid'] == ABI_EVIDENCE['cache_uuid'] and
            facts['symbols_uuid'] == ABI_EVIDENCE['symbols_uuid'], 'Original ABI image identity drift')
    actual = {row['fact']: [row['function'], row['address'], row['bytes'], row['mnemonic'], row['operands']]
              for row in facts['facts']}
    require(actual == ABI_INSTRUCTIONS and len(actual) == len(facts['facts']), 'Original ABI field facts drift')
    for path, digest in ABI_EVIDENCE['bound_files'].items():
        _validated((directory / path).read_bytes(), digest, path)
    fragments = {}
    for name, record in ABI_FUNCTIONS.items():
        content = _validated((directory / 'consumers-02' / (name + '.bin')).read_bytes(),
                             record['sha256'], name)
        require(len(content) == record['bytes'], 'Original consumer length drift: ' + name)
        fragments[name] = content
    for row in facts['facts']:
        name = row['function']
        require(row['function_sha256'] == ABI_FUNCTIONS[name]['sha256'], 'Original function binding drift')
        offset = int(row['address'], 16) - int(ABI_FUNCTIONS[name]['address'], 16)
        require(0 <= offset <= len(fragments[name]) - 4 and
                fragments[name][offset:offset + 4].hex() == row['bytes'], 'Original instruction bytes drift')
    for function, address, instruction, _, _ in ABI_SCAN_WRAPPER_INSTRUCTIONS.values():
        offset = int(address, 16) - int(ABI_FUNCTIONS[function]['address'], 16)
        require(0 <= offset <= len(fragments[function]) - 4 and
                fragments[function][offset:offset + 4].hex() == instruction,
                'Original scan initialization instruction drift')
    return dict(original_instruction_bytes_verified=True, facts=len(actual), functions=len(fragments),
                scan_wrapper_facts=len(ABI_SCAN_WRAPPER_INSTRUCTIONS),
                evidence=deepcopy(ABI_EVIDENCE), runtime_qualified=False)


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
        original_abi_evidence=deepcopy(ABI_EVIDENCE),
        original_abi_functions=deepcopy(ABI_FUNCTIONS), original_abi_instructions=deepcopy(ABI_INSTRUCTIONS),
        original_abi_scan_wrapper_instructions=deepcopy(ABI_SCAN_WRAPPER_INSTRUCTIONS),
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
                  runtime_qualified=False, apple80211_21h16_abi_qualified=True,
                  apple80211_21h16_complete_abi_qualified=False,
                  original_abi_evidence=deepcopy(ABI_EVIDENCE))
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
                          compiled=False, apple80211_21h16_abi_qualified=True,
                          apple80211_21h16_complete_abi_qualified=False)))


if __name__ == '__main__':
    main()
