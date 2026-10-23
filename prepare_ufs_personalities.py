#!/usr/bin/env python3
"""Preserve the captured kernel catalogue and append default-off nabu UFS matches."""
import json
from pathlib import Path
import struct

from native_ufs_bindings import MachO

MATCHES = """,
{ 'IOClass' = NativeUfs; 'IOProviderClass' = IOPlatformExpertDevice;
  'IOMatchCategory' = NativeUfsRoot; 'IOProbeScore' = 500:32; },
{ 'IOClass' = NativeUfs; 'IOProviderClass' = IOPlatformDevice;
  'IOMatchCategory' = NativeUfsNub; 'IOProbeScore' = 1000:32; }
"""


def prepare(obj_path, destination):
    obj = MachO(obj_path)
    address = obj.names['_gIOKernelConfigTables']
    target = obj.relocations(address)[address]
    pointer = obj.names[target] + struct.unpack('<Q', obj.read(address, 8))[0]
    section = next(s for s in obj.sections if s[0] <= pointer < s[0] + s[1])
    at = section[2] + pointer - section[0]
    original = obj.data[at:obj.data.index(b'\0', at)].decode('ascii').rstrip()
    if not original.startswith('(') or not original.endswith(')') or 'NativeUfs' in original:
        raise ValueError('Expected the captured catalogue without UFS personalities')
    combined = original[:-1] + MATCHES + ')'
    destination.write_text('const char *gIOKernelConfigTables =\n' + json.dumps(combined) + ';\n')
    return {'source': str(destination), 'preserved_catalogue': original,
            'added_classes': ['NativeUfsRoot', 'NativeUfsNub'], 'mmio_default_enabled': False}
