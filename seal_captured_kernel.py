#!/usr/bin/env python3
"""Seal the unused source-provider integrity field in a prelinked-mode base.

Only the native kernel's source archive HMAC is populated. Original Apple
components have not yet been inserted and their bytes are never processed here.
The source EARLY_BOOT bootstrap must be absent; no POST check is disabled.
"""
import argparse
import hashlib
import hmac
import json
from pathlib import Path
import struct


def seal(data):
    data = bytearray(data)
    if len(data) < 32 or struct.unpack_from('<4I', data) != (0xfeedfacf, 0x100000c, 0, 2):
        raise ValueError('Expected ordinary ARM64 MH_EXECUTE base')
    if b'_source_corecrypto14_bootstrap\0' in data or b'_source_corecrypto14_status\0' in data:
        raise ValueError('Source bootstrap must be compiled out')
    off, code, field, base = 32, None, None, None
    end = 32 + struct.unpack_from('<I', data, 20)[0]
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        if off + 8 > end or end > len(data):
            raise ValueError('Truncated load commands')
        cmd, size = struct.unpack_from('<II', data, off)
        if size < 8 or size % 8 or off + size > end:
            raise ValueError('Invalid load command')
        if cmd == 0x19:
            if size < 72: raise ValueError('Truncated segment')
            name, va, _, _, _ = struct.unpack_from('<16s4Q', data, off + 8)
            if name.rstrip(b'\0') == b'__TEXT': base = va
            count = struct.unpack_from('<I', data, off + 64)[0]
            if 72 + count * 80 != size: raise ValueError('Invalid section count')
            for i in range(count):
                name, segment, addr, length, pos = struct.unpack_from('<16s16sQQI', data, off + 72 + i * 80)
                if pos + length > len(data): raise ValueError('Section outside file')
                if name.rstrip(b'\0') == b'__text' and segment.rstrip(b'\0') in (b'__TEXT', b'__TEXT_EXEC'):
                    if code is not None: raise ValueError('Multiple native text sections')
                    code = pos, length, addr
                if name.rstrip(b'\0') == b'__fips_hmacs':
                    if field is not None or length != 32: raise ValueError('Invalid integrity field')
                    field = pos
        off += size
    if off != end or code is None or field is None or base is None:
        raise ValueError('Missing native code/integrity mapping')
    if code[2] - base != code[0] or code[0] <= field < code[0] + code[1]:
        raise ValueError('POST text mapping differs from native contract')
    mac = hmac.digest(b'\0', data[code[0]:code[0] + code[1]], 'sha256')
    data[field:field + 32] = mac
    return bytes(data), {'kernel_sha256': hashlib.sha256(data).hexdigest(),
        'code_file_offset': hex(code[0]), 'code_bytes': code[1], 'hmac_file_offset': hex(field),
        'hmac_sha256': mac.hex(), 'source_bootstrap_absent': True,
        'runtime_selftests_executed': False, 'original_components_modified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kernel', type=Path)
    args = parser.parse_args()
    data, report = seal(args.kernel.read_bytes())
    args.kernel.write_bytes(data)
    args.kernel.with_suffix(args.kernel.suffix + '.crypto-hmac.json').write_text(json.dumps(report, indent=2) + '\n')
    print('Native base integrity field sealed; original prelinked provider runtime checks remain required')


if __name__ == '__main__':
    main()
