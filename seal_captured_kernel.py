#!/usr/bin/env python3
"""Finalize the source-provider integrity state in a prelinked-mode base.

An unreferenced source provider and its HMAC field may be dead-stripped by the
Apple linker. In that case verify the native PRNG exports and leave all bytes
unchanged. A retained HMAC field is populated normally. Original Apple components
have not been inserted; their POST and integrity fields are never processed here.
"""
import argparse
import hashlib
import hmac
import json
from pathlib import Path
import struct


def defined_symbols(data, table):
    symoff, count, stroff, strsize = table
    if symoff + count * 16 > len(data) or stroff + strsize > len(data):
        raise ValueError('Symbol table outside file')
    names = set()
    for i in range(count):
        index, kind, _, _, address = struct.unpack_from('<IBBHQ', data, symoff + i * 16)
        if kind & 0xe0 or not kind & 0x0e or not address:
            continue
        end = data.find(b'\0', stroff + index, stroff + strsize)
        if index >= strsize or end < 0:
            raise ValueError('Invalid symbol name')
        names.add(bytes(data[stroff + index:end]))
    return names


def seal(data):
    data = bytearray(data)
    if len(data) < 32 or struct.unpack_from('<4I', data) != (0xfeedfacf, 0x100000c, 0, 2):
        raise ValueError('Expected ordinary ARM64 MH_EXECUTE base')
    if b'_source_corecrypto14_bootstrap\0' in data or b'_source_corecrypto14_status\0' in data:
        raise ValueError('Source bootstrap must be compiled out')
    off, code, field, base, table = 32, None, None, None, None
    end = 32 + struct.unpack_from('<I', data, 20)[0]
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        if off + 8 > end or end > len(data):
            raise ValueError('Truncated load commands')
        cmd, size = struct.unpack_from('<II', data, off)
        if size < 8 or size % 8 or off + size > end:
            raise ValueError('Invalid load command')
        if cmd == 0x19:
            if size < 72: raise ValueError('Truncated segment')
            name, va, span, fileoff, backed = struct.unpack_from('<16s4Q', data, off + 8)
            name = name.rstrip(b'\0')
            if backed > span or fileoff + backed > len(data):
                raise ValueError('Invalid segment extent')
            if name == b'__TEXT':
                if base is not None: raise ValueError('Multiple native TEXT segments')
                base = va
            count = struct.unpack_from('<I', data, off + 64)[0]
            if 72 + count * 80 != size: raise ValueError('Invalid section count')
            for i in range(count):
                name, segment, addr, length, pos = struct.unpack_from('<16s16sQQI', data, off + 72 + i * 80)
                flags = struct.unpack_from('<I', data, off + 72 + i * 80 + 64)[0]
                if flags & 0xff in (1, 0xc, 0x12):
                    continue
                if pos + length > len(data): raise ValueError('Section outside file')
                if name.rstrip(b'\0') == b'__text' and segment.rstrip(b'\0') in (b'__TEXT', b'__TEXT_EXEC'):
                    if code is not None: raise ValueError('Multiple native text sections')
                    code = pos, length, addr
                if name.rstrip(b'\0') == b'__fips_hmacs':
                    if field is not None or length != 32: raise ValueError('Invalid integrity field')
                    field = pos
        elif cmd == 2:
            if table is not None or size != 24:
                raise ValueError('Invalid symbol table command')
            table = struct.unpack_from('<4I', data, off + 8)
        off += size
    if off != end or code is None or base is None or not code[1]:
        raise ValueError('Missing native code mapping')
    if code[2] - base != code[0]:
        raise ValueError('POST text mapping differs from native contract')
    names = defined_symbols(data, table) if table is not None else set()
    if field is None:
        required = {b'_prng_ready', b'_register_and_init_prng', b'_register_crypto_functions'}
        if not required.issubset(names):
            raise ValueError('Missing integrity field requires verified native PRNG symbols')
        if any(b'fipspost' in name or b'fips_hmac' in name for name in names):
            raise ValueError('Retained source POST code has no integrity field')
        mac = None
    else:
        if field < 32 + struct.unpack_from('<I', data, 20)[0] or (
                field < code[0] + code[1] and code[0] < field + 32):
            raise ValueError('Integrity field overlaps native code or load commands')
        mac = hmac.digest(b'\0', data[code[0]:code[0] + code[1]], 'sha256')
        data[field:field + 32] = mac
    return bytes(data), {
        'kernel_sha256': hashlib.sha256(data).hexdigest(),
        'code_file_offset': hex(code[0]), 'code_bytes': code[1],
        'hmac_file_offset': hex(field) if field is not None else None,
        'hmac_sha256': mac.hex() if mac is not None else None,
        'integrity_field_status': 'sealed' if mac is not None else 'absent-source-post-dead-stripped',
        'integrity_field_written': mac is not None, 'source_bootstrap_absent': True,
        'runtime_selftests_executed': False, 'original_components_modified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kernel', type=Path)
    args = parser.parse_args()
    data, report = seal(args.kernel.read_bytes())
    args.kernel.write_bytes(data)
    args.kernel.with_suffix(args.kernel.suffix + '.crypto-hmac.json').write_text(json.dumps(report, indent=2) + '\n')
    print('Native base integrity state: ' + report['integrity_field_status']
          + '; original prelinked provider runtime checks remain required')


if __name__ == '__main__':
    main()
