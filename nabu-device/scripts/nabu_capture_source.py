#!/usr/bin/env python3
"""Apply the opt-in recorder after upstream XNU patches, before compilation."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Logging source drift: ' + old[:100])
    return text.replace(old, new, 1)


def patch_console(text):
    marker = '/* NABU_CAPTURE_V2 console producer hooks */'
    if marker in text:
        for name in ('console_write(char *str, int size)', 'console_write_unbuffered(char c)'):
            if text.count(name) != 1:
                raise ValueError('Recorder source changed after patching')
        return text
    text = replace_once(text, 'void\nconsole_write(char *str, int size)\n{\n',
        marker + '\n#define NABU_LOG_IMPLEMENTATION\n#include "NabuLogCore.h"\n\n'
        'void\nconsole_write(char *str, int size)\n{\n'
        '\tif (size > 0) nabu_capture_append(str, (unsigned)size);\n')
    return replace_once(text, 'console_write_unbuffered(char c)\n{\n',
                        'console_write_unbuffered(char c)\n{\n\tnabu_capture_append(&c, 1);\n')


def patch_kprintf(text):
    marker = '/* NABU_CAPTURE_V2 hardware kprintf producer */'
    if marker in text:
        return text
    return replace_once(text, 'static void\nserial_putc_crlf(char c)\n{\n',
        marker + '\nextern void nabu_capture_append(const char *, unsigned);\n'
        'static void\nserial_putc_crlf(char c)\n{\n\tnabu_capture_append(&c, 1);\n')


def apply(root, device):
    xnu = root / '.cache/xnu-work'
    changed = {}
    for relative, transform in [('osfmk/console/serial_console.c', patch_console),
                                 ('pexpert/arm/pe_kprintf.c', patch_kprintf)]:
        path = xnu / relative
        result = transform(path.read_text(encoding='utf-8'))
        path.write_text(result, encoding='utf-8')
        changed[relative] = hashlib.sha256(result.encode()).hexdigest()
    for name in ('NabuLogCore.h', 'NabuLogFormat.h'):
        shutil.copyfile(device / 'ufs' / name, xnu / 'osfmk/console' / name)
    out = root / 'build/nabu-log'
    out.mkdir(parents=True, exist_ok=True)
    (out / 'source-report.json').write_text(json.dumps({
        'version': 2, 'hooks': changed, 'capture_before_console_disable': True,
        'disk_io_in_capture': False, 'runtime_qualified': False}, indent=2) + '\n')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--device', type=Path, required=True)
    a = p.parse_args()
    apply(a.root, a.device)
