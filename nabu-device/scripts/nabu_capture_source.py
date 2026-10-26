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
    marker = '/* NABU_CAPTURE_V2_1 console producer hooks */'
    if marker in text:
        for name in ('console_write(char *str, int size)', 'console_write_unbuffered(char c)'):
            if text.count(name) != 1:
                raise ValueError('Recorder source changed after patching')
        return text
    if 'NABU_CAPTURE_' in text:
        raise ValueError('Older recorder hook present; use a fresh source tree')
    text = replace_once(text, 'void\nconsole_write(char *str, int size)\n{\n',
        marker + '\n#define NABU_LOG_IMPLEMENTATION\n#include "NabuLogCore.h"\n\n'
        'void nabu_console_write_captured(char *, int);\n'
        'static void nabu_console_write_raw(char *, int);\n'
        'void\nconsole_write(char *str, int size)\n{\n'
        '\tif (size > 0) nabu_capture_append(str, (unsigned)size);\n'
        '\tnabu_console_write_raw(str, size);\n}\n\n'
        'void\nnabu_console_write_captured(char *str, int size)\n{\n'
        '\tnabu_console_write_raw(str, size);\n}\n\n'
        'static void\nnabu_console_write_raw(char *str, int size)\n{\n')
    return replace_once(text, 'console_write_unbuffered(char c)\n{\n',
                        'console_write_unbuffered(char c)\n{\n\tnabu_capture_append(&c, 1);\n')


def patch_general(text):
    marker = '/* NABU_CAPTURE_V2 capture before printbuf truncation */'
    if marker in text:
        return text
    text = replace_once(text, 'void\nconsole_printbuf_putc(int ch, void * arg)\n{\n',
        marker + '\nextern void nabu_capture_append(const char *, unsigned);\n'
        'extern void nabu_console_write_captured(char *, int);\n'
        'void\nconsole_printbuf_putc(int ch, void * arg)\n{\n'
        '\tchar captured = (char)ch;\n\tnabu_capture_append(&captured, 1);\n')
    call = 'console_write(info->str, info->pos);'
    if text.count(call) != 3:
        raise ValueError('Expected all three printbuf flush calls')
    return text.replace(call, 'nabu_console_write_captured(info->str, info->pos);')


def patch_kprintf(text):
    marker = '/* NABU_CAPTURE_V2 hardware kprintf producer */'
    if marker in text:
        return text
    return replace_once(text, 'static void\nserial_putc_crlf(char c)\n{\n',
        marker + '\nextern void nabu_capture_append(const char *, unsigned);\n'
        'static void\nserial_putc_crlf(char c)\n{\n\tnabu_capture_append(&c, 1);\n')


def patch_bsd_init(text):
    marker = '/* NABU_CAPTURE_V2_2 opt-in diagnostic calls */'
    if marker in text:
        return text
    old = '/* NABU_CAPTURE_V2_1 opt-in USB probe call */'
    if old in text:
        # Upgrade a tree prepared by the earlier hook without re-injecting.
        text = replace_once(text, old, marker)
        return replace_once(text, '\t\tnabu_usb_probe_start();\n',
            '\t\tnabu_usb_probe_start();\n'
            '\t\textern void nabu_heartbeat_start(void);\n'
            '\t\tnabu_heartbeat_start();\n')
    return replace_once(text, '\tprintf(copyright);\n',
        '\tprintf(copyright);\n'
        '\t' + marker + '\n'
        '\t{\n'
        '\t\textern void nabu_usb_probe_start(void);\n'
        '\t\textern void nabu_heartbeat_start(void);\n'
        '\t\tnabu_usb_probe_start();\n'
        '\t\tnabu_heartbeat_start();\n'
        '\t}\n')


def patch_bsd_init_cdc(text):
    marker = '/* NABU_CAPTURE_V2_1 opt-in USB CDC call after IOKit init */'
    if marker in text:
        return text
    anchor = '\tbsd_autoconf();\n'
    return replace_once(text, anchor, anchor +
        marker + '\n'
        '\t{\n'
        '\t\textern void nabu_usb_cdc_log_start(void);\n'
        '\t\tnabu_usb_cdc_log_start();\n'
        '\t}\n')


def patch_data_mount(text, restore=False):
    marker = '/* NABU_CAPTURE_V2_3 Data mount progress */'
    if restore and marker not in text:
        return text
    if not restore and marker in text:
        return text
    anchor = 'static int\nnative_owner_data_prepare(proc_t p, user_addr_t scratch)\n{\n'
    if anchor not in text:
        # The root-only logging profile has no Data hook.
        return text
    start = text.index(anchor)
    end = text.index('\n}\n#endif', start) + 2
    body = text[start:end]
    edits = ((anchor, anchor + '\t' + marker + '\n'
              '\textern void nabu_data_mount_progress(unsigned, int);\n'),
            ('\tnative_owner_data_stage = 1;\n',
             '\tnative_owner_data_stage = 1;\n\tnabu_data_mount_progress(1, 0);\n'),
            ('\tnative_owner_data_stage = 2;\n',
             '\tnative_owner_data_stage = 2;\n\tnabu_data_mount_progress(2, -1);\n'),
            ('\terror = mount(p, &request, &result);\n',
             '\terror = mount(p, &request, &result);\n\tnabu_data_mount_progress(3, error);\n'),
            ('\terror = vnode_lookup("/private/var", 0, &data_root, vfs_context_current());\n',
             '\terror = vnode_lookup("/private/var", 0, &data_root, vfs_context_current());\n'
             '\tnabu_data_mount_progress(4, error);\n'),
            ('\tif (!error) native_owner_data_stage = 4;\n',
             '\tnabu_data_mount_progress(5, error);\n\tif (!error) native_owner_data_stage = 4;\n'),
            ('\tnative_owner_data_status = error;\n',
             '\tnative_owner_data_status = error;\n\tnabu_data_mount_progress(6, error);\n'))
    for old, new in edits:
        body = replace_once(body, new, old) if restore else replace_once(body, old, new)
    return text[:start] + body + text[end:]


def patch_exit_trace(text):
    marker = '/* NABU_CAPTURE_V2_4 opt-in exit trace */'
    if marker in text:
        return text
    anchor = ('int\n'
              'exit_with_reason(proc_t p, int rv, int *retval, boolean_t thread_can_terminate, boolean_t perf_notify,\n'
              '    int jetsam_flags, struct os_reason *exit_reason)\n'
              '{\n')
    snippet = (marker + '\n'
               '\tint nabu_exit_trace = 0;\n'
               '\tPE_parse_boot_argn("nabu-exit-trace", &nabu_exit_trace, sizeof(nabu_exit_trace));\n'
               '\tif (nabu_exit_trace && (rv || !strcmp(p->p_comm, "SpringBoard") ||\n'
               '\t    !strcmp(p->p_comm, "backboardd") || !strcmp(p->p_comm, "powerd") ||\n'
               '\t    !strcmp(p->p_comm, "servicetimed") || !strcmp(p->p_comm, "chronod") ||\n'
               '\t    !strcmp(p->p_comm, "contextstored") || !strcmp(p->p_comm, "accountsd"))) {\n'
               '\t\tstruct os_reason *nabu_reason = exit_reason ? exit_reason : p->p_exit_reason;\n'
               '\t\tprintf("NABU EXIT comm=%s pid=%d rv=0x%x xstat=0x%x\\n",\n'
               '\t\t    p->p_comm, proc_getpid(p), rv, p->p_xstat);\n'
               '\t\tif (nabu_reason) {\n'
               '\t\t\tchar *nabu_desc = exit_reason_get_string_desc(nabu_reason);\n'
               '\t\t\tprintf("NABU EXIT reason ns=%u code=%llu flags=%llu desc=%.200s\\n",\n'
               '\t\t\t    nabu_reason->osr_namespace, nabu_reason->osr_code,\n'
               '\t\t\t    nabu_reason->osr_flags, nabu_desc ? nabu_desc : "none");\n'
               '\t\t}\n'
               '\t}\n')
    if text.count(anchor) != 1:
        raise ValueError('Expected one exit_with_reason anchor')
    return text.replace(anchor, anchor + snippet, 1)


def apply(root, device):
    xnu = root / '.cache/xnu-work'
    changed = {}
    for relative, transforms in [
            ('osfmk/console/serial_console.c', [patch_console]),
            ('osfmk/console/serial_general.c', [patch_general]),
            ('pexpert/arm/pe_kprintf.c', [patch_kprintf]),
            # The probe stays at the top of bsd_init (read-only MMIO); the CDC
            # channel starts after bsd_autoconf() so IOKit init has completed
            # and no allocator/personality is assumed before it exists.
            ('bsd/kern/bsd_init.c', [patch_bsd_init, patch_bsd_init_cdc]),
            ('bsd/kern/kern_exec.c', [patch_data_mount]),
            ('bsd/kern/kern_exit.c', [patch_exit_trace])]:
        path = xnu / relative
        result = path.read_text(encoding='utf-8')
        for transform in transforms:
            result = transform(result)
        path.write_text(result, encoding='utf-8')
        changed[relative] = hashlib.sha256(result.encode()).hexdigest()
    for name in ('NabuLogCore.h', 'NabuLogFormat.h'):
        shutil.copyfile(device / 'ufs' / name, xnu / 'osfmk/console' / name)
    out = root / 'build/nabu-log'
    out.mkdir(parents=True, exist_ok=True)
    (out / 'source-report.json').write_text(json.dumps({
        'version': 2, 'hooks': changed, 'capture_before_console_disable': True,
        'usb_probe_call': True, 'usb_probe_read_only': True,
        'usb_cdc_call': True, 'usb_cdc_after_iokit_init': True,
        'usb_cdc_entry': 'nabu_usb_cdc_log_start',
        'usb_cdc_static_dma': True, 'usb_cdc_boot_arg_gated': True,
        'heartbeat_call': True, 'heartbeat_entry': 'nabu_heartbeat_start',
        'heartbeat_boot_arg_gated': True, 'heartbeat_read_only': True,
        'writer_counter_watch': True,
        'exit_trace': True,
        'data_mount_trace': 'NABU_CAPTURE_V2_3' in (xnu / 'bsd/kern/kern_exec.c').read_text(),
        'data_trace_stages': {'1': 'seed ready', '2': 'mount enter',
                              '3': 'mount returned', '4': 'lookup returned',
                              '5': 'validation/skeleton returned', '6': 'prepare returned'},
        'disk_io_in_capture': False, 'runtime_qualified': False}, indent=2) + '\n')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--device', type=Path)
    p.add_argument('--restore-data-progress', action='store_true')
    a = p.parse_args()
    if a.restore_data_progress:
        path = a.root / '.cache/xnu-work/bsd/kern/kern_exec.c'
        if path.exists():
            before = path.read_text(encoding='utf-8')
            after = patch_data_mount(before, restore=True)
            if before != after:
                path.write_text(after, encoding='utf-8')
    elif a.device:
        apply(a.root, a.device)
    else:
        p.error('--device is required when applying capture hooks')
