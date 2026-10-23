#!/usr/bin/env python3
"""Build the own EL0 md1 block-read instrument on a macOS Actions runner."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

BASE_SOURCE = '// SPDX-License-Identifier: BSD-2-Clause-Patent\n// Own static Darwin EL0 instrument. No imported Apple userspace or MMIO.\n// Every core syscall result is checked before console open/write.\n// Darwin 23 syscalls.master: write=4, open=5, getpid=20, sysctl=202, sys_sysctlbyname=274.\n.text\n.p2align 2\n.global _start, _checkpoint, _verify_results, _failure_checkpoint\n_start:\n  mov x16, #20\n  svc #0x80\n  mrs x9, nzcv\n  adrp x19, _results@PAGE\n  add x19, x19, _results@PAGEOFF\n  str x0, [x19]\n  str x9, [x19, #16]\n\n  // Numeric compatibility node is CTL_HW=6, HW_PAGESIZE=7; 32-bit result.\n  adrp x0, _mib@PAGE\n  add x0, x0, _mib@PAGEOFF\n  mov x1, #2\n  adrp x2, _user_page_size@PAGE\n  add x2, x2, _user_page_size@PAGEOFF\n  adrp x3, _old_length@PAGE\n  add x3, x3, _old_length@PAGEOFF\n  mov x4, #0\n  mov x5, #0\n  mov x16, #202\n  svc #0x80\n  mrs x9, nzcv\n  str x0, [x19, #8]\n  str x9, [x19, #24]\n\n  // The actual by-name syscall resolves hw.pagesize, a 64-bit node.\n  adrp x0, _byname_name@PAGE\n  add x0, x0, _byname_name@PAGEOFF\n  mov x1, #11 // strlen("hw.pagesize"), excludes terminal NUL.\n  adrp x2, _byname_page_size@PAGE\n  add x2, x2, _byname_page_size@PAGEOFF\n  adrp x3, _byname_old_length@PAGE\n  add x3, x3, _byname_old_length@PAGEOFF\n  mov x4, #0\n  mov x5, #0\n  mov x16, #274\n  svc #0x80\n  mrs x9, nzcv\n  str x0, [x19, #32]\n  str x9, [x19, #40]\n\n  // Missing OID must fail with ENOENT=2 and carry set.\n  adrp x0, _negative_name@PAGE\n  add x0, x0, _negative_name@PAGEOFF\n  mov x1, #27 // strlen("hw.hackios_missing_20261022"), excludes terminal NUL.\n  adrp x2, _negative_value@PAGE\n  add x2, x2, _negative_value@PAGEOFF\n  adrp x3, _negative_old_length@PAGE\n  add x3, x3, _negative_old_length@PAGEOFF\n  mov x4, #0\n  mov x5, #0\n  mov x16, #274\n  svc #0x80\n  mrs x9, nzcv\n  str x0, [x19, #48]\n  str x9, [x19, #56]\n.p2align 2\n_verify_results:\n  ldr x9, [x19]\n  cmp x9, #1\n  b.ne _failure_checkpoint\n  ldr x9, [x19, #8]\n  cbnz x9, _failure_checkpoint\n  ldr x9, [x19, #16]\n  tbnz x9, #29, _failure_checkpoint\n  ldr x9, [x19, #24]\n  tbnz x9, #29, _failure_checkpoint\n  ldr x9, [x19, #32]\n  cbnz x9, _failure_checkpoint\n  ldr x9, [x19, #40]\n  tbnz x9, #29, _failure_checkpoint\n  ldr x9, [x19, #48]\n  cmp x9, #2\n  b.ne _failure_checkpoint\n  ldr x9, [x19, #56]\n  tbz x9, #29, _failure_checkpoint\n  adrp x10, _user_page_size@PAGE\n  add x10, x10, _user_page_size@PAGEOFF\n  ldr x9, [x10]\n  cmp x9, #4096\n  b.ne _failure_checkpoint\n  adrp x10, _old_length@PAGE\n  add x10, x10, _old_length@PAGEOFF\n  ldr x9, [x10]\n  cmp x9, #4\n  b.ne _failure_checkpoint\n  adrp x10, _byname_page_size@PAGE\n  add x10, x10, _byname_page_size@PAGEOFF\n  ldr x9, [x10]\n  cmp x9, #4096\n  b.ne _failure_checkpoint\n  adrp x10, _byname_old_length@PAGE\n  add x10, x10, _byname_old_length@PAGEOFF\n  ldr x9, [x10]\n  cmp x9, #8\n  b.ne _failure_checkpoint\n  adrp x10, _negative_value@PAGE\n  add x10, x10, _negative_value@PAGEOFF\n  ldr x9, [x10]\n  cbnz x9, _failure_checkpoint\n  adrp x10, _negative_old_length@PAGE\n  add x10, x10, _negative_old_length@PAGEOFF\n  ldr x9, [x10]\n  cmp x9, #8\n  b.ne _failure_checkpoint\n\n  // No stdout assumption: explicitly open the console and use that descriptor.\n  adrp x0, _console_path@PAGE\n  add x0, x0, _console_path@PAGEOFF\n  mov w1, #1 // O_WRONLY\n  movk w1, #0x8000, lsl #16 // O_POPUP=0x80000000, Darwin bsd/sys/fcntl.h:751\n  mov x2, #0 // no O_CREAT\n  mov x16, #5\n  svc #0x80\n  mrs x9, nzcv\n  adrp x10, _open_result@PAGE\n  add x10, x10, _open_result@PAGEOFF\n  str x0, [x10]\n  str x9, [x10, #8]\n  tbnz x9, #29, _failure_checkpoint\n  tbnz x0, #63, _failure_checkpoint\n  mov x20, x0\n  adrp x0, _console_guard_passed@PAGE\n  add x0, x0, _console_guard_passed@PAGEOFF\n  mov x9, #1\n  str x9, [x0]\n\n  mov x0, x20\n  adrp x1, _success_line@PAGE\n  add x1, x1, _success_line@PAGEOFF\n  mov x2, #70 // exact bytes, independently checked against _success_line\n  mov x16, #4\n  svc #0x80\n  mrs x9, nzcv\n  adrp x10, _write_result@PAGE\n  add x10, x10, _write_result@PAGEOFF\n  str x0, [x10]\n  str x9, [x10, #8]\n  tbnz x9, #29, _failure_checkpoint\n  cmp x0, #70\n  b.ne _failure_checkpoint\n  adrp x10, _console_write_completed@PAGE\n  add x10, x10, _console_write_completed@PAGEOFF\n  mov x9, #1\n  str x9, [x10]\n.p2align 2\n_checkpoint:\n  b _checkpoint\n.p2align 2\n_failure_checkpoint:\n  b _failure_checkpoint\n\n.data\n.balign 8\n.global _results, _user_page_size, _old_length\n.global _byname_page_size, _byname_old_length, _negative_value, _negative_old_length\n.global _open_result, _open_flags, _write_result, _write_flags\n.global _console_guard_passed, _console_write_completed\n_results:\n  .quad 0, 0, 0, 0, 0, 0, 0, 0\n_mib:\n  .word 6, 7\n_user_page_size:\n  .quad 0\n_old_length:\n  .quad 8\n_byname_page_size:\n  .quad 0\n_byname_old_length:\n  .quad 8\n_negative_value:\n  .quad 0\n_negative_old_length:\n  .quad 8\n_open_result:\n  .quad -1 // cannot look successful before open executes\n_open_flags:\n  .quad 0\n_write_result:\n  .quad 0\n_write_flags:\n  .quad 0\n_console_guard_passed:\n  .quad 0\n_console_write_completed:\n  .quad 0\n_byname_name:\n  .asciz "hw.pagesize"\n_negative_name:\n  .asciz "hw.hackios_missing_20261022"\n_console_path:\n  .asciz "/dev/console"\n_success_line:\n  .ascii "HACKIOS_EL0_CHECKPOINT pid=1 pagesize=4096 byname=4096 missing=ENOENT\\n"\n_success_line_end:\n'
BASE_CONTRACT = {'description': 'Own static ARM64 EL0 syscall fixture; success requires live user checkpoint plus all results.', 'source': 'native-user-console-popup.S', 'sysctlbyname': True, 'results': [{'name': 'getpid_return', 'value': 1}, {'name': 'numeric_sysctl_return', 'value': 0}, {'name': 'getpid_carry', 'value': 0, 'mask': 536870912}, {'name': 'numeric_sysctl_carry', 'value': 0, 'mask': 536870912}, {'name': 'sysctlbyname_return', 'value': 0}, {'name': 'sysctlbyname_carry', 'value': 0, 'mask': 536870912}, {'name': 'missing_name_errno', 'value': 2}, {'name': 'missing_name_carry', 'value': 536870912, 'mask': 536870912}], 'checkpoint': 4294983672, 'checkpoint_word': '00000014', 'old_length': 4, 'byname_return_index': 4, 'byname_page_size': 4096, 'byname_old_length': 8, 'negative_return_index': 6, 'negative_name': 'hw.hackios_missing_20261022', 'negative_name_length': 27, 'negative_carry_index': 7, 'negative_value': 0, 'memory': {'_user_page_size': {'width': 8, 'value': 4096}, '_old_length': {'width': 8, 'value': 4}, '_byname_page_size': {'width': 8, 'value': 4096}, '_byname_old_length': {'width': 8, 'value': 8}, '_negative_value': {'width': 8, 'value': 0}, '_negative_old_length': {'width': 8, 'value': 8}, '_open_result': {'width': 8, 'predicate': 'nonnegative_signed'}, '_open_flags': {'width': 8, 'value': 0, 'mask': 536870912}, '_write_result': {'width': 8, 'value': 70}, '_write_flags': {'width': 8, 'value': 0, 'mask': 536870912}, '_console_guard_passed': {'width': 8, 'value': 1}, '_console_write_completed': {'width': 8, 'value': 1}}, 'user_page_size': 4096, 'initproc_nonzero': True, 'pstate_mode': 0, 'initial_results': [0, 0, 0, 0, 0, 0, 0, 0], 'initial_memory': {'_user_page_size': 0, '_old_length': 8, '_byname_page_size': 0, '_byname_old_length': 8, '_negative_value': 0, '_negative_old_length': 8}, 'syscall_numbers': [20, 202, 274, 274, 5, 4], 'byname_name': 'hw.pagesize', 'byname_name_length': 11, 'console_success_line': 'HACKIOS_EL0_CHECKPOINT pid=1 pagesize=4096 byname=4096 missing=ENOENT\n', 'console_success_line_bytes': 70, 'console_path': '/dev/console', 'console_open_flags': '0x80000001', 'console_popup': True, 'console_write': True, 'failure_checkpoint': 4294983676, 'trustcache_required': False, 'dynamic_dependencies': [], 'apple_userspace_used': False}
BLOCK_PROBE = """
  adrp x0, Lmd1_path@PAGE
  add x0, x0, Lmd1_path@PAGEOFF
  mov x1, #0
  mov x2, #0
  mov x16, #5
  svc #0x80
  mrs x9, nzcv
  adrp x21, _md1_open_result@PAGE
  add x21, x21, _md1_open_result@PAGEOFF
  str x0, [x21]
  str x9, [x21, #8]
  tbnz x9, #29, _failure_checkpoint
  adrp x1, _md1_buffer@PAGE
  add x1, x1, _md1_buffer@PAGEOFF
  mov x2, #4096
  mov x16, #3
  svc #0x80
  mrs x9, nzcv
  str x0, [x21, #16]
  str x9, [x21, #24]
  tbnz x9, #29, _failure_checkpoint
  cmp x0, #4096
  b.ne _failure_checkpoint
"""
BLOCK_DATA = """
.data
.balign 8
.global _md1_open_result, _md1_open_flags, _md1_read_result, _md1_read_flags
_md1_open_result: .quad -1
_md1_open_flags: .quad 0
_md1_read_result: .quad -1
_md1_read_flags: .quad 0
Lmd1_path: .asciz "/dev/md1"
.balign 4096
.global _md1_buffer
_md1_buffer: .space 4096, 0
"""

APFS_PROBE = """
  adrp x0, Lapfs_mountpoint@PAGE
  add x0, x0, Lapfs_mountpoint@PAGEOFF
  mov x1, #0755
  mov x16, #136
  svc #0x80
  mrs x9, nzcv
  adrp x21, _apfs_mkdir_result@PAGE
  add x21, x21, _apfs_mkdir_result@PAGEOFF
  str x0, [x21]
  str x9, [x21, #8]
  b.cs _failure_checkpoint
  adrp x0, Lapfs_name@PAGE
  add x0, x0, Lapfs_name@PAGEOFF
  adrp x1, Lapfs_mountpoint@PAGE
  add x1, x1, Lapfs_mountpoint@PAGEOFF
  mov x2, #1
  adrp x3, Lapfs_arguments@PAGE
  add x3, x3, Lapfs_arguments@PAGEOFF
  mov x9, #1
  str x9, [x21, #64]
  mov x16, #167
  svc #0x80
  mrs x9, nzcv
  str x0, [x21, #16]
  str x9, [x21, #24]
  b.cs _failure_checkpoint
  adrp x0, Lapfs_mountpoint@PAGE
  add x0, x0, Lapfs_mountpoint@PAGEOFF
  adrp x1, _apfs_statfs_buf@PAGE
  add x1, x1, _apfs_statfs_buf@PAGEOFF
  mov x16, #345
  svc #0x80
  b.cs _failure_checkpoint
  adrp x0, Lapfs_probe_path@PAGE
  add x0, x0, Lapfs_probe_path@PAGEOFF
  mov x1, #0
  mov x2, #0
  mov x16, #5
  svc #0x80
  mrs x9, nzcv
  str x0, [x21, #32]
  str x9, [x21, #40]
  b.cs _failure_checkpoint
  adrp x1, _apfs_probe_buffer@PAGE
  add x1, x1, _apfs_probe_buffer@PAGEOFF
  mov x2, #64
  mov x16, #3
  svc #0x80
  mrs x9, nzcv
  str x0, [x21, #48]
  str x9, [x21, #56]
  b.cs _failure_checkpoint
"""

APFS_DATA = """
.data
.balign 8
.global _apfs_mkdir_result, _apfs_mkdir_flags, _apfs_mount_result, _apfs_mount_flags
.global _apfs_open_result, _apfs_open_flags, _apfs_read_result, _apfs_read_flags, _apfs_mount_attempted
_apfs_mkdir_result: .quad -1
_apfs_mkdir_flags: .quad 0
_apfs_mount_result: .quad -1
_apfs_mount_flags: .quad 0
_apfs_open_result: .quad -1
_apfs_open_flags: .quad 0
_apfs_read_result: .quad -1
_apfs_read_flags: .quad 0
_apfs_mount_attempted: .quad 0
Lapfs_name: .asciz "apfs"
Lapfs_mountpoint: .asciz "/dev/apfs-offline"
Lapfs_probe_path: .asciz "/dev/apfs-offline/probe.bin"
Lapfs_device: .asciz "/dev/md1s1"
.balign 8
Lapfs_arguments:
  .quad Lapfs_device, 1
  .short 1
  .space 0x150 - 18, 0
.global _apfs_probe_buffer
_apfs_probe_buffer: .space 64, 0
.balign 8
_apfs_statfs_buf: .space 64, 0
.global _apfs_statfs_flags
_apfs_statfs_flags: .long 0
  .space 4, 0
.global _apfs_statfs_fstype, _apfs_statfs_mountpoint
_apfs_statfs_fstype: .space 16, 0
_apfs_statfs_mountpoint: .space 1024, 0
  .space 1024 + 32, 0
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--device", choices=("/dev/md0", "/dev/md1", "/dev/md1s1"), default="/dev/md1s1")
    parser.add_argument("--read-offset", type=lambda v: int(v, 0), default=0)
    parser.add_argument("--write-open", action="store_true", help="Expected-refusal control: try O_RDWR")
    parser.add_argument("--apfs-mount", action="store_true", help="21H16 APFS read-only data mount and file read")
    args = parser.parse_args()
    if sys.platform != "darwin":
        raise SystemExit("own EL0 fixture compilation requires macOS Actions")
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=False)
    if not 0 <= args.read_offset <= 0xffffffff or args.read_offset % 4096:
        raise ValueError("read offset must be page aligned and fit 32 bits")
    block_probe = BLOCK_PROBE
    if args.write_open:
        block_probe = block_probe.replace("  mov x1, #0\n  mov x2, #0", "  mov x1, #2\n  mov x2, #0")
    if args.apfs_mount:
        if args.write_open or args.device != "/dev/md1s1" or args.read_offset:
            raise ValueError("APFS mount requires the ordinary md1 read instrument")
        block_probe += APFS_PROBE
    if args.read_offset:
        seek = f"""
  mov x22, x0
  movz x1, #{args.read_offset & 65535}
  movk x1, #{args.read_offset >> 16}, lsl #16
  mov x2, #0
  mov x16, #199
  svc #0x80
  b.cs _failure_checkpoint
  movz x9, #{args.read_offset & 65535}
  movk x9, #{args.read_offset >> 16}, lsl #16
  cmp x0, x9
  b.ne _failure_checkpoint
  mov x0, x22
"""
        block_probe = block_probe.replace("  adrp x1, _md1_buffer@PAGE", seek + "  adrp x1, _md1_buffer@PAGE")
    source = BASE_SOURCE.replace(".p2align 2\n_checkpoint:", block_probe + "\n.p2align 2\n_checkpoint:")
    if source == BASE_SOURCE:
        raise ValueError("base fixture checkpoint marker absent")
    source += BLOCK_DATA.replace('"/dev/md1"', json.dumps(args.device))
    if args.apfs_mount:
        # 21H16 mount_apfs passes fspec/flags/mode at 0/8/16; original APFS
        # vfs_mount copies 0x144 bytes. Reserve the helper's 0x150-byte storage.
        source += APFS_DATA
    assembly = out / "md1-user.S"
    assembly.write_text(source, encoding="ascii")
    image = out / "launchd.macho"
    commands = [
        ["xcrun", "clang", "-target", "arm64-apple-ios17.0", "-c", str(assembly), "-o", str(out / "user.o")],
        ["xcrun", "ld", "-arch", "arm64", "-static", "-e", "_start", "-headerpad", "0x40",
         "-platform_version", "ios", "17.0", "17.0", str(out / "user.o"), "-o", str(image)],
        ["codesign", "--force", "--sign", "-", "--pagesize", "4096",
         "--identifier", "org.hackios.own-md1-probe", str(image)],
        ["codesign", "--verify", "--strict", str(image)],
    ]
    records = []
    try:
        for command in commands:
            result = subprocess.run(command, capture_output=True, text=True)
            records.append({"argv": command, "returncode": result.returncode,
                            "stdout": result.stdout, "stderr": result.stderr})
            result.check_returncode()
        nm = subprocess.check_output(["xcrun", "nm", "-U", str(image)], text=True)
        symbols = {name: int(va, 16) for va, name in
                   re.findall(r"^([0-9a-fA-F]+)\s+\S\s+(_\S+)$", nm, re.M)}
        if not all(name in symbols for name in ("_checkpoint", "_md1_buffer", "_md1_read_result")):
            raise ValueError("own probe symbol table incomplete")
        contract = json.loads(json.dumps(BASE_CONTRACT))
        contract.update({
            "checkpoint": symbols["_checkpoint"], "failure_checkpoint": symbols["_failure_checkpoint"],
            "description": "Own static PID1: core syscall regression plus actual md1 read of block 0",
            "mdev_block_read_probe": True, "apfs_mount_tested": False, "apple_userspace_used": False,
            "mdev_device": args.device, "mdev_read_offset": args.read_offset, "source": "md1-user.S",
            "mdev_write_open": args.write_open,
        })
        contract["memory"].update({
            "_md1_open_result": {"width": 8, "predicate": "nonnegative_signed"},
            "_md1_open_flags": {"width": 8, "value": 0, "mask": 0x20000000},
            "_md1_read_result": {"width": 8, "value": 4096},
            "_md1_read_flags": {"width": 8, "value": 0, "mask": 0x20000000},
        })
        if args.apfs_mount:
            contract["apfs_file_read_probe"] = True
            contract["memory"].update({
                "_apfs_mkdir_result": {"width": 8, "value": 0},
                "_apfs_mkdir_flags": {"width": 8, "value": 0, "mask": 0x20000000},
                "_apfs_mount_result": {"width": 8, "value": 0},
                "_apfs_mount_flags": {"width": 8, "value": 0, "mask": 0x20000000},
                "_apfs_open_result": {"width": 8, "predicate": "nonnegative_signed"},
                "_apfs_open_flags": {"width": 8, "value": 0, "mask": 0x20000000},
                "_apfs_read_result": {"width": 8, "value": 22},
                "_apfs_read_flags": {"width": 8, "value": 0, "mask": 0x20000000},
                "_apfs_mount_attempted": {"width": 8, "value": 1},
                "_apfs_statfs_flags": {"width": 4, "value": 1, "mask": 1},
            })
            contract["buffers"] = {
                "_apfs_probe_buffer": {"size": 22, "sha256": hashlib.sha256(b"HACKIOS_APFS_PROBE_V1\n").hexdigest()},
                "_apfs_statfs_fstype": {"size": 5, "sha256": hashlib.sha256(b"apfs\0").hexdigest()},
                "_apfs_statfs_mountpoint": {"size": 18, "sha256": hashlib.sha256(b"/dev/apfs-offline\0").hexdigest()},
            }
        (out / "addresses.json").write_text(json.dumps(symbols, indent=2) + "\n")
        (out / "el0-contract.json").write_text(json.dumps(contract, indent=2) + "\n")
    finally:
        report = {
            "commands": records, "source_sha256": hashlib.sha256(assembly.read_bytes()).hexdigest(),
            "fixture_sha256": hashlib.sha256(image.read_bytes()).hexdigest() if image.exists() else None,
            "compilation_passed": len(records) == len(commands) and all(r["returncode"] == 0 for r in records),
            "apfs_mount_tested": False, "apple_userspace_used": False,
        }
        (out / "build.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
