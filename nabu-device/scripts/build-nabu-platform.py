#!/usr/bin/env python3
"""Build only G0 platform archives using the current XNU compilation contract."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess


def instrument_armcpu(text):
    """Expose the existing GIC failure path without adding register accesses."""
    text = text.replace('volatile uint32_t armcpu_registered = 0;', '''volatile uint32_t armcpu_registered = 0;
static const char *volatile nabu_gic_stage = "not probed";
static volatile uint32_t nabu_gic_pidr2, nabu_gic_last_offset, nabu_gic_last_value;
static volatile uint32_t nabu_gic_typer_affinity;''')
    text = text.replace('while ((read32 (base, offset) & mask) != 0) {',
                        'nabu_gic_last_offset = offset;\n'
                        '  while (((nabu_gic_last_value = read32 (base, offset)) & mask) != 0) {')
    stages = [
        ('IOService *ArmCpu::probe (IOService *provider, SInt32 *score)\n{', 'CPU probe'),
        ('bool ArmCpu::start (IOService *provider)\n{', 'CPU start'),
        ('bool ArmCpu::mapGic (void)\n{', 'DT nodes'),
        ('  OSData *ranges = OSDynamicCast (OSData, soc->getProperty ("ranges"));', 'DT properties'),
        ('  for (unsigned index = 0; index < 4; index += 2) {', 'DT address range'),
        ('  OSSharedPtr<IOMemoryDescriptor> distMemory (IOMemoryDescriptor::withPhysicalAddress (', 'MMIO allocation'),
        ('  distributor = OSSharedPtr<IOMemoryMap> (distMemory->map', 'MMIO mapping'),
        ('  dist = static_cast<uintptr_t> (distributor->getVirtualAddress ());', 'GICD PIDR2'),
        ('  write32 (dist, 0, ctl & ~3U);', 'GICD disable RWP'),
        ('  write32 (dist, 0, (ctl & ~3U) | 16U);', 'GICD ARE RWP'),
        ('  unsigned interrupts = ((read32 (dist, 4) & 31) + 1) * 32;', 'GICD SPI mask'),
        ('bool ArmCpu::wakeRedistributor (bool local)\n{', 'GICR affinity'),
        ('  write32 (redist, 0x14, read32 (redist, 0x14) & ~2U);', 'GICR WAKER'),
        ('  return waitClear (redist, 0, 8);', 'GICR RWP'),
        ('  gGicShared = 1;', 'CPU registration'),
        ('  controller = new IOCPUInterruptController;', 'IRQ controller'),
        ('  armcpu_gic_ready = 1;', 'ready'),
    ]
    for marker, stage in stages:
        insertion = f'  nabu_gic_stage = "{stage}";'
        if marker.endswith('\n{'):
            text = text.replace(marker, marker + '\n' + insertion)
        else:
            text = text.replace(marker, insertion + '\n' + marker)
    text = text.replace('  if (((read32 (dist, 0xffe8) >> 4) & 15) != 3) {',
                        '  nabu_gic_pidr2 = read32 (dist, 0xffe8);\n'
                        '  if (((nabu_gic_pidr2 >> 4) & 15) != 3) {')
    text = text.replace('    armcpu_gic_typer_probe[1] = static_cast<uint32_t> (typer);',
                        '    armcpu_gic_typer_probe[1] = static_cast<uint32_t> (typer);\n'
                        '    nabu_gic_typer_affinity = static_cast<uint32_t> (typer >> 32);')
    text += '''
extern "C" void nabu_armcpu_report (void)
{
  IOLog ("NABU GIC stage=%s registered=%u pidr2=%08x\\n",
      nabu_gic_stage, armcpu_registered, nabu_gic_pidr2);
  IOLog ("NABU GIC last[%x]=%08x mpidr=%08x scan=%x typer=%08x:%08x stride=%x\\n",
      nabu_gic_last_offset, nabu_gic_last_value, armcpu_boot_mpidr,
      armcpu_gic_typer_probe[0], nabu_gic_typer_affinity,
      armcpu_gic_typer_probe[1], armcpu_gic_stride);
}
'''
    return text


def compile_command(record, source, output):
    arguments = record['arguments']
    command = []
    index = 0
    while index < len(arguments):
        value = arguments[index]
        if value in ('-o', '-MF', '-MJ'):
            if value == '-o':
                command += ['-o', str(output)]
            index += 2
            continue
        if value not in ('-MD', '-MP'):
            command.append(str(source) if value == record['file'] else value)
        index += 1
    if str(source) not in command or str(output) not in command:
        raise ValueError('XNU recipe lacks the expected source/output arguments')
    return command


def check_object(data):
    if struct.unpack_from('<4I', data) != (0xfeedfacf, 0x100000c, 0, 1):
        raise ValueError('Expected ordinary ARM64 relocatable Mach-O')
    at, deployment = 32, None
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        cmd, size = struct.unpack_from('<II', data, at)
        if size < 8 or at + size > len(data):
            raise ValueError('Invalid Mach-O load command')
        if cmd == 0x32:
            deployment = struct.unpack_from('<II', data, at + 8)
        at += size
    if deployment != (2, 0x110000):
        raise ValueError(f'Expected iOS 17 deployment, got {deployment}')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('component', choices=['ArmDTPlatform', 'ArmCpu'])
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    recipe = root / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json'
    recipe_bytes = recipe.read_bytes()
    record = json.loads(recipe_bytes.decode('utf-8').strip().rstrip(','))
    source = root / 'drivers' / args.component / (args.component + '.cpp')
    out = root / 'build' / {'ArmDTPlatform': 'armdt-platform', 'ArmCpu': 'armcpu'}[args.component]
    out.mkdir(parents=True, exist_ok=True)
    if args.component == 'ArmCpu':
        original = source.read_text(encoding='utf-8')
        source = out / 'ArmCpu.cpp'
        source.write_text(instrument_armcpu(original), encoding='utf-8')
    obj = out / (args.component + '.o')
    command = compile_command(record, source, obj)
    command += ['-I', str(root / '.cache/xnu-work/osfmk')]
    (out / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n', encoding='utf-8')
    result = subprocess.run(command, cwd=record['directory'], capture_output=True)
    (out / 'compile.log').write_bytes(result.stdout + result.stderr)
    if recipe.read_bytes() != recipe_bytes:
        raise SystemExit('Platform build modified the original XNU compile record')
    if result.returncode:
        raise SystemExit(result.stderr.decode('utf-8', errors='replace')[-4000:])
    check_object(obj.read_bytes())
    archive = out / ('lib' + args.component + '.a')
    if archive.exists():
        raise SystemExit('Refuse to reuse an existing platform archive; use a fresh build')
    subprocess.run(['xcrun', 'ar', 'rcs', str(archive), str(obj)], check=True)
    (out / 'build-report.json').write_text(json.dumps({
        'component': args.component, 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
        'recipe_sha256': hashlib.sha256(recipe_bytes).hexdigest(),
        'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
        'architecture': 'arm64', 'deployment': 'iOS 17.0', 'runtime_qualified': False,
    }, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
