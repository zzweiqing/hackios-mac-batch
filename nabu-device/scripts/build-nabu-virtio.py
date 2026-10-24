#!/usr/bin/env python3
"""Build modern read-only VirtIO MMIO against the 21H16 storage class."""
import importlib.util
import json
from pathlib import Path
import subprocess

spec = importlib.util.spec_from_file_location(
    'platform_builder', Path(__file__).with_name('build-nabu-platform.py'))
platform = importlib.util.module_from_spec(spec)
spec.loader.exec_module(platform)

# Same original IOStorageFamily layout as the passing nabu UFS binding.
# The parent remains Apple's class, not a locally reconstructed substitute.
BINDINGS = {
    '__ZTV20IOBlockStorageDevice': 0xfffffff0059644c0,
    '__ZN20IOBlockStorageDevice10gMetaClassE': 0xfffffff0067751d0,
    '__ZN20IOBlockStorageDeviceC2EPK11OSMetaClass': 0xfffffff0046ced98,
    '__ZN20IOBlockStorageDeviceD2Ev': 0xfffffff0046cedb8,
    '__ZN20IOBlockStorageDevice4initEP12OSDictionary': 0xfffffff0046cee30,
    '__ZNK20IOBlockStorageDevice11getPropertyEPK8OSSymbol': 0xfffffff0046cee88,
    '__ZN20IOBlockStorageDevice13setPropertiesEP8OSObject': 0xfffffff0046cef38,
    '__ZN20IOBlockStorageDevice11requestIdleEv': 0xfffffff0046cf050,
    '__ZN20IOBlockStorageDevice7doUnmapEP26IOBlockStorageDeviceExtentjj': 0xfffffff0046cf05c,
    '__ZN20IOBlockStorageDevice13doSetPriorityEP26IOBlockStorageDeviceExtentjh': 0xfffffff0046cf068,
    '__ZN20IOBlockStorageDevice20doGetProvisionStatusEyyPjP35IOBlockStorageProvisionDeviceExtenty': 0xfffffff0046cf08c,
}


def main():
    root = Path(__file__).resolve().parents[1]
    record_path = root / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json'
    record = json.loads(record_path.read_text().strip().rstrip(','))
    source = root / 'drivers/NativeVirtioBlock/NativeVirtioBlock.cpp'
    out = root / 'build/native-virtio-block'
    out.mkdir(parents=True, exist_ok=True)
    obj = out / 'NativeVirtioBlock.o'
    command = platform.compile_command(record, source, obj)
    command += ['-I', str(root / 'build/storage-abi/include'),
                '-I', str(root / '.cache/xnu-work/osfmk')]
    (out / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n')
    subprocess.run(command, cwd=record['directory'], check=True)
    assembly = out / 'original-bindings.S'
    assembly.write_text(''.join(f'.globl {name}\n.set {name}, {value:#x}\n'
                               for name, value in BINDINGS.items()))
    bindings_obj = out / 'original-bindings.o'
    subprocess.run(['xcrun', 'clang', '-target', 'arm64-apple-ios17.0', '-c',
                    str(assembly), '-o', str(bindings_obj)], check=True)
    archive = out / 'libNativeVirtioBlock.a'
    subprocess.run(['xcrun', 'ar', 'rcs', str(archive), str(obj), str(bindings_obj)], check=True)
    (out / 'bindings.json').write_text(json.dumps({
        'original_build': '21H16', 'slide': -0x1360000,
        'bindings': {name: hex(value) for name, value in BINDINGS.items()},
        'transport': 'modern-mmio', 'read_only': True,
        'verified_root_enabled': False, 'runtime_qualified': False,
    }, indent=2) + '\n')


if __name__ == '__main__':
    main()
