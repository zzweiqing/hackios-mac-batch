#!/usr/bin/env python3
"""Expand a private raw OwnerData APFS image on a macOS Actions runner."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import uuid
import zlib

PAGE = 4096
SECTOR = 512
ALIGNMENT = 1024 * 1024
PARTITION_START = ALIGNMENT // SECTOR
GPT_ENTRIES = 128
GPT_ENTRY_BYTES = 128
APFS_TYPE = uuid.UUID('7c3457ef-0000-11aa-aa11-00306543ecac')
DEVICE_PATTERN = re.compile(r'/dev/(disk(?:0|[1-9][0-9]*))(?:s([1-9][0-9]*))?\Z')
HDIUTIL = '/usr/bin/hdiutil'
DISKUTIL = '/usr/sbin/diskutil'
MOUNT_APFS = '/sbin/mount_apfs'
FSCK_APFS = '/sbin/fsck_apfs'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode()


def write_json(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(encoded(value))


@contextmanager
def read_file(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'Input is not a regular file')
        yield stream


@contextmanager
def new_file(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        yield stream


def sha256_file(path):
    digest = hashlib.sha256()
    with read_file(path) as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def unlinked_path(path):
    path = Path(path)
    require('..' not in path.parts, 'Parent traversal is forbidden')
    absolute = path.absolute()
    for component in (absolute, *absolute.parents):
        require(not component.is_symlink() and
                not getattr(component, 'is_junction', lambda: False)(), 'Linked path is forbidden')
    return absolute


def validate_parameters(input_path, expected_sha256, output_dir, target_bytes):
    require(isinstance(expected_sha256, str) and
            re.fullmatch(r'[0-9a-fA-F]{64}', expected_sha256), 'Invalid input SHA256')
    require(type(target_bytes) is int and 0 < target_bytes < (1 << 63) - 2 * ALIGNMENT and
            target_bytes % ALIGNMENT == 0, 'Target must be a positive MiB-aligned byte count')
    source = unlinked_path(input_path)
    output = unlinked_path(output_dir)
    require(source != output and output not in source.parents, 'Input/output paths overlap')
    require(source.is_file() and source.stat().st_nlink == 1, 'Missing or multiply linked input')
    require(not output.exists() and output.parent.is_dir(), 'Output must be a new directory')
    source_bytes = source.stat().st_size
    require(source_bytes >= 32 * ALIGNMENT and source_bytes % PAGE == 0 and
            target_bytes > source_bytes, 'Target must expand a page-aligned raw APFS image')
    require(shutil.disk_usage(output.parent).free >= 2 * target_bytes + 2 * ALIGNMENT,
            'Insufficient host space for wrapper and extracted candidate')
    return source, output


def inspect_superblock(path):
    with read_file(path) as stream:
        header = stream.read(PAGE)
        image_bytes = os.fstat(stream.fileno()).st_size
    require(len(header) == PAGE and header[32:36] == b'NXSB', 'Missing raw APFS superblock')
    block_bytes, blocks = struct.unpack_from('<IQ', header, 36)
    require(block_bytes == PAGE and blocks * block_bytes == image_bytes,
            'APFS geometry differs from raw image size')
    container_uuid = uuid.UUID(bytes=header[72:88])
    require(container_uuid.int != 0, 'Missing APFS container UUID')
    features, readonly_features, incompatible_features = struct.unpack_from('<QQQ', header, 48)
    return {'block_bytes': block_bytes, 'blocks': blocks, 'bytes': image_bytes,
            'container_uuid': str(container_uuid), 'features': features,
            'readonly_compatible_features': readonly_features,
            'incompatible_features': incompatible_features}


def verify_container_features(original, candidate):
    require(all(original[key] == candidate[key] for key in
                ('features', 'readonly_compatible_features', 'incompatible_features')),
            'APFS container feature flags changed')


def gpt_header(current, alternate, entries_lba, sectors, disk_uuid, entries):
    header = bytearray(SECTOR)
    struct.pack_into('<8sIIIIQQQQ16sQIII', header, 0, b'EFI PART', 0x10000, 92, 0, 0,
                     current, alternate, 34, sectors - 34, disk_uuid.bytes_le,
                     entries_lba, GPT_ENTRIES, GPT_ENTRY_BYTES, zlib.crc32(entries))
    struct.pack_into('<I', header, 16, zlib.crc32(header[:92]))
    return header


def create_wrapper(source, wrapper, source_bytes, target_bytes):
    wrapper_bytes = target_bytes + 2 * ALIGNMENT
    sectors = wrapper_bytes // SECTOR
    entries = bytearray(GPT_ENTRIES * GPT_ENTRY_BYTES)
    disk_uuid, partition_uuid = uuid.uuid4(), uuid.uuid4()
    struct.pack_into('<16s16sQQQ', entries, 0, APFS_TYPE.bytes_le, partition_uuid.bytes_le,
                     PARTITION_START, PARTITION_START + source_bytes // SECTOR - 1, 0)
    entries[56:74] = 'OwnerData'.encode('utf-16-le')
    mbr = bytearray(SECTOR)
    struct.pack_into('<B3sB3sII', mbr, 446, 0, b'\x00\x02\x00', 0xee,
                     b'\xff\xff\xff', 1, min(sectors - 1, 0xffffffff))
    mbr[510:512] = b'\x55\xaa'
    digest = hashlib.sha256()
    with read_file(source) as original, new_file(wrapper) as candidate:
        candidate.truncate(wrapper_bytes)
        candidate.write(mbr)
        candidate.write(gpt_header(1, sectors - 1, 2, sectors, disk_uuid, entries))
        candidate.write(entries)
        candidate.seek((sectors - 33) * SECTOR)
        candidate.write(entries)
        candidate.write(gpt_header(sectors - 1, 1, sectors - 33, sectors, disk_uuid, entries))
        candidate.seek(ALIGNMENT)
        copied = 0
        for chunk in iter(lambda: original.read(1024 * 1024), b''):
            candidate.write(chunk)
            digest.update(chunk)
            copied += len(chunk)
        require(copied == source_bytes, 'Input changed while copying')
        candidate.flush()
        os.fsync(candidate.fileno())
    return digest.hexdigest()


def inspect_gpt(path, expected_partition_bytes):
    with read_file(path) as stream:
        image_bytes = os.fstat(stream.fileno()).st_size
        require(image_bytes % SECTOR == 0, 'Unaligned GPT image')
        sectors = image_bytes // SECTOR
        require(sectors > PARTITION_START + 34, 'GPT image is too small')
        mbr = stream.read(SECTOR)
        require(mbr[510:512] == b'\x55\xaa' and mbr[450] == 0xee and
                struct.unpack_from('<II', mbr, 454) == (1, min(sectors - 1, 0xffffffff)) and
                mbr[462:510] == bytes(48), 'Invalid protective MBR')
        headers = []
        for current, alternate, entries_lba in ((1, sectors - 1, 2),
                                                (sectors - 1, 1, sectors - 33)):
            stream.seek(current * SECTOR)
            header = bytearray(stream.read(SECTOR))
            require(len(header) == SECTOR, 'Truncated GPT header')
            fields = struct.unpack_from('<8sIIIIQQQQ16sQIII', header)
            magic, revision, length, checksum, reserved, actual, backup, first, last, \
                disk_uuid, table_lba, count, entry_bytes, entries_crc = fields
            require(magic == b'EFI PART' and revision == 0x10000 and length == 92 and
                    reserved == 0 and actual == current and backup == alternate and
                    first == 34 and last == sectors - 34 and table_lba == entries_lba and
                    count == GPT_ENTRIES and entry_bytes == GPT_ENTRY_BYTES,
                    'GPT header geometry changed')
            struct.pack_into('<I', header, 16, 0)
            require(zlib.crc32(header[:length]) == checksum, 'GPT header CRC failed')
            stream.seek(table_lba * SECTOR)
            entries = stream.read(count * entry_bytes)
            require(len(entries) == count * entry_bytes and zlib.crc32(entries) == entries_crc,
                    'GPT entry CRC failed')
            headers.append((disk_uuid, entries))
        require(headers[0] == headers[1], 'Primary and backup GPT disagree')
        disk_uuid, entries = headers[0]
        part_type, part_uuid, first, last, attributes = struct.unpack_from('<16s16sQQQ', entries)
        require(part_type == APFS_TYPE.bytes_le and uuid.UUID(bytes_le=part_uuid).int != 0 and
                first == PARTITION_START and last >= first and last <= sectors - 34 and
                (last - first + 1) * SECTOR == expected_partition_bytes and attributes == 0 and
                entries[GPT_ENTRY_BYTES:] == bytes(len(entries) - GPT_ENTRY_BYTES),
                'GPT must contain only the expected APFS extent')
    return {'image_bytes': image_bytes, 'partition_start_lba': first,
            'partition_bytes': expected_partition_bytes, 'disk_uuid': str(uuid.UUID(bytes_le=disk_uuid)),
            'partition_uuid': str(uuid.UUID(bytes_le=part_uuid))}


def device_node(value):
    require(isinstance(value, str), 'Missing device identifier')
    node = value if value.startswith('/dev/') else '/dev/' + value
    require(DEVICE_PATTERN.fullmatch(node), 'Invalid disk device')
    return node


def raw_device(value, owned):
    node = device_node(value)
    require(node in owned, 'Device is outside this attachment')
    return '/dev/r' + node.removeprefix('/dev/')


def parse_attached_devices(payload):
    require(isinstance(payload, dict), 'Invalid hdiutil plist')
    entities = payload.get('system-entities')
    require(isinstance(entities, list) and entities, 'Missing hdiutil entities')
    devices = [device_node(entity['dev-entry']) for entity in entities
               if isinstance(entity, dict) and 'dev-entry' in entity]
    require(1 <= len(devices) <= 4 and len(set(devices)) == len(devices),
            'Invalid or duplicate attached devices')
    require(DEVICE_PATTERN.fullmatch(devices[0]).group(2) is None,
            'Attachment does not begin with a whole disk')
    return tuple(devices)


def normalized_uuid(value):
    require(isinstance(value, str), 'Missing UUID')
    parsed = uuid.UUID(value)
    require(parsed.int != 0, 'Zero UUID')
    return str(parsed)


def parse_topology(payload, infos, owned, expected_bytes, *, wrapper, readonly):
    containers = payload.get('Containers') if isinstance(payload, dict) else None
    require(isinstance(containers, list) and len(containers) == 1, 'Expected one APFS container')
    container = containers[0]
    stores, volumes = container.get('PhysicalStores'), container.get('Volumes')
    require(isinstance(stores, list) and len(stores) == 1 and
            isinstance(volumes, list) and len(volumes) == 1, 'Expected one store and one volume')
    store, volume = stores[0], volumes[0]
    container_device = device_node(container.get('ContainerReference'))
    store_device = device_node(store.get('DeviceIdentifier'))
    volume_device = device_node(volume.get('DeviceIdentifier'))
    for device in (container_device, store_device, volume_device):
        require(device in owned and device in infos, 'APFS topology escapes this attachment')
        require(device_node(infos[device].get('DeviceIdentifier')) == device, 'Device info identity differs')
    physical_match = DEVICE_PATTERN.fullmatch(store_device)
    root = '/dev/' + physical_match.group(1)
    require((physical_match.group(2) == '1' if wrapper else physical_match.group(2) is None) and
            root in owned and container_device != root and
            DEVICE_PATTERN.fullmatch(container_device).group(2) is None and
            '/dev/' + DEVICE_PATTERN.fullmatch(volume_device).group(1) == container_device and
            DEVICE_PATTERN.fullmatch(volume_device).group(2) is not None and
            set(owned) == {root, store_device, container_device, volume_device},
            'Unexpected APFS device family')
    require(container.get('Fusion') is False and container.get('CapacityCeiling') == expected_bytes and
            store.get('Size') == expected_bytes and type(container.get('CapacityFree')) is int and
            0 <= container['CapacityFree'] <= expected_bytes, 'APFS store/container geometry differs')
    store_info, volume_info = infos[store_device], infos[volume_device]
    require(store_info.get('TotalSize') == expected_bytes and
            store_info.get('DeviceBlockSize') == SECTOR and
            store_info.get('ReadOnlyMedia') is readonly,
            'Backing store size, sector size or access mode differs')
    for info in (store_info, volume_info):
        require(device_node(info.get('APFSContainerReference')) == container_device,
                'APFS container references disagree')
    require(volume.get('Name') == 'OwnerData' and volume_info.get('VolumeName') == 'OwnerData' and
            str(volume_info.get('FilesystemType', '')).lower() == 'apfs' and
            volume.get('FileVault') is False, 'Expected unencrypted OwnerData APFS volume')
    for key in ('Encrypted', 'APFSEncrypted', 'Locked'):
        require(key not in volume_info or volume_info[key] is False, 'Encrypted/locked volume refused')
        require(key not in volume or volume[key] is False, 'Encrypted/locked volume refused')
    require(volume_info.get('Mounted') is False and not volume_info.get('MountPoint') and
            all(not info.get('Mounted') and not info.get('MountPoint') for info in infos.values()),
            'An attached filesystem is unexpectedly mounted')
    require(volume.get('CapacityQuota', 0) == 0, 'A volume quota would prevent expansion')
    volume_uuid = normalized_uuid(volume.get('APFSVolumeUUID'))
    require(volume_uuid == normalized_uuid(volume_info.get('VolumeUUID')), 'Volume UUIDs disagree')
    volume_flags = {}
    for source_name, source_info in (('apfs_list', volume), ('disk_info', volume_info)):
        for key in ('APFSVolumeFeatures', 'APFSVolumeReadOnlyCompatibleFeatures',
                    'APFSVolumeIncompatibleFeatures', 'APFSVolumeFlags', 'VolumeFlags'):
            if key in source_info:
                require(type(source_info[key]) is int and source_info[key] >= 0, 'Invalid APFS volume flags')
                volume_flags[source_name + ':' + key] = source_info[key]
    return {'root_device': root, 'store_device': store_device, 'container_device': container_device,
            'volume_device': volume_device, 'container_uuid': normalized_uuid(container.get('APFSContainerUUID')),
            'volume_uuid': volume_uuid, 'bytes': expected_bytes, 'free_bytes': container['CapacityFree'],
            'encrypted': False, 'volume_name': 'OwnerData', 'volume_feature_flags': volume_flags,
            'volume_feature_flags_available': bool(volume_flags)}


def verify_identity(original, candidate):
    require(all(original[key] == candidate[key]
                for key in ('container_uuid', 'volume_uuid', 'volume_name', 'encrypted', 'volume_feature_flags')),
            'APFS identity changed')


def darwin_acl(path):
    if sys.platform != 'darwin':
        return {'available': False}
    library = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    library.acl_get_link_np.argtypes = [ctypes.c_char_p, ctypes.c_int]
    library.acl_get_link_np.restype = ctypes.c_void_p
    library.acl_to_text.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ssize_t)]
    library.acl_to_text.restype = ctypes.c_void_p
    library.acl_free.argtypes = [ctypes.c_void_p]
    library.acl_free.restype = ctypes.c_int
    ctypes.set_errno(0)
    acl = library.acl_get_link_np(os.fsencode(path), 0x100)  # ACL_TYPE_EXTENDED, no symlink following.
    if not acl:
        raise OSError(ctypes.get_errno(), 'Cannot read Darwin ACL')
    text = None
    try:
        size = ctypes.c_ssize_t()
        text = library.acl_to_text(acl, ctypes.byref(size))
        if not text or size.value < 0:
            raise OSError(ctypes.get_errno(), 'Cannot serialize Darwin ACL')
        value = ctypes.string_at(text, size.value)
        return {'available': True, 'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()}
    finally:
        if text:
            library.acl_free(text)
        library.acl_free(acl)


def build_manifest(mountpoint):
    root = os.fsencode(mountpoint)
    root_device = os.lstat(root).st_dev
    entries, links, pending = {}, {}, [(root, b'')]
    while pending:
        path, relative = pending.pop()
        before = os.lstat(path)
        require(before.st_dev == root_device, 'Manifest crosses a filesystem boundary')
        kind = stat.S_IFMT(before.st_mode)
        record = {'mode': before.st_mode, 'uid': before.st_uid, 'gid': before.st_gid,
                  'flags': getattr(before, 'st_flags', 0), 'mtime_ns': before.st_mtime_ns,
                  'birthtime': getattr(before, 'st_birthtime', None),
                  'birthtime_ns': getattr(before, 'st_birthtime_ns', None)}
        if kind == stat.S_IFREG:
            digest, read_bytes = hashlib.sha256(), 0
            with read_file(path) as stream:
                opened = os.fstat(stream.fileno())
                require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
                        'File changed while opening')
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(chunk)
                    read_bytes += len(chunk)
            require(read_bytes == before.st_size, 'File size changed while reading')
            record.update(bytes=read_bytes, sha256=digest.hexdigest(), nlink=before.st_nlink)
            if before.st_nlink > 1:
                links.setdefault(before.st_ino, []).append(os.fsdecode(relative))
        elif kind == stat.S_IFLNK:
            record['target'] = os.fsdecode(os.readlink(path))
        elif kind == stat.S_IFDIR:
            with os.scandir(path) as children:
                names = sorted(child.name for child in children)
            for name in reversed(names):
                require(name not in (b'.', b'..') and b'/' not in name, 'Invalid directory entry')
                pending.append((os.path.join(path, name), relative + (b'/' if relative else b'') + name))
        else:
            require(kind in (stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR, stat.S_IFBLK),
                    'Unsupported filesystem entry')
            record['rdev'] = before.st_rdev
        attributes = {}
        for name in sorted(os.listxattr(path, follow_symlinks=False)):
            value = os.getxattr(path, name, follow_symlinks=False)
            attributes[name] = {'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()}
        record['xattrs'] = attributes
        record['acl'] = darwin_acl(path)
        after = os.lstat(path)
        require((before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid,
                 before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid,
                 after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'Entry changed during traversal')
        entries[os.fsdecode(relative) or '.'] = record
    groups = sorted(sorted(paths) for paths in links.values())
    return {'schema': 'OwnerData-preservation-v1', 'entries': entries, 'hardlink_groups': groups}


def manifest_difference(original, candidate):
    require(original.get('schema') == candidate.get('schema') == 'OwnerData-preservation-v1',
            'Manifest schema differs')
    before, after = original['entries'], candidate['entries']
    return {'added': sorted(after.keys() - before.keys()), 'removed': sorted(before.keys() - after.keys()),
            'changed': sorted(name for name in before.keys() & after.keys() if before[name] != after[name]),
            'hardlinks_changed': original['hardlink_groups'] != candidate['hardlink_groups']}


def verify_manifests(original, candidate):
    difference = manifest_difference(original, candidate)
    require(not any(difference.values()), 'User filesystem manifest changed')
    return {'equal': True, 'entries': len(original['entries'])}


class Commands:
    def __init__(self, output, report):
        self.output, self.report = output, report
        (output / 'commands').mkdir(mode=0o700)

    def run(self, arguments, *, parse=False, required=True):
        require(isinstance(arguments, list) and all(isinstance(value, str) for value in arguments),
                'Commands must be argument arrays')
        index = len(self.report['commands']) + 1
        record = {'argv': arguments}
        try:
            completed = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True,
                                       timeout=600, check=False)
            record.update(returncode=completed.returncode, stdout=completed.stdout.decode('utf-8', 'replace'),
                          stderr=completed.stderr.decode('utf-8', 'replace'))
        except (OSError, subprocess.TimeoutExpired) as error:
            record.update(error=str(error), stdout=(getattr(error, 'stdout', None) or b'').decode('utf-8', 'replace'),
                          stderr=(getattr(error, 'stderr', None) or b'').decode('utf-8', 'replace'))
            raise
        finally:
            name = f'commands/{index:04d}.json'
            write_json(self.output / name, record)
            self.report['commands'].append({'log': name, 'returncode': record.get('returncode')})
            write_json(self.output / 'nabu-data-resize.json', self.report)
        require(not required or completed.returncode == 0, 'Host command failed; see private command log')
        return plistlib.loads(completed.stdout) if parse else completed


class Attachment:
    def __init__(self, commands, image, *, readonly, wrapper):
        self.commands, self.image, self.readonly, self.wrapper = commands, image, readonly, wrapper
        self.devices, self.topology, self.mountpoint = (), None, None

    def __enter__(self):
        arguments = [HDIUTIL, 'attach', '-nomount', '-nobrowse', '-noautofsck', '-plist',
                     '-imagekey', 'diskimage-class=CRawDiskImage']
        if self.readonly:
            arguments.append('-readonly')
        result = self.commands.run(arguments + [str(self.image)], required=False)
        self.devices = parse_attached_devices(plistlib.loads(result.stdout))
        if result.returncode:
            self.close()
            raise ValueError('hdiutil attach failed; see private command log')
        return self

    def info(self, device):
        require(device in self.devices, 'Device is outside this attachment')
        return self.commands.run([DISKUTIL, 'info', '-plist', device], parse=True)

    def qualify(self, expected_bytes):
        infos = {device: self.info(device) for device in self.devices}
        references = {device_node(info['APFSContainerReference']) for info in infos.values()
                      if info.get('APFSContainerReference')}
        require(len(references) == 1 and references <= set(self.devices), 'Ambiguous APFS container')
        container = next(iter(references))
        payload = self.commands.run([DISKUTIL, 'apfs', 'list', '-plist', container], parse=True)
        self.topology = parse_topology(payload, infos, self.devices, expected_bytes,
                                       wrapper=self.wrapper, readonly=self.readonly)
        return self.topology

    def snapshot(self, mountpoint):
        require(self.topology is not None and self.mountpoint is None, 'Attachment is not ready to mount')
        volume = self.topology['volume_device']
        require(volume in self.devices, 'Volume is outside this attachment')
        mountpoint.mkdir(mode=0o700)
        self.mountpoint = mountpoint
        self.commands.run([MOUNT_APFS, '-o', 'rdonly,nobrowse,owners,noatime', volume, str(mountpoint)])
        info = self.info(volume)
        require(info.get('Mounted') is True and info.get('MountPoint') == str(mountpoint) and
                info.get('ReadOnlyVolume') is True and
                os.statvfs(mountpoint).f_flag & os.ST_RDONLY and
                normalized_uuid(info.get('VolumeUUID')) == self.topology['volume_uuid'],
                'Read-only mount identity was not verified')
        manifest = build_manifest(mountpoint)
        self.unmount()
        return manifest

    def unmount(self):
        if self.mountpoint is None:
            return
        volume = self.topology['volume_device']
        require(volume in self.devices, 'Volume is outside this attachment')
        info = self.info(volume)
        if info.get('Mounted'):
            require(info.get('MountPoint') == str(self.mountpoint), 'Mount moved to an unexpected path')
            self.commands.run([DISKUTIL, 'unmount', volume])
        info = self.info(volume)
        require(info.get('Mounted') is False and not info.get('MountPoint'), 'Volume remains mounted')
        self.mountpoint.rmdir()
        self.mountpoint = None

    def resize(self, target_bytes):
        require(not self.readonly and self.wrapper and self.topology is not None and
                self.mountpoint is None and target_bytes > self.topology['bytes'], 'Unsafe resize state')
        device = self.topology['store_device']
        require(device in self.devices, 'Store is outside this attachment')
        self.qualify(self.topology['bytes'])
        self.commands.run([DISKUTIL, 'apfs', 'resizeContainer', device, f'{target_bytes}B'])

    def fsck(self):
        require(self.topology is not None and self.mountpoint is None, 'Filesystem must be unmounted for fsck')
        self.qualify(self.topology['bytes'])
        self.commands.run([FSCK_APFS, '-n', raw_device(self.topology['store_device'], self.devices)])

    def close(self):
        errors = []
        try:
            self.unmount()
        except Exception as error:
            errors.append(str(error))
        if self.devices:
            root = self.topology['root_device'] if self.topology else self.devices[0]
            require(root in self.devices, 'Detach device is outside this attachment')
            try:
                self.commands.run([HDIUTIL, 'detach', root])
                self.devices = ()
            except Exception as error:
                errors.append(str(error))
        require(not errors, 'Attachment cleanup failed: ' + '; '.join(errors))

    def __exit__(self, error_type, error, traceback):
        try:
            self.close()
        except Exception as cleanup_error:
            self.commands.report.setdefault('cleanup_errors', []).append(str(cleanup_error))
            if error is None:
                raise


def extract_partition(wrapper, candidate, geometry):
    with read_file(wrapper) as source, new_file(candidate) as destination:
        source.seek(geometry['partition_start_lba'] * SECTOR)
        remaining = geometry['partition_bytes']
        while remaining:
            chunk = source.read(min(1024 * 1024, remaining))
            require(chunk, 'Truncated wrapper partition')
            destination.write(chunk)
            remaining -= len(chunk)
        destination.flush()
        os.fsync(destination.fileno())


def resize_image(source, expected_sha256, output, target_bytes):
    report = {'schema': 'nabu-data-resize-v1', 'result': 'in_progress', 'commands': [],
              'input': str(source), 'input_sha256_expected': expected_sha256,
              'target_bytes': target_bytes, 'candidate': 'resized.apfs.raw',
              'github_run_id': os.environ.get('GITHUB_RUN_ID'), 'github_head_sha': os.environ.get('GITHUB_SHA'),
              'script_sha256': sha256_file(Path(__file__)), 'device_writes': False, 'ipados_booted': False}
    commands = Commands(output, report)
    try:
        require(sys.platform == 'darwin' and os.geteuid() == 0, 'Requires macOS Actions with root privileges')
        require(sha256_file(source) == expected_sha256, 'Input SHA256 differs')
        original_geometry = inspect_superblock(source)
        report['input_geometry'] = original_geometry
        commands.run(['/usr/bin/sw_vers'])
        with Attachment(commands, source, readonly=True, wrapper=False) as attached:
            original = attached.qualify(original_geometry['bytes'])
            require(original['container_uuid'] == original_geometry['container_uuid'], 'Raw/container UUID differs')
            report['input_topology'] = original
            before = attached.snapshot(output / 'mount-input')
            write_json(output / 'input-manifest.json', before)
        wrapper = output / 'resize-wrapper.raw'
        require(create_wrapper(source, wrapper, original_geometry['bytes'], target_bytes) == expected_sha256,
                'Copied APFS bytes differ from input')
        initial_gpt = inspect_gpt(wrapper, original_geometry['bytes'])
        report['wrapper_before'] = initial_gpt
        with Attachment(commands, wrapper, readonly=False, wrapper=True) as attached:
            verify_identity(original, attached.qualify(original_geometry['bytes']))
            attached.resize(target_bytes)
            resized = attached.qualify(target_bytes)
            verify_identity(original, resized)
            report['resized_topology'] = resized
            require(resized['free_bytes'] > original['free_bytes'], 'APFS free capacity did not increase')
            report['capacity_free_before'] = original['free_bytes']
            report['capacity_free_after'] = resized['free_bytes']
            attached.fsck()
            report['fsck_apfs_read_only_passed'] = True
            after = attached.snapshot(output / 'mount-output')
            write_json(output / 'output-manifest.json', after)
            report['manifest_difference'] = manifest_difference(before, after)
            report['manifest_preservation'] = verify_manifests(before, after)
        final_gpt = inspect_gpt(wrapper, target_bytes)
        require(all(initial_gpt[key] == final_gpt[key]
                    for key in ('image_bytes', 'partition_start_lba', 'disk_uuid', 'partition_uuid')),
                'Wrapper GPT identity or start changed')
        report['wrapper_after'] = final_gpt
        candidate = output / 'resized.apfs.raw'
        extract_partition(wrapper, candidate, final_gpt)
        candidate_geometry = inspect_superblock(candidate)
        require(candidate_geometry['bytes'] == target_bytes and
                candidate_geometry['container_uuid'] == original_geometry['container_uuid'],
                'Extracted APFS geometry or identity differs')
        verify_container_features(original_geometry, candidate_geometry)
        report['container_feature_flags_unchanged'] = True
        report.update(candidate_geometry=candidate_geometry, candidate_sha256=sha256_file(candidate),
                      input_manifest_sha256=sha256_file(output / 'input-manifest.json'),
                      output_manifest_sha256=sha256_file(output / 'output-manifest.json'))
        require(not report.get('cleanup_errors'), 'Attachment cleanup was incomplete')
        report['result'] = 'apfs_resized_preserved_host_verified'
    except Exception as error:
        report.update(result='failed', error_type=type(error).__name__, error=str(error))
    finally:
        try:
            report['input_sha256_after'] = sha256_file(source)
            report['input_unchanged'] = report['input_sha256_after'] == expected_sha256
            require(report['input_unchanged'], 'Original input changed')
        except Exception as error:
            report.update(result='failed', input_verification_error=str(error))
        write_json(output / 'nabu-data-resize.json', report)
    return report['result'] == 'apfs_resized_preserved_host_verified'


class PrivateArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        print(json.dumps({'status': 'invalid_arguments'}))
        raise SystemExit(2)


def interrupted(signum, frame):
    raise RuntimeError('Host execution interrupted')


def main(argv=None):
    parser = PrivateArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--input-sha256', required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--target-bytes', type=int, required=True)
    options = parser.parse_args(argv)
    try:
        source, output = validate_parameters(options.input, options.input_sha256,
                                             options.output_dir, options.target_bytes)
        output.mkdir(mode=0o700)
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        passed = resize_image(source, options.input_sha256.lower(), output, options.target_bytes)
    except Exception:
        print(json.dumps({'status': 'failed'}))
        return 1
    print(json.dumps({'status': 'passed' if passed else 'failed'}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
