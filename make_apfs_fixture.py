#!/usr/bin/env python3
"""Create an unencrypted APFS probe in a raw file on a macOS Actions runner."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import struct
import subprocess
import sys

PROBE = b"HACKIOS_APFS_PROBE_V1\n"
MAX_BYTES = 64 * 1024 * 1024
PAGE = 4096


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_superblock(path):
    # Apple File System Reference: obj_phys_t is 32 bytes before nx_magic.
    with path.open("rb") as stream:
        header = stream.read(PAGE)
    if len(header) != PAGE or header[32:36] != b"NXSB":
        raise ValueError("missing APFS container superblock magic at offset 32")
    block_size, block_count = struct.unpack_from("<IQ", header, 36)
    if block_size != PAGE or block_count * block_size != path.stat().st_size:
        raise ValueError("APFS superblock geometry differs from raw image size")
    return {"block_size": block_size, "block_count": block_count}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--size-mib", type=int, default=32)
    args = parser.parse_args()
    if sys.platform != "darwin":
        raise SystemExit("APFS fixture creation requires macOS hdiutil/diskutil")
    if not 32 <= args.size_mib < 64:
        raise SystemExit("size must be at least 32 and less than 64 MiB")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    image = output / "apfs-probe.raw"
    mountpoint = output / "mount"
    mountpoint.mkdir()
    report = {
        "format": "raw", "creation_passed": False,
        "probe_path": "/probe.bin", "probe_content": PROBE.decode("ascii"),
        "probe_sha256": hashlib.sha256(PROBE).hexdigest(), "probe_size": len(PROBE),
        "requested_size_mib": args.size_mib, "page_bytes": PAGE,
        "apfs_uuid_and_timestamps_may_vary": True, "binary_determinism_claimed": False,
        "apfs_mount_tested": False, "ipados_booted": False, "commands": [],
    }

    def save():
        (output / "apfs-probe.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    def run(command, *, parse=False, required=True):
        result = subprocess.run(command, text=True, capture_output=True)
        report["commands"].append({
            "argv": command, "returncode": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr,
        })
        save()
        if required and result.returncode:
            raise RuntimeError(f"{command[0]} {command[1]} failed ({result.returncode}): {result.stderr}")
        return plistlib.loads(result.stdout.encode()) if parse else result.stdout.strip()

    device = None
    try:
        report["tool_versions"] = {
            "sw_vers": run(["sw_vers"]), "hdiutil": run(["hdiutil", "info", "-plist"]),
            "diskutil": run(["diskutil", "version"], required=False),
        }
        with image.open("xb") as stream:
            stream.truncate(args.size_mib * 1024 * 1024)
        attached = run(["hdiutil", "attach", "-nomount", "-nobrowse",
                        "-imagekey", "diskimage-class=CRawDiskImage", "-plist", str(image)], parse=True)
        physical = [e["dev-entry"] for e in attached.get("system-entities", []) if e.get("dev-entry")]
        if len(physical) != 1:
            raise ValueError("blank raw image must attach as one whole disk")
        device = physical[0]
        report["host_backing_device"] = device
        run(["diskutil", "apfs", "createContainer", device])
        info = run(["diskutil", "info", "-plist", device], parse=True)
        container = info.get("APFSContainerReference")
        if not container:
            raise ValueError("physical store has no APFSContainerReference")
        run(["sudo", "diskutil", "apfs", "addVolume", container, "APFS", "HackiosProbe",
             "-mountpoint", str(mountpoint)])
        topology = run(["diskutil", "apfs", "list", "-plist", container], parse=True)
        containers = topology.get("Containers", [])
        if len(containers) != 1 or len(containers[0].get("Volumes", [])) != 1:
            raise ValueError("fixture must expose exactly one APFS container and volume")
        volume = containers[0]["Volumes"][0]
        volume_info = run(["diskutil", "info", "-plist", volume["DeviceIdentifier"]], parse=True)
        if volume_info.get("MountPoint") != str(mountpoint):
            raise ValueError("probe volume mounted at an unexpected path")
        if volume.get("FileVault") is not False:
            raise ValueError("diskutil did not verify FileVault disabled")
        if str(volume_info.get("FilesystemType", "")).lower() != "apfs":
            raise ValueError("diskutil did not verify APFS filesystem")
        volume_uuid = volume_info.get("VolumeUUID")
        if not volume_uuid:
            raise ValueError("volume UUID is absent")
        run(["sudo", "chown", f"{os.getuid()}:{os.getgid()}", str(mountpoint)])
        probe = mountpoint / "probe.bin"
        probe.write_bytes(PROBE)
        os.sync()
        if probe.read_bytes() != PROBE:
            raise ValueError("host probe readback differs")
        report.update({
            "encrypted": False, "single_volume": True,
            "volume_uuid": volume_uuid, "volume_name": volume_info.get("VolumeName"),
            "container_uuid": containers[0].get("APFSContainerUUID"),
            "host_apfs_topology": topology,
        })
        run(["hdiutil", "detach", device])
        device = None
        geometry = inspect_superblock(image)
        size = image.stat().st_size
        if not 0 < size < MAX_BYTES or size % PAGE:
            raise ValueError("raw image violates the less-than-64-MiB page-aligned contract")
        report.update({
            "creation_passed": True, "image_bytes": size, "image_pages": size // PAGE,
            "image_sha256": sha256(image), **geometry,
        })
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        if device:
            try:
                run(["hdiutil", "detach", device])
            except Exception as error:
                report["cleanup_error"] = str(error)
        if not any(mountpoint.iterdir()):
            mountpoint.rmdir()
        save()
    print(json.dumps({key: value for key, value in report.items()
                      if key not in ("commands", "host_apfs_topology")}, indent=2))


if __name__ == "__main__":
    main()
