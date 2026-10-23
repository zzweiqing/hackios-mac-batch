#!/usr/bin/env python3
"""Fetch the two public Darwin 23 headers used for virtual IOMedia calls."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
from urllib.request import urlopen

REVISION = "e45fbe30a7879e0b16e26dddb78538f1b00e0bff"
BASE = "https://raw.githubusercontent.com/apple-oss-distributions/IOStorageFamily/"
HEADERS = ("IOStorage.h", "IOMedia.h")
DEVICE_HEADERS = (
    "IOAppleLabelScheme.h", "IOApplePartitionScheme.h", "IOBlockStorageDevice.h",
    "IOBlockStorageDriver.h", "IOBlockStoragePerfControlExports.h", "IOFDiskPartitionScheme.h",
    "IOFilterScheme.h", "IOGUIDPartitionScheme.h", "IOMedia.h", "IOMediaBSDClient.h",
    "IOPartitionScheme.h", "IORequest.h", "IORequestsPool.h", "IOStorage.h",
    "IOStorageCardCharacteristics.h", "IOStorageControllerCharacteristics.h",
    "IOStorageDeviceCharacteristics.h", "IOStorageProtocolCharacteristics.h",
    "IOUserBlockStorageDevice_kext.h",
)


def fetch_header(name):
    with urlopen(BASE + REVISION + "/" + name, timeout=60) as response:
        return name, response.read()


def prepare(root, storage_device=False):
    root = Path(root)
    output = root / "mac-batch-output/storage-headers"
    target = output / "IOKit/storage"
    target.mkdir(parents=True, exist_ok=True)
    names = DEVICE_HEADERS if storage_device else HEADERS
    with ThreadPoolExecutor(max_workers=4) as pool:
        for name, data in pool.map(fetch_header, names):
            (target / name).write_bytes(data)
    (output / "provenance.json").write_text(json.dumps({
        "repository": "apple-oss-distributions/IOStorageFamily",
        "revision": REVISION,
        "headers": list(names),
        "purpose": "declarations only; original IOMedia is allocated at runtime",
        "storage_implementation_recompiled": False,
    }, indent=2) + "\n")
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    print(prepare(parser.parse_args().root))
