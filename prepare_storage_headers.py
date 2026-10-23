#!/usr/bin/env python3
"""Fetch the two public Darwin 23 headers used for virtual IOMedia calls."""
import argparse
import json
from pathlib import Path
from urllib.request import urlopen

REVISION = "e45fbe30a7879e0b16e26dddb78538f1b00e0bff"
BASE = "https://raw.githubusercontent.com/apple-oss-distributions/IOStorageFamily/"
HEADERS = ("IOStorage.h", "IOMedia.h")


def prepare(root):
    root = Path(root)
    output = root / "mac-batch-output/storage-headers"
    target = output / "IOKit/storage"
    target.mkdir(parents=True, exist_ok=True)
    for name in HEADERS:
        with urlopen(BASE + REVISION + "/" + name, timeout=60) as response:
            data = response.read()
        if b"@APPLE_LICENSE_HEADER_START@" not in data:
            raise SystemExit("Unexpected public header: " + name)
        (target / name).write_bytes(data)
    (output / "provenance.json").write_text(json.dumps({
        "repository": "apple-oss-distributions/IOStorageFamily",
        "revision": REVISION,
        "headers": list(HEADERS),
        "purpose": "declarations only; original IOMedia is allocated at runtime",
        "storage_implementation_recompiled": False,
    }, indent=2) + "\n")
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    print(prepare(parser.parse_args().root))
