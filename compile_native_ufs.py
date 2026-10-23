#!/usr/bin/env python3
"""Compile the patched nabu UFS object on Actions; do not link or run it."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

from prepare_storage_headers import prepare


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    root, source = args.root.resolve(), args.source.resolve()
    prepared = json.loads((source / "nabu-ufs-source.json").read_text())
    if prepared.get("source_commit") != "af785c1777161a62931425c2faaa536ce0bebd5b":
        raise SystemExit("Expected the prepared pinned nabu UFS source")
    headers = prepare(root, storage_device=True)
    sdk = Path(subprocess.check_output(
        ["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True).strip())
    shutil.copyfile(sdk / "usr/include/TargetConditionals.h", headers / "TargetConditionals.h")
    output = root / "mac-batch-output/native-ufs"
    output.mkdir(exist_ok=False)
    (output / "source-prepare.json").write_text(json.dumps(prepared, indent=2) + "\n")
    destination = output / "NativeUfs.o"
    batch = json.loads((root / "mac-batch-output/compile-report.json").read_text())
    reference = next(r for r in batch["records"]
                     if r["object"] == "iokit/DEVELOPMENT/IOKitBSDInit.cpo")
    if reference["returncode"]:
        raise SystemExit("The reference IOKit compile did not pass")
    command, flags = [], iter(reference["command"])
    for flag in flags:
        if flag in ("-MF", "-MJ", "-MT", "-MQ"):
            next(flags)
        elif flag in ("-MD", "-MMD", "-MP"):
            continue
        elif flag == "-o":
            next(flags)
            command.extend(["-o", str(destination)])
        elif flag.endswith("/iokit/bsddev/IOKitBSDInit.cpp"):
            command.append(str(source / "NativeUfs.cpp"))
        else:
            command.append(flag)
    command.extend(["-I", str(headers), "-I", str(root / ".cache/xnu-work/osfmk")])
    result = subprocess.run(command, cwd=root / "build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT",
                            text=True, capture_output=True)
    (output / "compile.log").write_text(result.stdout + result.stderr)
    report = {"source_commit": prepared["source_commit"], "source": str(source),
              "command": command, "returncode": result.returncode,
              "compiled": result.returncode == 0, "linked": False,
              "personality_installed": False, "hardware_tested": False,
              "iostorage_bindings_connected": False, "output": str(destination)}
    (output / "compile.json").write_text(json.dumps(report, indent=2) + "\n")
    if result.returncode:
        raise SystemExit(result.stderr[-6000:])
    undefined = subprocess.check_output(["xcrun", "nm", "-u", str(destination)], text=True)
    (output / "undefined.txt").write_text(undefined)
    print(json.dumps({k: v for k, v in report.items() if k != "command"}, indent=2))


if __name__ == "__main__":
    main()
