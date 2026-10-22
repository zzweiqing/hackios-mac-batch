#!/usr/bin/env python3
"""Read-only completeness check; missing exact sources remain explicit."""
import argparse,json,tarfile
from pathlib import Path
KIT=Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--full-root',type=Path);a=p.parse_args()
required=['inputs/mac-xnu-sdk-and-objects-backup-20261022.tar.gz','inputs/xnu-d8b80295118ef25ac3a784134bcf95cd8e88109f.tar.gz','inputs/restored-apple-headers.tar.gz','capture/build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/link.filelist','patches/nabu-mockfs-no-amfi-query.patch']
checks={name:(KIT/name).is_file() for name in required}
full=[]
if a.full_root:
    for name in ('refer/corecrypto-2023/corecrypto.xcodeproj/project.pbxproj','refer/libpthread/bsd/kern/kern_synch.c','drivers/ArmCpu/ArmCpu.cpp','drivers/ArmDTPlatform/ArmDTPlatform.cpp','scripts/build-xnu-offline.sh','scripts/seal-source-crypto-kernel.py','kits/NativePrelink/patches'):
        full.append({'path':name,'exists':(a.full_root/name).exists()})
report={'checks':checks,'captured_batch_complete':all(checks.values()),'full_source_closure':full,'full_clean_build_ready':bool(full) and all(x['exists'] for x in full),'mac_compilation_executed':False,'tablet_access':False}
print(json.dumps(report,indent=2));raise SystemExit(0 if report['captured_batch_complete'] and (not a.full_root or report['full_clean_build_ready']) else 1)
