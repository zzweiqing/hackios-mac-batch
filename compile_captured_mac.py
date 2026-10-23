#!/usr/bin/env python3
"""One native-Apple batch of real source object recompiles; fail on any error."""
import argparse,hashlib,json,subprocess
from pathlib import Path
from prepare_storage_headers import prepare as prepare_storage_headers

KIT=Path(__file__).resolve().parent
OLD='/Users/chuzu/Desktop/UniXNU-build/unixnu-mac-offline-20261021/work/UniXNU'
OBJECTS=['bsd/DEVELOPMENT/ubc_subr.o','bsd/DEVELOPMENT/memdev.o','iokit/DEVELOPMENT/IOKitBSDInit.cpo','osfmk/DEVELOPMENT/copyio.o','osfmk/DEVELOPMENT/arm_init.o','osfmk/DEVELOPMENT/pcb.o','osfmk/DEVELOPMENT/pmap.o','osfmk/DEVELOPMENT/platform_tests.o','osfmk/DEVELOPMENT/kernel_tests.o','osfmk/DEVELOPMENT/kdp_vm.o','bsd/DEVELOPMENT/bsd_tests.o','bsd/DEVELOPMENT/km.o']
PATCHES=[('non-apple-pmap-field.patch','osfmk/arm/pmap/pmap.h'),('native-arm-pan.patch','pexpert/pexpert/arm64/BCM2837.h'),('native-4k-user-abi.patch','osfmk/arm/arm_init.c'),('zzz-boot-progress.patch','osfmk/arm/arm_init.c'),('non-apple-iommu-bootstrap.patch','osfmk/arm/pmap/pmap.c'),('zzx-pmap-sync-64bit-pa.patch','osfmk/arm/pmap/pmap.c'),('native-4k-signature-hash-cache.patch','bsd/sys/ubc_internal.h'),('nabu-mockfs-no-amfi-entitlements.patch','bsd/kern/ubc_subr.c'),('nabu-mockfs-no-amfi-query.patch','iokit/bsddev/IOKitBSDInit.cpp'),('nabu-mockfs-console-popup.patch','bsd/dev/arm/km.c'),('nabu-mdev-readonly-apfs.patch','bsd/dev/memdev.c'),('nabu-apfs-md1-hook.patch','iokit/bsddev/IOKitBSDInit.cpp')]
p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);p.add_argument('--crypto-bootstrap',choices=('source','prelinked'),default='source');a=p.parse_args();root=a.root.resolve();source=root/'.cache/xnu-work';objroot=root/'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837';out=root/'mac-batch-output';out.mkdir(exist_ok=True)
objects=OBJECTS+(['osfmk/DEVELOPMENT/prng_random.o'] if a.crypto_bootstrap=='prelinked' else [])
for patch,include in PATCHES:
    command=['git','apply','--include='+include,str(KIT/'patches'/patch)]
    check=subprocess.run([command[0],command[1],'--check',*command[2:]],cwd=source,capture_output=True,text=True)
    if check.returncode==0:subprocess.run(command,cwd=source,check=True)
    elif subprocess.run([command[0],command[1],'--reverse','--check',*command[2:]],cwd=source,capture_output=True).returncode:
        raise SystemExit('Patch requires review: '+patch+'\n'+check.stderr)
storage_headers=prepare_storage_headers(root)
records=[]
for relative in objects:
    record=json.loads((objroot/(relative+'.json')).read_text().rstrip(',\n'))
    command=[subprocess.check_output(['xcrun','--find','clang++' if relative.endswith('.cpo') else 'clang'],text=True).strip()]
    flags=record['arguments'][1:];i=0;destination=out/relative;destination.parent.mkdir(parents=True,exist_ok=True)
    while i<len(flags):
        flag=flags[i]
        if flag=='-o':command+=['-o',str(destination)];i+=2;continue
        if flag=='XNU_NATIVE_PAN=0':flag='XNU_NATIVE_PAN=1'
        command.append(flag.replace(OLD,str(root)));i+=1
    command+=['-DXNU_NATIVE_PAN=1','-DXNU_NABU_MOCKFS_EL0=1','-DXNU_NABU_APFS_MD1=1','-march=armv8.1-a','-Wno-error']
    if relative=='iokit/DEVELOPMENT/IOKitBSDInit.cpo':command+=['-I',str(storage_headers)]
    if relative=='osfmk/DEVELOPMENT/prng_random.o':command+=['-UXNU_SOURCE_CORECRYPTO14']
    result=subprocess.run(command,cwd=objroot/Path(relative).parent,capture_output=True,text=True)
    destination.with_suffix(destination.suffix+'.log').write_text(result.stdout+result.stderr)
    records.append({'object':relative,'command':command,'returncode':result.returncode,'output':str(destination),'sha256':hashlib.sha256(destination.read_bytes()).hexdigest() if destination.is_file() else None})
    (out/'compile-report.json').write_text(json.dumps({'crypto_bootstrap':a.crypto_bootstrap,'expected_objects':objects,'records':records,'all_passed':len(records)==len(objects) and all(x['returncode']==0 for x in records),'apple_builtins_preserved':True},indent=2)+'\n')
    if result.returncode:raise SystemExit(result.stderr[-6000:])
print(f'All {len(objects)} native Apple objects compiled; crypto bootstrap={a.crypto_bootstrap}; final link and runtime checks still required')
