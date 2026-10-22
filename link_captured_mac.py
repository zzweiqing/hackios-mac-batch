#!/usr/bin/env python3
"""Link captured source archives and fresh native Apple objects; no publishing."""
import argparse,json,shlex,subprocess
from pathlib import Path
KIT=Path(__file__).resolve().parent
OLD='/Users/chuzu/Desktop/UniXNU-build/unixnu-mac-offline-20261021/work/UniXNU'
p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);a=p.parse_args();root=a.root.resolve();objroot=root/'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837';out=root/'mac-batch-output'
record=json.loads((out/'compile-report.json').read_text())
if not record.get('all_passed'):raise SystemExit('Compile batch incomplete')
replace={r['object']:r['output'] for r in record['records']}
listed=[]
for line in (objroot/'link.filelist').read_text().splitlines():
    mapped=Path(line.replace(OLD,str(root)));relative=str(mapped.relative_to(objroot));listed.append(replace.get(relative,str(mapped)))
listed += [str(objroot/x) for x in ('lastkerneldataconst.o','lastkernelconstructor.o','nonlto.o','version.o')]
if any(not Path(x).is_file() for x in listed):raise SystemExit('Missing real object')
filelist=out/'link.filelist';filelist.write_text('\n'.join(listed)+'\n')
flags=shlex.split((objroot/'.LDFLAGS').read_text().strip('\0\r\n'))[1:]
# -lcc_kext is dropped on purpose: current SDK libcc_kext.a implements the LLVM21
# 12-param llvm_profile buffer ABI, while XNU 10063 source declares the 6/7-param
# one; linking it would resolve by name but mismatch at runtime. The project-built
# LLVM 17 kernel runtime below carries the matching real implementations and is the
# same archive used by the verified WSL relink of this exact object closure.
flags=[f.replace(OLD,str(root)) for f in flags if f!='-lcc_kext']
command=['xcrun','--sdk','iphoneos','clang++',*flags,'-filelist',str(filelist),
         str(root/'.cache/fakeroot/usr/local/lib/kernel/libfirehose_kernel.a'),
         str(root/'build/corecrypto-2023/libcorecrypto_kernel_noasm-namespaced.a')]
runtime=KIT/'runtime/libcompiler_runtime_kernel.a'
if not runtime.is_file():raise SystemExit('Missing project LLVM17 kernel compiler runtime (runtime/)')
command.append(str(runtime))
for archive in ('armdt-platform/libArmDTPlatform.a','armcpu/libArmCpu.a','libpthread-kernel/libpthread_kernel.a','mockfs-fixture/libmockfs_fixture.a'):
    path=root/'build'/archive
    if not path.is_file():raise SystemExit('Missing exact source archive '+archive)
    command.append('-Wl,-force_load,'+str(path))
kernel=out/'nabu-mockfs-native-apple.macho'
if kernel.exists():raise SystemExit('Refuse to overwrite existing kernel')
command+=['-o',str(kernel)]
result=subprocess.run(command,capture_output=True,text=True)
(out/'link.log').write_text(result.stdout+result.stderr)
(out/'link.json').write_text(json.dumps({'command':command,'returncode':result.returncode,'kernel':str(kernel),'hardware_verified':False,'runtime_verified':False},indent=2)+'\n')
if result.returncode:raise SystemExit(result.stderr[-6000:])
subprocess.run(['python3',str(root/'scripts/seal-source-crypto-kernel.py'),str(kernel)],check=True)
undefined=subprocess.check_output(['xcrun','nm','-u',str(kernel)],text=True)
(out/'undefined.txt').write_text(undefined)
if undefined.strip():raise SystemExit('Kernel has undefined symbols')
print(kernel)
