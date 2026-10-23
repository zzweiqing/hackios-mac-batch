#!/usr/bin/env python3
"""Link captured source archives and fresh native Apple objects; no publishing."""
import argparse,hashlib,json,shlex,subprocess
from pathlib import Path
KIT=Path(__file__).resolve().parent
OLD='/Users/chuzu/Desktop/UniXNU-build/unixnu-mac-offline-20261021/work/UniXNU'
p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);a=p.parse_args();root=a.root.resolve();objroot=root/'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837';out=root/'mac-batch-output'
record=json.loads((out/'compile-report.json').read_text())
if not record.get('all_passed'):raise SystemExit('Compile batch incomplete')
mode=record.get('crypto_bootstrap','source')
if mode not in ('source','prelinked'):raise SystemExit('Unknown crypto bootstrap mode')
expected=record.get('expected_objects')
expected_count=(13 if mode=='prelinked' else 12)
if expected is not None and ([r['object'] for r in record['records']]!=expected or len(expected)!=expected_count):raise SystemExit('Compile object closure incomplete')
for r in record['records']:
    if r['returncode'] or (r.get('sha256') and hashlib.sha256(Path(r['output']).read_bytes()).hexdigest()!=r['sha256']):raise SystemExit('Compiled object failed or changed')
if mode=='prelinked':
    prng=[r for r in record['records'] if r['object']=='osfmk/DEVELOPMENT/prng_random.o']
    if len(prng)!=1 or prng[0]['command'][-1]!='-UXNU_SOURCE_CORECRYPTO14':raise SystemExit('Prelinked PRNG compile selection absent')
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
(out/'link.json').write_text(json.dumps({'command':command,'returncode':result.returncode,'kernel':str(kernel),'crypto_bootstrap':mode,'finalization_passed':False,'hardware_verified':False,'runtime_verified':False},indent=2)+'\n')
if result.returncode:raise SystemExit(result.stderr[-6000:])
if mode=='source':
    subprocess.run(['python3',str(root/'scripts/seal-source-crypto-kernel.py'),str(kernel)],check=True)
else:
    subprocess.run(['python3',str(KIT/'seal_captured_kernel.py'),str(kernel)],check=True)
undefined=subprocess.check_output(['xcrun','nm','-u',str(kernel)],text=True)
(out/'undefined.txt').write_text(undefined)
if undefined.strip():raise SystemExit('Kernel has undefined symbols')
symbols=subprocess.check_output(['xcrun','nm','-a',str(kernel)],text=True)
names={line.split()[-1] for line in symbols.splitlines() if line.split()}
required={'_register_and_init_prng','_prng_ready','_kalloc_sparse_prelink_index_version'}
if not required.issubset(names):raise SystemExit('Required PRNG/prelink symbols missing')
if mode=='prelinked' and names & {'_source_corecrypto14_bootstrap','_source_corecrypto14_status'}:raise SystemExit('Source provider startup still linked')
linked=json.loads((out/'link.json').read_text())
linked.update(finalization_passed=True,kernel_sha256=hashlib.sha256(kernel.read_bytes()).hexdigest(),undefined_symbol_count=0,required_symbols_present=True,source_bootstrap_absent=mode=='prelinked',objects=[r['object'] for r in record['records']])
(out/'link.json').write_text(json.dumps(linked,indent=2)+'\n')
print(kernel)
