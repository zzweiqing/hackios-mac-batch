#!/usr/bin/env bash
# 恢复后穷尽检查:11 个对象捕获命令中所有 OLD 前缀参数(文件)在恢复树中存在。
set -e
R=/tmp/hackios-mac-batch-restore-20261022b
B=$(cd -- "$(dirname -- "$0")/.." && pwd)
rm -rf "$R"
mkdir -p "$R"; rmdir "$R"
cd "$B"
python3 prepare_mac_workspace.py "$R" >/dev/null
echo "RESTORE_EXIT=$?"
test -f "$R/build/xnu/ios-obj/san/kasan-blacklist-arm64" && echo "kasan-blacklist: OK" || echo "kasan-blacklist: MISS"
python3 - "$R" <<'PY'
import json, sys, os
root = sys.argv[1]
OBJROOT = root + '/build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837'
OLD = '/Users/chuzu/Desktop/UniXNU-build/unixnu-mac-offline-20261021/work/UniXNU'
objs = ['bsd/DEVELOPMENT/ubc_subr.o','iokit/DEVELOPMENT/IOKitBSDInit.cpo','osfmk/DEVELOPMENT/copyio.o',
        'osfmk/DEVELOPMENT/arm_init.o','osfmk/DEVELOPMENT/pcb.o','osfmk/DEVELOPMENT/pmap.o',
        'osfmk/DEVELOPMENT/platform_tests.o','osfmk/DEVELOPMENT/kernel_tests.o','osfmk/DEVELOPMENT/kdp_vm.o',
        'bsd/DEVELOPMENT/bsd_tests.o','bsd/DEVELOPMENT/km.o']
missing = {}
for o in objs:
    rec = json.loads(open(OBJROOT + '/' + o + '.json').read().rstrip(',\n'))
    for a in rec['arguments']:
        if a.startswith(OLD):
            p = root + a[len(OLD):]
            if not os.path.exists(p):
                missing.setdefault(o, []).append(p)
if missing:
    print('MISSING REFS:')
    for o, paths in missing.items():
        print(' ', o)
        for p in paths[:5]:
            print('   ', p)
else:
    print('ALL_OLD_PREFIX_REFS_EXIST=1')
PY
