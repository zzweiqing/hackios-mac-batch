# 下次新授权 Mac 一次性批处理

整理日期：2026-10-22（Asia/Shanghai）。本包未连接历史Mac、未续费或购买环境、未执行任何平板操作。只有用户重新开启并明确授权新的Mac环境后才执行。

当前WSL已交付的PAN1 + mockfs/EL0 + O_POPUP控制台候选不依赖本包才能复现：它用完整备份对象、真实源编ubc/PAN/console、Linux cctools ld64、真实compiler-rt、有限无AMFI拒绝guard和probe生成；完整新root复现已通过。证据入口为`mac_build/research/nabu-agent/offline-audit-20261022/pan-build-audit.zh-CN.md`及`final-console-probe-reproduce-comparison.json`。实机依然待用户验收，本包不声称硬件或iPadOS成功。

## 真正需要 Mac 的事项

| 工作 | 为何延后到 Mac | 当前状态/边界 |
| --- | --- | --- |
| 完整`IOKitBSDInit.cpp`源编无AMFI entitlement拒绝守卫 | Apple Clang真实`__builtin_xnu_type_summary`/`__builtin_xnu_type_signature`被IOLib/OSData/OSValueObject/OSAllocation模板使用，Linux21不具备 | 源patch已保存；当前候选用经独立机器码验证的有限入口guard，缺provider时拒绝而非授予 |
| 全部配置一致的干净XNU构建 | 本轮有Apple历史对象 + Linux重编对象，PAN0的kernel_POST表只是少一个未运行PAN测试。完全一致的Apple原生构建能消除这些技术债 | 本次核心修改闭包已通过源编/链接/QEMU；全量Apple一致构建尚未执行，不能标完成 |
| 真实CoreCrypto固定版本全源归档及重建 | 旧69MB只带静态库/objects，235条include symlink指向缺失refer源；原构建脚本使用xcrun/plutil | 固定`ONLYA/corecrypto-2023` commit `11fba65b12d8830630e248dfa8344caf8b065f26`；529源C文件；该snapshot未认证为Apple发布包，不能偷偷换另版本补齐 |
| 原生Apple runtime与编译SDK闭包归档 | 旧备份缺Clang自动runtime archive，只有链接头而非全Xcode SDK | 当前已用真实LLVM17 kernel profile/官方Darwin probe补齐；下次归档Apple compiler runtime、资源头、准确SDK/工具版本便于一致重链 |

这几项是待新资源的清理与增强，不应让已通过的本地离线候选变成“建议而未交付”。真正缺少不可替代source/Apple工具的项保持明确待办，任何Mac新产物重新跑当前严格QEMU与EL0后才进入发布包。

## 批处理包内容

`run_mac_batch.sh`只读preflight默认不构建；传`--build-captured`后在**新的私有派生工作区**恢复归档、应用必要patch并用Mac Apple compiler重编受影响9个对象，再全核重链；`--build-clean`做全量一致源码配置构建，必须额外明确提供配套完整UniXNU源码资源目录；`--archive-corecrypto`只读归档用户提供的准确固定Git源。不接受网络自动clone，也不含连接凭据。

`prepare_mac_workspace.py`恢复本地XNU固定归档、对象SDK归档与捕获overlay，拒绝非空目标目录。`compile_captured_mac.py`保留Apple捕获编译参数，不伪造typed builtin、不删原Apple vendor参数；新toolchain不兼容时记录首错并停止。`link_captured_mac.py`采用原.LDFLAGS和真实源provider闭包，使用xcrun clang++自动加入Apple compiler runtime；保留POST HMAC封印。

本批只准备和做宿主脚本检查，**未实际在Mac执行**。不能因为shell语法或Python静态检查通过，就写成Apple源编已成功。

## 新 Mac 开启后最短顺序

1. 用户把包复制到新授权Mac本地目录。先本地执行`bash run_mac_batch.sh --preflight`，保存Xcode/SDK/compiler/builtin/source完整性报告；脚本不连接旧机器。
2. 提供准确CoreCrypto Git源时执行`bash run_mac_batch.sh --archive-corecrypto /absolute/private/corecrypto-2023`；固定commit与干净工作树检查不符就失败，不能改用其他版本。缺源时仍可重编本次XNU对象，但不能宣称CoreCrypto全源闭包完成。
3. 执行`bash run_mac_batch.sh --build-captured /absolute/new/private/work`，批量重编ubc、IOKit、PAN7对象、console并重新链接。入口guard不再patch IOKit，因为真实源guard已经编入；probe仍需当前脚本和HMAC。
4. 全量一致清理留到同一次租期：`bash run_mac_batch.sh --build-clean /absolute/new/private/clean /absolute/private/full-unixnu-resource-root`。preflight检查相同fixed源/archives都齐全后才跑，缺资源保存报告而停止，不联网静默替代。
5. 下载完整命令、日志、对象、候选、SDK/compiler runtime/source归档；回本地对新Mac候选重跑严格QEMU/EL0/PAN/console和原始nabu ADT合同，验证通过才更新离线发布清单。

Mac也不能代替实机内存图、MMIO、GIC/计时器/GOP事实取证。重新开Mac无需重做Darling PackageKit旧路线，不向参考库推送、不公开发布。

## 完成证据要求

对象成功须有完整编译命令、工具版本、source patch和exit0；链接成功须无undefined、Mach-O/boot ABI、FIPS HMAC校验；运行成功须当前严格QEMU的initproc、fixture EL0 checkpoint、getpid/sysctlbyname/4K页、负例及用户写console实际结果。纯Mac文件生成不能称EL0执行。CoreCrypto补源须准确commit、干净树、完整归档可读取、源/头235symlink关系、529源编结果及自检运行。
