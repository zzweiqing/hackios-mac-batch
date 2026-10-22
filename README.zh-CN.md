# nabu / UniXNU XNU 移植——Mac 批处理公共仓库

本仓库是 [hackios](.) 项目"确需 Apple 工具链"批处理的**公共部分**:自有脚本、
补丁、审查记录与 GitHub Actions CI。用于在 GitHub 托管的 macOS runner 上,
用真实 Apple Clang 重编 XNU 受影响对象并全核重链(XNU 10063.141.1 / nabu 平板移植实验)。

**本仓库不含、也永不提交 Apple 专有材料**(iPhoneOS SDK 头/对象备份、CoreCrypto
静态库、恢复的 Apple 头文件、由它们链接出的内核二进制)。这些输入保存在一个
**私有仓库**的 release asset 中;CI 运行时用 token 拉取,构建产物也传回私有仓库。
公共侧只留下摘要(工具版本、逐对象返回码、内核尺寸/SHA-256)。

## CI 做什么

手动触发(workflow_dispatch)的 `mac-batch captured build`:

1. **preflight**:记录 runner 的 Xcode/SDK/Clang/ld 版本,校验批处理输入完整性。
2. **build-captured**(默认):全新空工作区恢复归档 → 应用补丁 → 用捕获的原始
   Apple 编译命令重编 11 个对象(ubc_subr、IOKitBSDInit.cpo、7 个 PAN 对象、
   km.o 含 kernel_tests.o)→ `.LDFLAGS` 全核重链 → CoreCrypto FIPS HMAC 封印 →
   `nm -u` 无未定义符号检查。
3. 产物:公共 artifact `ci-summary-<run>`;完整对象/日志/新内核在私有仓库
   release `ci-<run_id>`。

不伪造 Apple 专用 builtin(`__builtin_xnu_type_summary` 等);工具链不兼容时
首错即停并保存现场。

## 重要边界

- **CI 编译成功 ≠ 验收通过**:任何新内核必须重跑本项目严格 QEMU/EL0 判据
  (initproc、EL0 checkpoint/PSTATE、getpid/sysctlbyname、4 KiB 用户页、负例、
  可见文字)后才能进入发布包。见 `MAC_REQUIRED.zh-CN.md` 的完成证据要求。
- `--build-clean`(全量一致干净构建)与 `--archive-corecrypto`(CoreCrypto 固定
  commit 源归档)需要用户另行提供的完整私有资源,不在本 workflow 内。
- 捕获命令来自 Xcode 15.4 beta/Apple Clang 15;runner 上是更新的 Xcode。
  版本差异按 fail-closed 原则处理:编译失败保留首错,成功则仍须重验证。

## 目录

| 路径 | 内容 |
| --- | --- |
| `run_mac_batch.sh` | 批处理入口(preflight / build-captured / archive-corecrypto / build-clean) |
| `prepare_mac_workspace.py` 等 5 个脚本 | 工作区恢复、捕获命令重编、链接、干净构建准备、输入检查 |
| `patches/` | 10 个源补丁(PAN、4K 用户 ABI、mockfs 无 AMFI、console popup 等) |
| `MAC_REQUIRED.zh-CN.md` | 什么真正需要 Mac、批处理内容、完成证据要求 |
| `review/` | 2026-10-22 对批处理包的独立审查记录 |
| `validation*.json`、`corecrypto-required-provenance.json` | 本地验证与来源溯源元数据 |

本地无 `inputs/`、`capture/`(私有材料)时,`check_batch_inputs.py` 会正确地
报告 `captured_batch_complete=false`——这是设计行为,不是缺陷。
