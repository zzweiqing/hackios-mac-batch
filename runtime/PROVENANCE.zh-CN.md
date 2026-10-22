libcompiler_runtime_kernel.a 溯源
================================

构建来源:LLVM compiler-rt 源码,固定 llvmorg-17.0.6(commit
6009708b4367171ccdbf4b5905cb6a803753fe18),取 LLVM 17 的 6 个 Darwin kernel
profile 组件(InstrProfilingBuffer/InstrProfiling/Internal 等,KERNEL_USE 配置)
加 Darwin ARM64 栈探测(__chkstk_darwin,LLVM review D40857 原始补丁,w9 字节数、
逐页真实访存探测),由本项目在 WSL Debian Clang 21.1.8 下离线构建。

- 许可:LLVM Apache-2.0(含 LLVM 例外)开源衍生,非 Apple 专有材料。
- ABI:profile buffer 函数为 6/7 参,与 XNU 10063 源码声明一致;不能用当前
  SDK libcc_kext.a 替代(LLVM21 起 get-size 扩展为 12 参,同名不同 ABI)。
- 验证:与 WSL 重链验证链(nabu-mockfs-pan1-console-probe 最终内核)链接的
  是同一份归档;该闭包 1010 对象 + 本 runtime 链接无未定义符号。
- 完整源码、补丁与构建脚本:offline-audit-20261022/build_compiler_runtime.py
  与 build-toolchain/compiler-rt-sources-llvm17.tar.gz(项目内保留)。
