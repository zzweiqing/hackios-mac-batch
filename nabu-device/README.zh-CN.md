# nabu G0 源码构建输入

本目录只描述 UniXNU 固定源码与 iPadOS 17.7 / 21H16 输入下的 G0 构建候选。
它编译并预链 XNU、原始 CoreCrypto 注册/APFS 依赖闭包及平台/pthread 归档；不包含系统卷、
Apple launchd、UFS 真机访问、显示或可启动 iPadOS 包。

`nabu_bootstrap_defconfig` 有意关闭 BootProgress、mockfs、物理存储、AES、VirtIO 和显示。
构建成功只证明源码候选通过链接和静态预链；仍须用候选绑定的 QEMU 回归，才能确认所选
XNU/原始 crypto 检查点。它不是 Apple 用户态启动证据。

根目录 `board.toml` 固定 21H16 kernelcache、slide 与 APFS root 闭包；
`scripts/build-nabu-platform.py` 从当前 XNU 编译记录产生 ArmDTPlatform 和 ArmCpu 归档。
构建身份、日志、候选及有限文件集保存在私有产物；公开 artifact 仅含有界摘要。

独立 `nabu_ufs_passive_defconfig` 在这个闭包增加 SM8150 NativeUfs 编译/父类绑定，
但构建时固定阻止 `start()` 的所有硬件分派，不能作为系统盘驱动使用。
它与 QEMU 原用户态开发分离；模式、共享补丁副本与 ABI 验收见根目录 `docs/BUILD.zh-CN.md`。
