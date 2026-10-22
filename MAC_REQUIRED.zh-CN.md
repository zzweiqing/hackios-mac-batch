# Apple 工具链任务：GitHub Actions

需要 macOS/Xcode 的编译统一在 GitHub Actions 执行，不再使用已到期租赁 Mac。
主项目的当前操作说明是 `docs/BUILD.zh-CN.md`；公共投影可直接手动运行本仓库工作流。

## 当前已支持

- `preflight-only`：检查 runner 的 Xcode、iPhoneOS SDK、Apple Clang/ld 与私有输入。
- `build-captured`：恢复固定输入/捕获树，重编声明的 11 个对象，然后全核重链、FIPS HMAC 封印及 undefined 检查。
- 私有输入与完整编译产物在私有 release；公共侧只保留源脚本/补丁及摘要。

捕获编译命令不能通过删掉 Apple 专有 builtin 参数、伪造 builtin 或放宽接口来“修成通过”。
更换 toolchain 不兼容时保存首错并修正真正的不兼容原因。

## 尚未闭环

- 任意新增对象不会自动加入当前 11 对象任务，需扩展编译清单并绑定准确输入。
- 全量一致 clean XNU build 还缺完整资源闭包，当前 workflow 不支持它。
- CoreCrypto 固定源全量归档/重建需要准确来源；只有旧静态库/对象不能称全源具备。
- 本地 fakeroot/对象备份不等价于完整 Xcode SDK。Linux compiler-rt 是明确记录的开源构建依赖。

## 完成证据

每次记录实际 Actions run ID、head SHA、输入 release/asset、Xcode/SDK/编译器版本、精确编译对象和返回码。
链接必须无 undefined，并检查 Mach-O/boot ABI 与 FIPS HMAC；这些都只属于编译链成功。
进入候选前继续验证严格 QEMU EL0 正负例、真实 syscall 结果、4K 页与可见输出。
硬件成功仅按实际 nabu 观察记录，不能由 Mac 编译、QEMU或同名自有 launchd 推断。
