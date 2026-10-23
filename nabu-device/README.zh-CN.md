# nabu-device（UniXNU 设备层：Xiaomi Pad 5 / SM8150）

本目录是 UniXNU 构建驱动的 nabu 设备仓库层，随 hackios-mac-batch 仓库一起分发。
目标输入：用户提供的本地 `iPad_10.2_17.7_21H16_Restore.ipsw`（iPad7,11/12，j171ap，
17.7 / 21H16）；CI 通过 `UNIXNU_IPSW` 使用私有仓库中的小成员子集容器，不下载整包。

## 状态（2026-10-24）

- `nabu_bootstrap_defconfig`：首个从源码 bootstrap pass（corecrypto14 / pthread /
  ArmDTPlatform / ArmCpu，无归档构建器）。board.toml 为配套最小形态。
- `nabu_defconfig`：完整目标配置（存储 + 原始用户态链），待 bootstrap 通过后
  连同归档构建器清单、AMFI `early_security_init`（21H16 已审计为
  `0xfffffff005b70ae0`）与 package 组件一起启用。
- `scripts/build-arm-driver.py`：逐字复制自 UniXNU-sheng `251b291a`（BSD-2）。
- 完整依赖与输入清单、21H16 ABI 审计记录见 hackios 主仓库
  `project_audit/unixnu-nabu-port-20261023/` 与 `.../unixnu-nabu-port-20261024/`。

## 许可

`LICENSE` 为上游 UniXNU 的 BSD-2-Clause-Patent 文本；`build-arm-driver.py`
来自 UniXNU-sheng，同许可。
