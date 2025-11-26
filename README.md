# Chess-piece 加壳器

## 概述
- 基于 Rust 的 Windows EXE 加壳器，内置 AES‑256‑GCM 加密与 Zstd 压缩，具备基础反调试、反虚拟机检测。支持两种载荷模式：文件模式与命令模式。
- 命令模式可直接执行系统命令（如 `C:\Windows\System32\calc.exe`），避免在用户目录下落地临时 EXE。

## 构建
- `cargo build -p packer -p stub --release`

## 使用
- 文件模式（将输入 EXE 加密封装到壳文件）：
  - `target\release\packer.exe <输入EXE> <输出壳EXE>`
  - 例：`target\release\packer.exe target\release\stub.exe packed.exe`
- 命令模式（推荐用于内测与演示，避免落地）：
  - `target\release\packer.exe --cmd <命令路径> <输出壳EXE>`
  - 例：`target\release\packer.exe --cmd C:\Windows\System32\calc.exe packed_calc_cmd.exe`

## 运行
- 直接双击壳文件运行，壳 Stub 采用 Windows 子系统，不显示控制台黑框。
- 在内测或沙盒验证时，可设置环境变量跳过检测：
  - PowerShell: `$env:RS_PACK_SKIP_ANTI='1'; ./packed_calc_cmd.exe`

## 反检测
- 反调试：`IsDebuggerPresent`、`CheckRemoteDebuggerPresent` 聚合判断。
- 反虚拟机：默认仅检查 CPUID 超管位；如需启用更激进的 BIOS 注册表检测，设置环境变量：
  - `RS_PACK_VM_BIOS=1`

## 载荷格式
- `marker 'RSPKv1\0'` + `u32 key_len(=32)` + `key[32]` + `u32 nonce_len(=12)` + `nonce[12]` + `u64 ct_len` + `ciphertext`
- 先 Zstd 压缩，再 AES‑256‑GCM 加密，提升对抗静态分析能力并具备完整性校验。

## 注意事项
- 本项目用于企业自有软件的保护与内测演示，不应用于规避安全产品的检测或其他不当用途。
- 命令模式建议优先使用系统受信任组件（如计算器）进行演示；文件模式可能在部分沙盒中被标记为在 `%TEMP%` 落地 EXE。

## 后续增强
- 内存执行（不落地）：反射式 PE 映射或子进程注入。
- 更丰富反检测：时间扰动、硬件断点、驱动与特征进程枚举、IAT/EAT 校验等。
- 密钥管理与混淆：密钥分裂与运行期合成、控制流平坦化、字符串与常量加密。
