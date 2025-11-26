# Chess-piece 加壳器（CLI）

## 构建
- `cargo build -p packer -p stub --release`

## 用法（Windows）
- 文件模式：
  - `target\release\packer.exe <输入EXE路径> [--out <输出壳EXE>]`
- 命令模式：
  - `target\release\packer.exe --cmd <命令路径> [--out <输出壳EXE>]`
- Shellcode 模式：
  - `target\release\packer.exe --sc <shellcode.bin|.c|.py> [--out <输出壳EXE>] [--remote <进程路径>]`
  - `.bin`：作为原始shellcode内存运行（使用直接系统调用）；`.py`：打包为内置脚本，运行 `pythonw -c <脚本>` 不落地；`.c`：编译为EXE后加壳（等价源码模式）
- 源码模式（编译后加壳）：
  - `target\release\packer.exe --src <源码文件> --lang <rust|c> [--out <输出壳EXE>]`

当未指定 `--out` 时，默认输出为 `<输入文件名>_packed.exe`。

## 运行与控制
- 壳 Stub 采用 Windows 子系统，双击不显示控制台窗口。
- 内测跳过检测：`RS_PACK_SKIP_ANTI=1`
- 启用 BIOS 注册表检测：`RS_PACK_VM_BIOS=1`

## 特性概览
- **核心防护**
  - **加密与压缩**：采用 AES-256-GCM 高强度加密 payload，结合 Zstd 压缩算法减小体积。
  - **反调试**：集成 `IsDebuggerPresent`、`CheckRemoteDebuggerPresent` 等多重检测机制。
  - **反虚拟机**：默认检测 CPUID 超管位；支持可选的 BIOS/注册表指纹检测 (`RS_PACK_VM_BIOS=1`)。

- **隐蔽执行 (Stealth)**
  - **Direct Syscalls**：通过动态解析 SSN 直接调用内核服务，完全绕过用户态 API 监控 (EDR Hooks)。
  - **Unhooking**：运行时自动重载 `ntdll.dll` 代码段，清除安全软件植入的 Inline Hooks。
  - **多态加载 (Polyglot Loading)**：Shellcode 执行方式随机化，降低行为特征熵值：
    - **Fiber**：利用纤程上下文切换执行。
    - **Callback**：通过系统回调 (`EnumSystemLocalesA`) 隐蔽触发。
    - **APC / EarlyBird**：利用异步过程调用队列注入。
