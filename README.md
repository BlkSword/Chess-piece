# Chess-piece：Advanced Shellcode Packer & Loader Generator

**Chess-piece** 是一个面向安全研究的 Shellcode 打包与加载器生成工具。它旨在将原始 Shellcode、PE 文件或命令转换为具备隐蔽性的加载器，支持现代化的反分析技术与多层加密。

## 核心特性

###  Rust Stub (默认/推荐)
新版默认使用基于 Rust 编写的高级 Stub 加载器，提供更强的隐蔽性与稳定性：
-   **Indirect Syscalls**: 动态解析 SSN 并通过汇编直接调用内核函数，绕过用户层 API Hooking (AV/EDR)。
-   **强加密**: 采用 AES-256-GCM 加密 + Zstd 压缩，确保 Payload 安全与体积优化。
-   **多负载支持**:
    -   **Shellcode**: 支持本地注入与远程进程注入。
    -   **PE 文件**: 支持打包 EXE 文件，运行时释放并执行。
    -   **Command**: 支持嵌入 CMD 命令并隐蔽执行。
-   **反分析**: 内置多态代码混淆与简单的反调试/反沙箱逻辑。
-   **子系统切换**: 支持通过 `--debug` 参数灵活切换 GUI (无窗口) 与 Console (黑框) 模式。

###  Legacy C Templates (可选)
保留了基于 C 语言模板的生成方式，适合需要高度定制底层技术的场景：
-   **多种加载技术**: `callback` (EnumSystemLocalesA), `fiber` (纤程), `earlybird` (APC 注入)。
-   **加密算法**: 支持 AES, RC4, XOR。
-   **混淆**: UUID 混淆 (将 Shellcode 编码为 UUID 字符串)。
-   **Un-hooking**: 支持运行时恢复 `ntdll.dll`。

---

##  安装与构建

需要安装 [Rust Toolchain](https://rustup.rs/)。

```bash
# 克隆项目
git clone https://github.com/Blksword/Chess-piece.git
cd Chess-piece

# 构建 Release 版本 (推荐)
cargo build --release
```

构建完成后，可执行文件位于 `target/release/packer.exe`。
> 注意：首次运行打包时，packer 会自动寻找同目录下的 `stub.exe`。请确保同时构建了 stub：`cargo build -p stub --release`。

---

##  使用指南

### 基础用法

**1. 打包 Shellcode (推荐)**
```bash
# 将 raw shellcode 打包为 output.exe
packer.exe --input shellcode.bin --output payload
```

**2. 打包 CMD 命令**
```bash
# 生成一个执行 "whoami" 的 exe，默认无窗口
packer.exe --cmd "whoami > C:\Windows\Temp\out.txt" --output cmd_runner
```

**3. 打包 PE 文件**
```bash
# 将 mimikatz.exe 打包
packer.exe --input tools/mimikatz.exe --output mimi_packed
```

**4. 调试模式 (显示控制台)**
```bash
# 增加 --debug 参数，生成的 exe 运行时会显示黑框，便于查看输出或调试
packer.exe --input shellcode.bin --output payload_debug --debug
```

### 命令行参数

| 参数 | 缩写 | 描述 | 默认值 |
|---|---|---|---|
| `--input` | `-i` | 输入文件路径 (Shellcode 或 PE)。 | - |
| `--cmd` | | 直接嵌入的 CMD 命令字符串。 | - |
| `--output` | `-o` | 输出文件名 (不含扩展名)。 | `Program` |
| `--use-stub` | | 是否使用 Rust Stub 模式。 | `true` (默认) |
| `--debug` | | **Rust Stub**: 开启控制台窗口 (Console Subsystem)。<br>**Legacy**: 打印生成的 C 源码。 | `false` |
| `--enc` | | (Legacy) 加密算法: `aes`, `rc4`, `xor`。 | `aes` |
| `--loading` | | (Legacy) 加密载荷加载方式: `callback`, `fiber`, `earlybird`。 | `callback` |
| `--unhook` | | (Legacy) 启用常规 WinAPI (设为 false 则尝试间接系统调用)。 | `true` |

---

##  技术细节 (Rust Stub)

当使用默认的 `--use-stub` 模式时，Packer 会执行以下流程：

1.  **Payload 处理**:
    -   输入数据 (Shellcode/PE/Cmd) 首先经过 **Zstd** 压缩。
    -   使用随机密钥进行 **AES-256-GCM** 加密。
2.  **Stub 生成**:
    -   读取预编译的 `stub.exe`。
    -   根据 `--debug` 参数修改 Stub 的 PE Subsystem (GUI/Console)。
    -   将加密后的 Payload、密钥、Nonce 追加到 Stub 尾部。
3.  **运行时行为**:
    -   Stub 启动后通过多态代码干扰静态分析。
    -   解析自身读取 Payload 并解密。
    -   **Shellcode**: 使用 Indirect Syscalls (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory`) 分配内存并写入，最后通过 `NtCreateThreadEx` 执行。
    -   **PE**: 释放到临时目录并隐藏执行。
    -   **CMD**: 调用 `cmd.exe` 或直接执行命令。

##  免责声明

本工具仅供安全研究与授权测试使用。请勿用于非法用途。开发者不对因使用本工具造成的任何损害承担责任。
