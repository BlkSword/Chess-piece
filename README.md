# Chess-piece

**Chess-piece** 是一个面向安全研究的 Shellcode 打包与加载器生成工具。它采用 "Packer + Stub" 的架构，将原始 Shellcode、PE 文件或命令加密打包，并生成具备反分析能力的加载器 (Stub)。


---

##  项目结构

本项目包含三个核心 Crates：

1.  **`crates/packer`**: 命令行打包工具。负责读取 payload、压缩 (Zstd)、加密 (AES-256-GCM)、混淆，并将处理后的数据注入到 `stub.exe` 中。
2.  **`crates/stub`**: 默认的 Rust 加载器模板。编译后生成 `stub.exe`。它包含解密逻辑、反沙箱、反调试以及通过 Indirect Syscalls 执行 payload 的核心代码。
3.  **`crates/anti`**: 为 `stub` 提供反分析功能的库。

---

## 快速开始

### 1. 构建项目

在项目根目录下运行以下命令，这将同时构建 Packer 和 Stub：

```bash
cargo build --release
```

构建完成后，生成的文件位于 `target/release/` 目录：
- `packer.exe`: 打包工具
- `stub.exe`: 也就是加载器模板 (Packer 会自动寻找并使用它)

### 2. 使用示例

**场景：将 `calc.bin` (Shellcode) 打包为 `ml111.exe`**

```powershell
target\release\packer.exe --input calc.bin --output ml111
```

执行后，`ml111.exe` 即为最终生成的免杀加载器。

---

## 详细功能与用法

### 核心特性 (Rust Stub)

默认模式 (`--use-stub`) 下，Packer 使用预编译的 Rust Stub，具备以下特性：

-   **Indirect Syscalls**: 动态解析 SSN，通过汇编直接调用内核函数，绕过用户层 API Hooking。
-   **高强度加密**: AES-256-GCM 加密 + Zstd 压缩。
-   **多负载支持**:
    -   **Shellcode**: 本地注入 / 远程进程注入。
    -   **PE 文件**: 支持反射式加载 EXE。
    -   **Command**: 隐蔽执行 CMD 命令。
-   **反分析**: 包含反调试、反沙箱、以及伪造数字签名。
-   **子系统切换**: 自动根据 `--debug` 参数切换 GUI (无窗口) 或 Console (黑框) 模式。

### 命令行参数

```bash
packer.exe [OPTIONS] --output <OUTPUT>
```

| 参数 | 描述 | 示例 |
|---|---|---|
| `-i, --input <PATH>` | 输入文件路径 (Shellcode 或 PE 文件) | `-i shellcode.bin` |
| `--cmd <CMD>` | 直接打包一条 CMD 命令 | `--cmd "whoami > out.txt"` |
| `-o, --output <NAME>` | 输出文件名 (不含扩展名) | `-o payload` |
| `--debug` | 开启调试模式 (显示控制台窗口，便于查看日志) | `--debug` |
| `--sign <PATH>` | 指定一个合法 PE 文件以伪造其数字签名 | `--sign C:\Windows\explorer.exe` |

### 更多用法示例

**1. 打包 CMD 命令 (无文件落地执行)**
```bash
packer.exe --cmd "calc.exe" --output run_calc
```

**2. 打包 PE 文件 (Reflective Loading)**
```bash
packer.exe --input mimikatz.exe --output mimi_packed
```

**3. 启用调试控制台**
如果生成的 exe 没有任何反应，可以使用 `--debug` 重新打包，运行时会弹窗黑框显示内部日志：
```bash
packer.exe --input payload.bin --output payload_debug --debug
```
