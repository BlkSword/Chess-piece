# Chess-piece

**Chess-piece** 是一个基于 Rust 开发的 Shellcode 免杀打包与加载器生成工具，专为安全研究和红队测试设计。它采用 "Packer + Stub" 架构，通过 AES-256-GCM 加密、Zstd 压缩、多层混淆、Indirect Syscalls、VEH 内存保护等高级技术，将原始 Shellcode、PE 文件或 CMD 命令打包成具备反分析、反调试、反沙箱能力的免杀加载器。

## 杂记
项目是本人学习现代免杀并且自制rust技术栈免杀的一次尝试。截至制作完成之日的免杀效果为VT两个报毒，卡巴斯基、360、火绒均在动态和静态状态通过了查杀；在面对一些激进的查杀手法下表现较差（QVM查杀时会报毒）。本加载器默认自带反虚拟机、反沙盒。

---

## 项目结构

本项目采用 Rust Workspace 架构，包含三个核心 Crates：

```
chess-piece/
├── crates/
│   ├── packer/          # 命令行打包工具
│   │   ├── src/
│   │   │   ├── main.rs           # CLI 入口
│   │   │   ├── lib.rs            # 打包核心逻辑
│   │   │   ├── obfuscation.rs    # 数据混淆模块
│   │   │   └── signer.rs         # 签名伪造模块
│   │   └── Cargo.toml
│   ├── stub/            # Rust 加载器模板
│   │   ├── src/
│   │   │   └── main.rs           # 加载器实现 (解密+执行)
│   │   └── Cargo.toml
│   └── anti/            # 反分析功能库
│       ├── src/
│       │   └── lib.rs            # 反调试、反沙箱
│       └── Cargo.toml
├── target/release/
│   ├── packer.exe       # 打包工具
│   └── stub.exe         # 加载器模板
└── Cargo.toml           # Workspace 配置
```

### 模块说明

| 模块 | 功能描述 |
|------|----------|
| **`crates/packer`** | 命令行打包工具。负责读取 payload、执行 Zstd 压缩、AES-256-GCM 加密、数据混淆，并将处理后的数据注入到 `stub.exe` 中 |
| **`crates/stub`** | Rust 加载器模板。编译后生成 `stub.exe`。包含解密逻辑、反沙箱、反调试以及通过 Indirect Syscalls 执行 payload 的核心代码 |
| **`crates/anti`** | 反分析功能库，为 Stub 提供反调试、反沙箱、环境检测等能力 |

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

## 技术特性

### 核心技术栈

| 技术类别 | 具体实现 | 作用 |
|----------|----------|------|
| **加密技术** | AES-256-GCM | 提供机密性和完整性验证 |
| **压缩技术** | Zstd (Level 3) | 减小 payload 体积 |
| **数据混淆** | UUID / MAC / IPv4 / IPv6 | 绕过特征检测 |
| **系统调用** | Indirect Syscalls | 绕过用户层 API Hooking |
| **内存保护** | VEH (Vectored Exception Handler) | 动态切换内存权限 (RW/RX) |
| **数字签名** | 签名伪造 | 增加文件可信度 |

### 反分析能力

#### 反调试 (Anti-Debugging)
- 检测本地调试器 (如 OllyDbg、x64dbg)
- 检测远程调试器
- 硬件断点检测

#### 反沙箱 (Anti-Sandbox)
- 系统运行时间检测
- 物理内存大小检测
- 临时文件数量检测
- 进程数量检测
- 特定软件检测 (如微信)

#### 环境清理
- 清除敏感环境变量
- 延迟执行 (通过数学计算而非系统调用)

### 多负载支持

<details>
<summary><b>Shellcode</b></summary>

支持本地注入和远程进程注入：
- **本地注入**: 在当前进程内存中执行
- **远程注入**: 注入到指定目标进程

</details>

<details>
<summary><b>PE 文件</b></summary>

支持反射式加载 (Reflective PE Loading)：
- 无需落地磁盘
- 在内存中完整加载 PE 文件
- 自动处理导入表和重定位

</details>

<details>
<summary><b>CMD 命令</b></summary>

隐蔽执行系统命令：
- 直接执行命令而不创建 cmd.exe 进程
- 支持复杂命令和管道操作

</details>

### 执行方式

Stub 使用多种执行方式以提高可靠性：

1. **Thread Pool 回调** (优先级最高)
2. **EnumSystemLocalesA 回调**
3. **Fiber 切换**
4. **传统线程创建**

执行方式可随机选择，增加行为分析难度。

## 使用指南

### 命令行参数

```bash
packer.exe [OPTIONS] --output <OUTPUT>
```

| 参数 | 描述 | 示例 |
|------|------|------|
| `-i, --input <PATH>` | 输入文件路径 (Shellcode 或 PE 文件) | `-i shellcode.bin` |
| `--cmd <CMD>` | 直接打包一条 CMD 命令 | `--cmd "whoami > out.txt"` |
| `-o, --output <NAME>` | 输出文件名 (不含扩展名) | `-o payload` |
| `--debug` | 开启调试模式 (显示控制台窗口，便于查看日志) | `--debug` |
| `--sign <PATH>` | 指定一个合法 PE 文件以伪造其数字签名 | `--sign C:\Windows\explorer.exe` |

> 注意：`--input` 和 `--cmd` 参数互斥，只能使用其中一个。

### 使用示例

#### 1. 打包 Shellcode

```bash
# 本地注入
packer.exe --input calc.bin --output calc_packed

# 远程注入 (需要在 shellcode 中指定目标进程)
packer.exe --input shellcode.bin --output remote_inject
```

#### 2. 打包 CMD 命令

无文件落地执行系统命令：

```bash
packer.exe --cmd "whoami > C:\temp\result.txt" --output whoami_exe
```

#### 3. 打包 PE 文件

反射式加载 PE 文件，无需落地磁盘：

```bash
packer.exe --input mimikatz.exe --output mimi_packed
```

#### 4. 伪造数字签名

使用合法 PE 文件的签名增加可信度：

```bash
packer.exe --input payload.bin --output signed_payload --sign "C:\Windows\System32\calc.exe"
```

#### 5. 调试模式

如果生成的 exe 没有任何反应，可以使用 `--debug` 重新打包，运行时会显示控制台窗口和内部日志：

```bash
packer.exe --input payload.bin --output payload_debug --debug
```

---

## 免责声明

本项目仅供安全研究和教育目的使用。使用本工具进行任何未经授权的活动均属违法行为，作者对此不承担任何责任。

