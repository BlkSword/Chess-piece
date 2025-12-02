# Chess-piece：shellcode Packer（v2.0）

Chess-piece 面向安全研发的 shellcode 打包与生成器。它将原始 shellcode 或命令字符串转换为隐蔽加载器，支持多层加密、UUID 混淆与多种执行技术，并优先采用 MSVC 编译以降低特征。

## 功能特性

- 多层加密：`aes`（AES-256-GCM）、`rc4`、`xor`。
- UUID 混淆：加密后的数据按 16 字节分块编码为 UUID 字符串；运行时使用 `UuidFromStringA` 还原字节并解密。
- 执行技术：`callback`（`EnumSystemLocalesA`）、`fiber`（纤程切换）、`earlybird`（挂起进程 + APC）。
- 间接系统调用：当 `--unhook=false` 时启用；MSVC 下通过汇编 stub 进行调用解析。
- NTDLL Unhook：可选择在运行时恢复 `ntdll.dll` 的 `.text` 段。
- 语言：当前仅生成 C 版本。

## 使用方法

命令行支持二选一输入：

```
packer.exe [--input <路径> | --cmd <命令>] [选项]
```

**参数说明**

| 参数 | 缩写 | 描述 | 默认值 |
|---|---|---|---|
| `--input` | `-i` | 原始 shellcode 文件路径。与 `--cmd` 二选一。 | 无 |
| `--cmd` | | 直接嵌入的命令字符串（NUL 结尾）。与 `--input` 二选一。 | 无 |
| `--enc` | | 加密方法：`aes`、`rc4`、`xor`。 | `aes` |
| `--key-length` | `-k` | 密钥长度。`aes` 需为 `32`。 | `32` |
| `--obf` | | 混淆方式。当前为 `uuid`。 | `uuid` |
| `--lang` | | 生成语言。当前支持 `c`。 | `c` |
| `--output` | `-o` | 输出可执行文件名（不含扩展名）。 | `Program` |
| `--framework` | `-f` | 目标架构标识（保留）。 | `x64` |
| `--sandbox` | | 反沙箱开关（保留）。 | `true` |
| `--unhook` | | `false` 启用间接系统调用路径；`true` 使用常规 WinAPI。 | `true` |
| `--ntdll-unhook` | | 运行时恢复 `ntdll.dll` 的 `.text` 段；`--cmd` 模式下自动关闭。 | `true` |
| `--loading` | | 执行技术：`callback`、`fiber`、`earlybird`。 | `callback` |
| `--debug` | | 打印生成的 C 源代码与编译命令。 | `false` |

**示例**

```bash
# 以文件为输入，RC4 加密 + fiber 加载
cargo run -p packer -- -i shellcode.bin --enc rc4 --loading fiber -o packed_loader --debug

# 以命令为输入，AES-256-GCM 加密 + 回调加载（自动写入输出文件）
cargo run -p packer -- --cmd "echo test" -o TestEcho --debug
```

## 输出与调试

- `--cmd` 模式下，运行生成的可执行文件会在 `%TEMP%\cp_cmd_output.txt` 写入命令输出，并在 `%TEMP%\cp_cmd_params.txt` 写入完整 `cmd.exe` 参数。
- `--debug` 在控制台打印生成的 C 源代码，以及编译命令与结果。
- 编译优先使用 MSVC `cl.exe`；不可用时回退到 MinGW `gcc`。
  - MSVC：链接 `Rpcrt4.lib`、`Shell32.lib`。
  - GCC：链接 `-lrpcrt4`、`-lbcrypt`、`-lshell32`，并使用 `-mwindows`。

## 从源码构建

需要安装 Rust 工具链。Windows 推荐安装 MSVC；如未安装，确保存在可用的 MinGW GCC 并能链接上述库。

```bash
cargo build -p packer --release
```

运行位于 `target/release` 的可执行文件，或直接使用：

```bash
cargo run -p packer -- --cmd "echo test" -o TestEcho --debug
```

## 输入与混淆说明

- 原始二进制：推荐使用原始二进制格式的 shellcode 文件（如 `shellcode.bin`）。
- 文本或数组：如 shellcode 以 C 数组或十六进制文本存在，请先转换为二进制文件。
- 架构匹配：请确保生成架构与输入一致（如 x64）。
- UUID 字节序：已采用 `Uuid::from_bytes_le` 生成，与 Windows 侧 `UuidFromStringA` 还原字节序一致。

## 系统调用与执行模板

- 间接系统调用：当 `--unhook=false` 时，模板将定义 `USE_INDIRECT_SYSCALLS` 并在 MSVC 下注入 `syscall_stub.x64.asm` 与 `syscalls.c.tpl`。
  - 使用 MSVC 编译时：`VirtualAlloc`/`VirtualProtect` 等调用通过解析 SSN 并经汇编 stub 间接触发。
  - 使用 GCC 回退时：`USE_INDIRECT_SYSCALLS` 分支将退回常规 WinAPI（无真正间接系统调用）。
- 执行模板：
  - `callback`：通过 `EnumSystemLocalesA` 回调执行。
  - `fiber`：通过 `ConvertThreadToFiber`/`CreateFiber` 切换执行。
  - `earlybird`：创建挂起的 `svchost.exe` 远程进程，写入 payload 后队列 APC 并恢复线程。
- `--cmd` 模式：忽略 `--loading`，改用 `cmd_exec.c.tpl` 在隐藏窗口中运行命令并保存输出；同时自动关闭 `--ntdll-unhook`。

## 故障排查

- 命令无输出：检查 `%TEMP%\cp_cmd_params.txt` 与 `%TEMP%\cp_cmd_output.txt`；确认命令无需交互且语法正确。
- 输出为空：可能等待时间不足（默认等待 ~10 秒）或命令本身无输出；可调整模板等待或取消隐藏窗口。
- 编译失败：安装并配置 MSVC `cl.exe` 或 MinGW `gcc`，并确保能链接所需库。
- 间接系统调用未生效：使用 MinGW 编译时不注入汇编 stub；请安装 MSVC 或将 `--unhook=true`。
- 被安全产品拦截：尝试禁用 `--ntdll-unhook`、更换执行技术（`fiber`/`callback`/`earlybird`），或在隔离环境测试。
- 非 ASCII 命令：当前使用 ANSI API；建议命令不含非 ASCII，或根据需要切换到宽字符 API 模板。

## 注意与限制

- `--framework` 与 `--sandbox` 目前为保留参数，尚未影响生成行为。
- 仅支持生成 C 源并编译为 Windows 可执行文件；后续将扩展更多语言与架构。
