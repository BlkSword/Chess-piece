# Chess-piece：shellcode Packer

Chess-piece 是一款为安全专业人员设计的精密 shellcode 打包工具。它将原始 shellcode 或命令行指令转换为一个隐蔽且具备规避能力的加载器（loader），配备了多层加密、混淆和先进的加载技术，旨在绕过现代安全解决方案。

## 功能特性

- 多层加密：支持 `aes`、`rc4`、`xor`。
- 熵值混淆：`uuid` 伪装加密后数据，降低静态特征。
- 高级加载：`callback`、`fiber`、`earlybird`。
- 间接系统调用：在 `--unhook=false` 时启用，以绕过用户态钩子。
- NTDLL Unhook：可恢复 `ntdll.dll` 的 `.text` 段，清除钩子。
- 反沙箱：可选沙箱检测与规避。
- 语言：当前生成 C 版本，后续将扩展。

## 使用方法

命令行接口支持二选一的输入方式：

```
packer.exe [--input <路径> | --cmd <命令>] [选项]
```

**参数说明**

| 参数 | 缩写 | 描述 | 默认值 |
|---|---|---|---|
| `--input` | `-i` | 原始 shellcode 文件路径。与 `--cmd` 二选一。 | 无 |
| `--cmd` | | 直接嵌入的命令字符串（NUL 结尾）。与 `--input` 二选一。 | 无 |
| `--enc` | | 加密方法。可选 `aes`、`rc4`、`xor`。 | `aes` |
| `--key-length` | `-k` | 密钥长度。`aes` 需为 `32`。 | `32` |
| `--obf` | | 混淆方式。当前为 `uuid`。 | `uuid` |
| `--lang` | | 生成语言。当前支持 `c`。 | `c` |
| `--output` | `-o` | 输出可执行文件名（不含扩展名）。 | `Program` |
| `--framework` | `-f` | 目标架构标识。 | `x64` |
| `--sandbox` | | 开启/关闭反沙箱检测。 | `true` |
| `--unhook` | | 控制是否注入“间接系统调用”路径。`false` 表示启用间接系统调用。 | `true` |
| `--ntdll-unhook` | | 运行时恢复 `ntdll.dll` 的 `.text` 段。`--cmd` 模式下自动关闭。 | `true` |
| `--loading` | | 加载技术：`callback`、`fiber`、`earlybird`。 | `callback` |
| `--debug` | | 打印详细过程与生成的源代码。 | `false` |

**示例**

```bash
# 以文件为输入，RC4 加密 + fiber 加载
cargo run -p packer -- -i shellcode.bin --enc rc4 --loading fiber -o packed_loader --debug

# 以命令为输入，AES-256-GCM 加密 + 回调加载
cargo run -p packer -- --cmd "echo test" -o TestEcho --debug
```

## 输出与调试

- `--cmd` 模式下，运行生成的可执行文件会在 `%TEMP%\cp_cmd_output.txt` 写入命令输出。
- 为便于排查，运行时还会在 `%TEMP%\cp_cmd_params.txt` 写入传递给 `cmd.exe` 的完整参数字符串。
- `--debug` 会在控制台打印最终生成的 C 源代码，以及编译命令与结果。
- 生成器优先调用 MSVC `cl.exe`，不可用时自动回退到 `gcc`（链接 `rpcrt4`、`bcrypt`、`shell32`，并使用 `-mwindows`）。

## 从源码构建

需要安装 Rust 工具链。Windows 推荐安装 MSVC；如未安装，确保存在可用的 MinGW GCC 并能链接 `rpcrt4`、`bcrypt`、`shell32`。

```bash
cargo build -p packer --release
```

运行位于 `target/release` 的可执行文件，或直接使用 `cargo run`：

```bash
cargo run -p packer -- --cmd "echo test" -o TestEcho --debug
```

## 输入格式支持

- 原始二进制：推荐使用原始二进制格式的 shellcode 文件（如 `shellcode.bin`）。
- 文本或数组：如 shellcode 以 C 数组或十六进制文本存在，请先转换为二进制文件。
- 架构匹配：请确保 `--framework` 与 shellcode 生成架构一致（如 x64）。

混淆说明：当前采用 `uuid` 方式，对加密后的数据按 16 字节分块编码为 UUID 字符串，运行时在 Windows 侧使用 `UuidFromStringA` 还原为原始字节并解密后再执行。已修复 UUID 字节序与 Windows 还原字节序的匹配问题，确保还原的内容与加密前一致。

系统调用说明：当 `--unhook=false` 时启用间接系统调用路径以降低用户态钩子影响；`--ntdll-unhook` 可在运行时恢复 `ntdll.dll` 的 `.text` 段，但在 `--cmd` 模式下默认关闭以提升稳定性。

## 故障排查

- 命令未产生输出：检查 `%TEMP%\cp_cmd_params.txt` 与 `%TEMP%\cp_cmd_output.txt`；确保命令语法正确且无需交互。
- 输出为空：可能等待时间不足或命令本身无输出；可自行修改模板提高等待或移除窗口隐藏。
- 编译失败：安装并配置 MSVC `cl.exe` 或 MinGW `gcc`，并确保可链接 `rpcrt4`、`bcrypt`、`shell32`。
- 被安全产品拦截：尝试禁用 `--ntdll-unhook` 或改用不同加载技术，或在非生产环境测试。
- 非 ASCII 命令：目前使用 ANSI API；建议命令不含非 ASCII，或根据需要将模板改为宽字符 API。
