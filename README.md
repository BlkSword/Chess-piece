# Chess-piece：shellcode Packer

Chess-piece 是一款为安全专业人员设计的精密shellcode打包工具。它将原始shellcode转换为一个隐蔽且具备规避能力的加载器（loader），配备了多层加密、混淆和先进的加载技术，旨在绕过现代安全解决方案。

## 功能特性

- **多层加密**：可选择 `aes`、`rc4` 和 `xor` 等多种方式加密shellcode负载。
- **熵值混淆**：采用 `uuid` 格式化来伪装shellcode，降低其熵值，以规避静态分析。
- **高级加载技术**：支持多种内存加载方法，包括 `callback`、`fiber` 和 `earlybird`。
- **间接系统调用**：通过直接发起系统调用来执行关键操作（如内存分配和保护），从而绕过用户态的EDR钩子。
- **Unhooking**：可在运行时恢复 `ntdll.dll` 的代码段，以移除钩子。
- **反沙箱**：内置检测机制，用于识别并规避沙箱环境。
- **可定制加载器**：目前可生成C语言版本的加载器，并计划在未来支持更多语言。

## 使用方法

本打包器通过命令行界面进行控制。以下是所有可用选项：

```
packer.exe --input <路径> [选项]
```

**参数说明：**

| 参数 | 缩写 | 描述 | 默认值 |
|---|---|---|---|
| `--input` | `-i` | 原始shellcode文件的路径。 | **必需** |
| `--enc` | | Shellcode的加密方法。 | `aes` |
| | | *可选值*: `aes`, `rc4`, `xor` | |
| `--lang` | | 生成的加载器所使用的语言。 | `c` |
| `--output` | `-o` | 输出的可执行文件名。 | `Program` |
| `--key-length` | `-k` | 加密密钥的长度。 | `16` |
| `--obf` | | 用于降低熵值的混淆技术。 | `uuid` |
| `--framework` | `-f` | 目标架构。 | `x64` |
| `--sandbox` | | 启用或禁用反沙箱检测。 | `true` |
| `--unhook` | | 启用或禁用ntdll unhooking。 | `false` |
| | | *注意*: 设置为 `false` 将启用间接系统调用。 | |
| `--loading` | | Shellcode的加载技术。 | `callback` |
| | | *可选值*: `callback`, `fiber`, `earlybird` | |
| `--debug` | | 打印中间过程的详细信息，包括生成的源代码。 | `false` |

**示例：**

```bash
# 使用RC4加密和fiber加载技术打包shellcode
.\packer.exe -i shellcode.bin --enc rc4 --loading fiber -o packed_loader.exe
```

## 从源码构建

要从源码构建此打包器，您需要安装Rust工具链。

1.  **构建项目**：

    ```bash
    cargo build -p packer -p stub --release
    ```

2.  **运行打包器**：

    生成的可执行文件将位于 `target/release` 目录下。

    ```bash
    cd target/release
    .\packer.exe -i <你的-shellcode.bin>
    ```

