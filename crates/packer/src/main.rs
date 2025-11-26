use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use packer::{pack_cmd, pack_file, pack_shellcode, pack_shellcode_py};

fn main() {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        eprintln!("用法:\n  packer <输入EXE路径> [--out <输出EXE>]\n  packer --cmd <命令路径> [--out <输出EXE>]\n  packer --sc <shellcode.bin> [--out <输出EXE>] [--remote <进程路径>]\n  packer --src <源码文件> --lang <rust|c> [--out <输出EXE>]");
        std::process::exit(2);
    }
    let mut out: Option<PathBuf> = None;
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == "--out" && i + 1 < args.len() {
            out = Some(PathBuf::from(&args[i + 1]));
            args.drain(i..=i+1);
        } else { i += 1; }
    }
    if args[0] == "--cmd" {
        if args.len() < 2 { eprintln!("缺少命令路径"); std::process::exit(2); }
        let cmd = &args[1];
        let dest = out.unwrap_or_else(|| default_out_from(Path::new(cmd)));
        if let Err(e) = pack_cmd(cmd, &dest) { eprintln!("打包失败: {}", e); std::process::exit(2); }
        println!("已生成壳文件: {}", dest.display());
    } else if args[0] == "--sc" {
        if args.len() < 2 { eprintln!("缺少shellcode路径"); std::process::exit(2); }
        let sc = PathBuf::from(&args[1]);
        let mut inj = "self".to_string();
        let mut remote: Option<PathBuf> = None;
        let mut j = 2;
        while j < args.len() {
            if args[j] == "--remote" && j + 1 < args.len() { inj = "remote".to_string(); remote = Some(PathBuf::from(&args[j + 1])); j += 2; } else { j += 1; }
        }
        let dest = out.unwrap_or_else(|| default_out_from(&sc));
        match sc.extension().and_then(|e| e.to_str()).map(|s| s.to_ascii_lowercase()) {
            Some(ref ext) if ext == "py" => {
                if let Err(e) = pack_shellcode_py(&sc, &dest) { eprintln!("打包失败: {}", e); std::process::exit(2); }
            }
            Some(ref ext) if ext == "c" => {
                // 等价于源码模式：编译后加壳
                let tmp_exe = std::env::temp_dir().join(format!("rs_src_payload_{}.exe", std::process::id()));
                let st = Command::new("cl").arg(&sc).arg("/O2").arg("/Fe:").arg(&tmp_exe).status().unwrap_or_else(|e| { eprintln!("cl调用失败: {}", e); std::process::exit(2) });
                if !st.success() { eprintln!("c 源码编译失败"); std::process::exit(2); }
                if let Err(e) = pack_file(&tmp_exe, &dest) { let _ = std::fs::remove_file(&tmp_exe); eprintln!("打包失败: {}", e); std::process::exit(2); }
                let _ = std::fs::remove_file(&tmp_exe);
            }
            _ => {
                if let Err(e) = pack_shellcode(&sc, &dest, &inj, remote.as_deref()) { eprintln!("打包失败: {}", e); std::process::exit(2); }
            }
        }
        println!("已生成壳文件: {}", dest.display());
    } else if args[0] == "--src" {
        if args.len() < 2 { eprintln!("缺少源码文件路径"); std::process::exit(2); }
        let src = PathBuf::from(&args[1]);
        let mut lang = String::from("rust");
        let mut j = 2;
        while j < args.len() {
            if args[j] == "--lang" && j + 1 < args.len() { lang = args[j + 1].clone(); j += 2; } else { j += 1; }
        }
        let tmp_exe = std::env::temp_dir().join(format!("rs_src_payload_{}.exe", std::process::id()));
        if lang.eq_ignore_ascii_case("rust") {
            let st = Command::new("rustc").arg("-C").arg("opt-level=3").arg(&src).arg("-o").arg(&tmp_exe).status().unwrap_or_else(|e| { eprintln!("rustc调用失败: {}", e); std::process::exit(2) });
            if !st.success() { eprintln!("rust 源码编译失败"); std::process::exit(2); }
        } else if lang.eq_ignore_ascii_case("c") {
            let st = Command::new("cl").arg(&src).arg("/O2").arg("/Fe:").arg(&tmp_exe).status().unwrap_or_else(|e| { eprintln!("cl调用失败: {}", e); std::process::exit(2) });
            if !st.success() { eprintln!("c 源码编译失败"); std::process::exit(2); }
        } else { eprintln!("不支持的语言，允许 rust 或 c"); std::process::exit(2); }
        let dest = out.unwrap_or_else(|| default_out_from(&src));
        if let Err(e) = pack_file(&tmp_exe, &dest) { let _ = std::fs::remove_file(&tmp_exe); eprintln!("打包失败: {}", e); std::process::exit(2); }
        let _ = std::fs::remove_file(&tmp_exe);
        println!("已生成壳文件: {}", dest.display());
    } else {
        let in_path = PathBuf::from(&args[0]);
        let dest = out.unwrap_or_else(|| default_out_from(&in_path));
        if let Err(e) = pack_file(&in_path, &dest) { eprintln!("打包失败: {}", e); std::process::exit(2); }
        println!("已生成壳文件: {}", dest.display());
    }
}

fn default_out_from(p: &Path) -> PathBuf {
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("packed");
    PathBuf::from(format!("{}_packed.exe", stem))
}
