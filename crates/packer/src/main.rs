use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use rand::{rngs::OsRng, RngCore};
use std::env;
use std::fs;
use std::path::PathBuf;

const MARKER: &[u8] = b"RSPKv1\0"; // must match stub

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() < 2 {
        eprintln!("用法: packer <输入EXE路径> <输出EXE路径>");
        std::process::exit(2);
    }
    let in_path = PathBuf::from(&args[0]);
    let out_path = PathBuf::from(&args[1]);

    let input = match fs::read(&in_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("读取输入失败: {}", e);
            std::process::exit(2);
        }
    };

    // 可选压缩（提高加密前的去特征性）
    let compressed = match zstd::encode_all(&input[..], 3) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("压缩失败: {}", e);
            std::process::exit(2);
        }
    };

    // 读取 Stub
    let mut stub_path = PathBuf::from("target/release/stub.exe");
    if !stub_path.exists() {
        stub_path = PathBuf::from("target/debug/stub.exe");
    }
    let stub = match fs::read(&stub_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("读取Stub失败: {}。请先构建stub: cargo build -p stub --release", e);
            std::process::exit(2);
        }
    };

    // AES-256-GCM 加密
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = match cipher.encrypt(nonce, compressed.as_ref()) {
        Ok(ct) => ct,
        Err(_) => {
            eprintln!("加密失败");
            std::process::exit(2);
        }
    };

    // 组合输出：stub + marker + key_len(u32=32) + key + nonce_len(u32=12) + nonce + payload_len(u64) + ciphertext
    let mut out = stub;
    out.extend_from_slice(MARKER);
    out.extend_from_slice(&(32u32).to_le_bytes());
    out.extend_from_slice(&key);
    out.extend_from_slice(&(12u32).to_le_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    out.extend_from_slice(&ciphertext);
    if let Err(e) = fs::write(&out_path, &out) {
        eprintln!("写入输出失败: {}", e);
        std::process::exit(2);
    }
    println!("已生成壳文件: {}", out_path.display());
}
