use aes_gcm::aead::Aead;
use aes_gcm::KeyInit;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::{thread_rng, RngCore};
fn rc4_crypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut s = [0u8; 256];
    for i in 0..256 {
        s[i] = i as u8;
    }
    let mut j: usize = 0;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }
    let mut i_idx: usize = 0;
    let mut j_idx: usize = 0;
    let mut out = Vec::with_capacity(data.len());
    for &byte in data.iter() {
        i_idx = (i_idx + 1) % 256;
        j_idx = (j_idx + s[i_idx] as usize) % 256;
        s.swap(i_idx, j_idx);
        let k = s[(s[i_idx] as usize + s[j_idx] as usize) % 256];
        out.push(byte ^ k);
    }
    out
}

pub fn encrypt(data: &[u8], method: &str, key_length: u32) -> Result<(Vec<u8>, Vec<u8>), String> {
    match method {
        "aes" => {
            if key_length != 32 {
                return Err("AES-256-GCM 需要32字节密钥".to_string());
            }

            let mut key = vec![0u8; key_length as usize];
            thread_rng().fill_bytes(&mut key);

            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
            let nonce = Nonce::from_slice(b"uniquestring"); // 12-byte nonce

            let ciphertext = cipher
                .encrypt(nonce, data.as_ref())
                .map_err(|e| e.to_string())?;

            Ok((ciphertext, key))
        }
        "rc4" => {
            let mut key = vec![0u8; key_length as usize];
            thread_rng().fill_bytes(&mut key);
            let ciphertext = rc4_crypt(data, &key);
            Ok((ciphertext, key))
        }
        "xor" => {
            let mut key = vec![0u8; key_length as usize];
            thread_rng().fill_bytes(&mut key);

            let mut ciphertext = Vec::with_capacity(data.len());
            for (i, byte) in data.iter().enumerate() {
                ciphertext.push(byte ^ key[i % key.len()]);
            }

            Ok((ciphertext, key))
        }
        _ => Err(format!("Unsupported encryption method: {}", method)),
    }
}
