
use uuid::Uuid;

pub fn obfuscate(shellcode: &[u8], method: &str) -> Result<Vec<u8>, String> {
    match method {
        "uuid" => {
            let mut padded = shellcode.to_vec();
            let rem = padded.len() % 16;
            if rem != 0 {
                padded.extend(vec![0x90; 16 - rem]);
            }
            let strings: Vec<String> = padded
                .chunks_exact(16)
                .map(|c| Uuid::from_bytes_le(c.try_into().unwrap()).to_string())
                .collect();
            Ok(strings.join("\n").into_bytes())
        }
        "mac" => {
            let mut padded = shellcode.to_vec();
            let rem = padded.len() % 6;
            if rem != 0 {
                padded.extend(vec![0x00; 6 - rem]);
            }
            let strings: Vec<String> = padded
                .chunks_exact(6)
                .map(|c| {
                    format!(
                        "{:02X}-{:02X}-{:02X}-{:02X}-{:02X}-{:02X}",
                        c[0], c[1], c[2], c[3], c[4], c[5]
                    )
                })
                .collect();
            Ok(strings.join("\n").into_bytes())
        }
        "ipv6" => {
            let mut padded = shellcode.to_vec();
            let rem = padded.len() % 16;
            if rem != 0 {
                padded.extend(vec![0x00; 16 - rem]);
            }
            let strings: Vec<String> = padded
                .chunks_exact(16)
                .map(|c| {
                    let mut s = String::new();
                    for i in 0..8 {
                        let val = u16::from_be_bytes([c[i * 2], c[i * 2 + 1]]);
                        if i > 0 {
                            s.push(':');
                        }
                        s.push_str(&format!("{:x}", val));
                    }
                    s
                })
                .collect();
            Ok(strings.join("\n").into_bytes())
        }
        _ => Ok(shellcode.to_vec()),
    }
}
