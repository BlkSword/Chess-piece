
use uuid::Uuid;

pub fn obfuscate(shellcode: &[u8], method: &str) -> Result<Vec<u8>, String> {
    match method {
        "uuid" => {
            let mut padded_shellcode = shellcode.to_vec();
            let remainder = padded_shellcode.len() % 16;
            if remainder != 0 {
                let padding_needed = 16 - remainder;
                padded_shellcode.extend(vec![0x90; padding_needed]); // Pad with NOPs
            }

            let uuid_strings: Vec<String> = padded_shellcode
                .chunks_exact(16)
                .map(|chunk| {
                    let uuid = Uuid::from_slice(chunk).unwrap();
                    format!("\"{}\"", uuid.to_string())
                })
                .collect();

            let final_string = format!("{}", uuid_strings.join(",\n"));
            Ok(final_string.into_bytes())
        }
        _ => Err(format!("Unsupported obfuscation method: {}", method)),
    }
}
