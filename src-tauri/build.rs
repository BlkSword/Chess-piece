use std::fs;
use std::path::PathBuf;

fn ensure_default_icon() {
    let icon_path = PathBuf::from("src-tauri/icons/icon.ico");
    let root_icon_path = PathBuf::from("icons/icon.ico");
    let need_write = fs::metadata(&icon_path).is_err() || fs::metadata(&root_icon_path).is_err();
    if !need_write {
        return;
    }
    let _ = fs::create_dir_all(icon_path.parent().unwrap());
    let _ = fs::create_dir_all(root_icon_path.parent().unwrap());
    let mut ico: Vec<u8> = Vec::new();
    // ICONDIR
    ico.extend_from_slice(&[0, 0, 1, 0, 1, 0]);
    // ICONDIRENTRY
    ico.extend_from_slice(&[16, 16, 0, 0]); // width, height, colors, reserved
    ico.extend_from_slice(&(1u16).to_le_bytes()); // planes
    ico.extend_from_slice(&(32u16).to_le_bytes()); // bitcount
    let dib_size: u32 = 40 + (16 * 16 * 4) + (4 * 16); // header + pixels + AND mask
    let offset: u32 = 6 + 16; // after header and entry
    ico.extend_from_slice(&dib_size.to_le_bytes());
    ico.extend_from_slice(&offset.to_le_bytes());

    // BITMAPINFOHEADER
    let mut dib: Vec<u8> = Vec::new();
    dib.extend_from_slice(&(40u32).to_le_bytes()); // biSize
    dib.extend_from_slice(&(16i32).to_le_bytes()); // biWidth
    dib.extend_from_slice(&(32i32).to_le_bytes()); // biHeight (XOR+AND)
    dib.extend_from_slice(&(1u16).to_le_bytes()); // biPlanes
    dib.extend_from_slice(&(32u16).to_le_bytes()); // biBitCount
    dib.extend_from_slice(&(0u32).to_le_bytes()); // biCompression BI_RGB
    dib.extend_from_slice(&(16u32 * 16 * 4).to_le_bytes()); // biSizeImage
    dib.extend_from_slice(&(0i32).to_le_bytes()); // biXPelsPerMeter
    dib.extend_from_slice(&(0i32).to_le_bytes()); // biYPelsPerMeter
    dib.extend_from_slice(&(0u32).to_le_bytes()); // biClrUsed
    dib.extend_from_slice(&(0u32).to_le_bytes()); // biClrImportant

    // Pixel data (BGRA), simple blue-ish square with full alpha
    for _y in 0..16 {
        for _x in 0..16 {
            dib.extend_from_slice(&[0xCC, 0x66, 0x00, 0xFF]); // B,G,R,A
        }
    }
    // AND mask (1 bit per pixel, 4-byte aligned per row). All zeros (opaque)
    dib.extend(std::iter::repeat(0u8).take(4 * 16));

    ico.extend_from_slice(&dib);
    let _ = fs::write(&icon_path, &ico);
    let _ = fs::write(&root_icon_path, &ico);
}

fn main() {
    ensure_default_icon();
    tauri_build::build();
}
