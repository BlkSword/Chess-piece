#![cfg_attr(all(windows), windows_subsystem = "windows")]
use std::path::Path;
use tauri::Wry;

#[tauri::command]
fn pack_cmd(cmd: String, out_path: String) -> Result<(), String> {
    packer::pack_cmd(&cmd, Path::new(&out_path))
}

#[tauri::command]
fn pack_file(input_path: String, out_path: String) -> Result<(), String> {
    packer::pack_file(Path::new(&input_path), Path::new(&out_path))
}

fn main() {
    tauri::Builder::<Wry>::new()
        .invoke_handler(tauri::generate_handler![pack_cmd, pack_file])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
