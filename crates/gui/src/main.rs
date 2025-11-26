#![windows_subsystem = "windows"]
use eframe::egui;
use std::path::PathBuf;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Chess-piece 加壳器",
        options,
        Box::new(|_cc| Box::new(App::default())),
    )
}

#[derive(Default)]
struct App {
    mode_cmd: bool,
    input_path: String,
    output_path: String,
    status: String,
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Chess-piece 加壳器");
            ui.horizontal(|ui| {
                ui.label("模式:");
                ui.selectable_value(&mut self.mode_cmd, false, "文件模式");
                ui.selectable_value(&mut self.mode_cmd, true, "命令模式");
            });
            ui.separator();
            if self.mode_cmd {
                ui.horizontal(|ui| {
                    ui.label("命令路径:");
                    ui.text_edit_singleline(&mut self.input_path);
                    if ui.button("浏览").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            self.input_path = path.display().to_string();
                        }
                    }
                });
            } else {
                ui.horizontal(|ui| {
                    ui.label("输入EXE:");
                    ui.text_edit_singleline(&mut self.input_path);
                    if ui.button("浏览").clicked() {
                        if let Some(path) = rfd::FileDialog::new().add_filter("exe", &["exe"]).pick_file() {
                            self.input_path = path.display().to_string();
                        }
                    }
                });
            }
            ui.horizontal(|ui| {
                ui.label("输出壳EXE:");
                ui.text_edit_singleline(&mut self.output_path);
                if ui.button("选择").clicked() {
                    if let Some(path) = rfd::FileDialog::new().set_directory(std::env::current_dir().unwrap_or_default()).save_file() {
                        self.output_path = path.display().to_string();
                    }
                }
            });
            if ui.button("开始打包").clicked() {
                self.status.clear();
                let out = PathBuf::from(self.output_path.clone());
                let res = if self.mode_cmd {
                    packer::pack_cmd(self.input_path.trim(), &out)
                } else {
                    packer::pack_file(&PathBuf::from(self.input_path.trim()), &out)
                };
                match res {
                    Ok(_) => self.status = format!("已生成: {}", out.display()),
                    Err(e) => self.status = format!("失败: {}", e),
                }
            }
            if !self.status.is_empty() {
                ui.separator();
                ui.label(&self.status);
            }
        });
    }
}
