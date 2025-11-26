use std::env;
use std::path::PathBuf;
use packer::{pack_cmd, pack_file};

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() < 2 {
        eprintln!("用法: packer <输入EXE路径> <输出EXE路径>\n或: packer --cmd <命令路径> <输出EXE路径>");
        std::process::exit(2);
    }
    let out_path: PathBuf;
    if args[0] == "--cmd" {
        if args.len() < 3 {
            eprintln!("用法: packer --cmd <命令路径> <输出EXE路径>");
            std::process::exit(2);
        }
        let cmd = &args[1];
        out_path = PathBuf::from(&args[2]);
        if let Err(e) = pack_cmd(cmd, &out_path) {
            eprintln!("打包失败: {}", e);
            std::process::exit(2);
        }
    } else {
        let in_path = PathBuf::from(&args[0]);
        out_path = PathBuf::from(&args[1]);
        if let Err(e) = pack_file(&in_path, &out_path) {
            eprintln!("打包失败: {}", e);
            std::process::exit(2);
        }
    }
    println!("已生成壳文件: {}", out_path.display());
}
