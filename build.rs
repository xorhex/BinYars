use std::fs;
use std::path::PathBuf;

fn main() {
    let link_path = std::env::var_os("DEP_BINARYNINJACORE_PATH")
        .expect("DEP_BINARYNINJACORE_PATH not specified");

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR specified");
    let _out_dir_path = PathBuf::from(out_dir);

    println!("cargo::rustc-link-lib=dylib=binaryninjacore");
    println!("cargo::rustc-link-search={}", link_path.to_str().unwrap());

    #[cfg(not(target_os = "windows"))]
    {
        println!(
            "cargo::rustc-link-arg=-Wl,-rpath,{0},-L{0}",
            link_path.to_string_lossy()
        );
    }

    // Read Cargo.lock to extract the version of a dependency
    let lock = fs::read_to_string("Cargo.lock").unwrap();
    let version = lock
        .lines()
        .skip_while(|line| !line.contains("name = \"yara-x\""))
        .find(|line| line.contains("version ="))
        .and_then(|line| line.split('"').nth(1))
        .unwrap_or("unknown");

    println!("cargo:rustc-env=YARA_X_VERSION={}", version);
}
