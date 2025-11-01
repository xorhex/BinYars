use std::env;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // === 1. Get Binary Ninja Core path ===
    let link_path =
        env::var_os("DEP_BINARYNINJACORE_PATH").expect("DEP_BINARYNINJACORE_PATH not specified");
    let link_path_str = link_path
        .to_str()
        .expect("DEP_BINARYNINJACORE_PATH not valid UTF-8");

    // === 2. Tell Cargo how to link ===
    println!("cargo::rustc-link-lib=dylib=binaryninjacore");
    println!("cargo::rustc-link-search={}", link_path_str);

    // === 3. Platform-specific handling ===
    let target_os = env::consts::OS;
    let _ = match target_os {
        "linux" => {
            println!("cargo::rustc-link-arg=-Wl,-rpath,{0},-L{0}", link_path_str);
            "libbinyars.so"
        }
        "macos" => "libbinyars.dylib",
        "windows" => "binyars.dll",
        _ => panic!("Unsupported target OS: {}", target_os),
    };

    // === 5. Extract YARA-X version from Cargo.lock ===
    let version =
        extract_dependency_version("Cargo.lock", "yara-x").unwrap_or_else(|| "unknown".to_string());

    // Make the version available to code via env!()
    println!("cargo:rustc-env=YARA_X_VERSION={}", version);

    Ok(())
}

/// Extract the version of a dependency from Cargo.lock
fn extract_dependency_version(lock_path: &str, dep_name: &str) -> Option<String> {
    let lock_contents = fs::read_to_string(lock_path).ok()?;
    let mut lines = lock_contents.lines();

    while let Some(line) = lines.next() {
        if line.trim() == format!("name = \"{}\"", dep_name) {
            if let Some(ver_line) = lines.find(|l| l.trim().starts_with("version =")) {
                return ver_line.split('"').nth(1).map(|s| s.to_string());
            }
        }
    }
    None
}
