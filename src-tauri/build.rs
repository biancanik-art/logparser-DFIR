fn main() {
    tauri_build::build();
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        if let Ok(out_dir) = std::env::var("OUT_DIR") {
            let res_lib = std::path::Path::new(&out_dir).join("libresource.a");
            if res_lib.exists() {
                println!("cargo:rustc-link-arg-tests={}", res_lib.display());
            }
        }
    }
}
