use std::env;

fn main() {
    let ext = match env::consts::OS {
        "linux" => "so",
        "macos" => "dylib",
        _ => "dll",
    };
    let binary_path = format!("target/release/libpayjoin_ffi.{}", ext);
    #[cfg(feature = "uniffi")]
    uniffi::uniffi_bindgen_main();
    #[cfg(feature = "uniffi")]
    uniffi_dart::gen::generate_dart_bindings(
        "src/payjoin_ffi.udl".into(),
        None,
        Some("dart/lib".into()),
        binary_path.as_str().into(),
        true,
    )
    .unwrap();
}
