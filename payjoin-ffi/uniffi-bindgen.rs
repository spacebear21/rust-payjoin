use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    let language =
        args.iter().position(|arg| arg == "--language").and_then(|idx| args.get(idx + 1));

    match language {
        Some(lang) if lang == "dart" => {
            #[cfg(feature = "uniffi")]
            uniffi_dart::gen::generate_dart_bindings(
                "src/payjoin_ffi.udl".into(),
                None,
                Some(
                    args.iter()
                        .position(|arg| arg == "--out-dir")
                        .and_then(|idx| args.get(idx + 1))
                        .expect("No output directory found")
                        .as_str()
                        .into(),
                ),
                args.iter()
                    .position(|arg| arg == "--library")
                    .and_then(|idx| args.get(idx + 1))
                    .expect("No target file found")
                    .as_str()
                    .into(),
                true,
            )
            .expect("Failed to generate dart bindings");
        }
        Some(lang) if lang == "python" => {
            #[cfg(feature = "uniffi")]
            uniffi::uniffi_bindgen_main();
        }
        _ => panic!("No language specified"),
    }
}
