use std::env;
use std::path::PathBuf;

fn main() {
    let cargo_manifest_dir = env::var_os("CARGO_MANIFEST_DIR").unwrap();

    pkg_config::Config::new()
        .print_system_libs(false)
        .atleast_version("1.0.20")
        .probe("libsodium") // probe() calls pkg-config --libs --cflags libsodium
        .unwrap();

    // The bindgen::Builder is the main entry point to bindgen, and lets you build up options for the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate bindings for.
        .header("wrapper.h")
        .allowlist_function("sodium_init")
        .allowlist_function("crypto_generichash")
        .allowlist_function("crypto_generichash_keygen")
        .allowlist_function("crypto_generichash_init")
        .allowlist_function("crypto_generichash_update")
        .allowlist_function("crypto_generichash_final")
        .allowlist_var("crypto_generichash_.*")
        .opaque_type("crypto_generichash_state")
        .allowlist_function("randombytes_.*")
        .allowlist_function("crypto_auth")
        .allowlist_function("crypto_auth_keygen")
        .allowlist_function("crypto_auth_verify")
        .allowlist_var("crypto_auth_.*")
        // Tell cargo to invalidate the built crate whenever any of the included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the 'src' directory (so they can be committed)
    let out_path = PathBuf::from(cargo_manifest_dir).join("src");
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
