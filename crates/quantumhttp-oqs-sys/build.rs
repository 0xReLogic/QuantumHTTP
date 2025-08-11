use std::{env, path::PathBuf};

fn main() {
    // If feature `oqs` is not enabled, do nothing (stub mode compiles without liboqs)
    let oqs_enabled = env::var("CARGO_FEATURE_OQS").is_ok();
    if !oqs_enabled {
        println!("cargo:rerun-if-changed=build.rs");
        return;
    }

    // Try to discover liboqs via pkg-config or environment variables
    // Env overrides: OQS_INCLUDE_DIR, OQS_LIB_DIR
    let include_dir_env = env::var("OQS_INCLUDE_DIR").ok();
    let lib_dir_env = env::var("OQS_LIB_DIR").ok();

    let mut include_paths: Vec<PathBuf> = Vec::new();
    let mut lib_paths: Vec<PathBuf> = Vec::new();
    let mut found_via_pkg = false;

    if include_dir_env.is_none() || lib_dir_env.is_none() {
        if let Ok(lib) = pkg_config::Config::new()
            .atleast_version("0.8.0")
            .probe("liboqs")
        {
            for p in lib.include_paths {
                include_paths.push(p);
            }
            for p in lib.link_paths {
                lib_paths.push(p);
            }
            found_via_pkg = true;
        }
    }

    if !found_via_pkg {
        if let Some(inc) = include_dir_env {
            include_paths.push(PathBuf::from(inc));
        }
        if let Some(libd) = lib_dir_env {
            lib_paths.push(PathBuf::from(libd));
        }
    }

    if include_paths.is_empty() || lib_paths.is_empty() {
        println!("cargo:warning=Feature `oqs` enabled but liboqs not found. Set OQS_INCLUDE_DIR and OQS_LIB_DIR or install pkg-config/liboqs.");
    }

    // Link search paths
    for p in &lib_paths {
        println!("cargo:rustc-link-search=native={}", p.display());
    }

    // Prefer dynamic link; adjust if you build static liboqs
    println!("cargo:rustc-link-lib=oqs");

    // Generate bindings if we have includes
    if let Some(inc) = include_paths.get(0) {
        let header = inc.join("oqs/oqs.h");
        if header.exists() {
            let mut builder = bindgen::Builder::default()
                .header(header.to_string_lossy())
                .allowlist_function("OQS_.*")
                .allowlist_type("OQS_.*")
                .allowlist_var("OQS_.*")
                .clang_arg(format!("-I{}", inc.display()));

            for extra in include_paths.iter().skip(1) {
                builder = builder.clang_arg(format!("-I{}", extra.display()));
            }

            let bindings = builder
                .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
                .generate()
                .expect("Unable to generate liboqs bindings");

            let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
            bindings
                .write_to_file(out_path.join("bindings.rs"))
                .expect("Couldn't write bindings!");

            println!("cargo:rerun-if-changed=build.rs");
        } else {
            println!("cargo:warning=Could not find oqs.h under {}", inc.display());
        }
    }
}
