use std::{env, path::PathBuf};

fn main() {
    // If feature `oqs` is not enabled, do nothing (stub mode compiles without liboqs)
    let oqs_enabled = env::var("CARGO_FEATURE_OQS").is_ok();
    if !oqs_enabled {
        println!("cargo:rerun-if-changed=build.rs");
        return;
    }

    // Rebuild if env changes
    println!("cargo:rerun-if-env-changed=OQS_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=OQS_LIB_DIR");

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
    if !include_paths.is_empty() {
        // Try to locate oqs.h in any of the include paths
        let mut chosen_inc: Option<PathBuf> = None;
        for inc in &include_paths {
            let candidate = inc.join("oqs").join("oqs.h");
            if candidate.exists() {
                println!("cargo:warning=Found oqs.h at {}", candidate.display());
                chosen_inc = Some(inc.clone());
                break;
            } else {
                println!("cargo:warning=Not found: {}", candidate.display());
            }
        }

        if let Some(primary_inc) = chosen_inc {
            let header = primary_inc.join("oqs").join("oqs.h");
            let mut builder = bindgen::Builder::default()
                .header(header.to_string_lossy())
                .allowlist_function("OQS_.*")
                .allowlist_type("OQS_.*")
                .allowlist_var("OQS_.*")
                .clang_arg(format!("-I{}", primary_inc.display()));

            for extra in &include_paths {
                if extra != &primary_inc {
                    builder = builder.clang_arg(format!("-I{}", extra.display()));
                }
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
            println!("cargo:warning=oqs.h not found in any include path. Checked:");
            for inc in &include_paths {
                println!("cargo:warning=  - {}", inc.display());
            }
            // Fail fast to avoid confusing missing bindings error
            panic!("liboqs headers not found; set OQS_INCLUDE_DIR to the directory containing 'oqs/oqs.h'");
        }
    }
}
