# QuantumHTTP

A developer-friendly, post-quantum secure HTTP/TLS library for Rust, aiming to make PQC adoption simple and practical.



## Workspace Layout
- `crates/quantumhttp-oqs-sys`: Low-level FFI bindings to liboqs (C). Default build uses a safe stub so the workspace compiles without liboqs.
- `crates/quantumhttp-core`: Safe Rust wrappers and higher-level API (work-in-progress).
- `crates/quantumhttp-cli`: CLI tools for key/cert management and diagnostics.

## Build

### 1) Stub mode (no liboqs required)
This verifies the workspace compiles and tooling works.

```bash
cargo build
```

### 2) With liboqs
Enable feature `oqs` for the `quantumhttp-oqs-sys` crate transitively via `quantumhttp-core`.

Requirements:
- A working liboqs installation (headers and library).
- Either
  - pkg-config can find `liboqs`, or
  - Environment variables are set: `OQS_INCLUDE_DIR` and `OQS_LIB_DIR`.

Example:

```bash
# Using environment variables
set OQS_INCLUDE_DIR=C:\path\to\liboqs\include
set OQS_LIB_DIR=C:\path\to\liboqs\lib
cargo build --features oqs
```

> Note: On Linux/macOS, use `export` instead of `set`.

The build script attempts to link `-l oqs` dynamically. Adjust if you build liboqs statically.

## CLI

```bash
# Show environment/build status
cargo run -p quantumhttp-cli -- status

# Generate keypair (stub until liboqs integration is implemented)
cargo run -p quantumhttp-cli -- gen-key --alg kyber512
```

## License
Licensed under the Apache License, Version 2.0 (LICENSE-APACHE).

Copyright 2025 Allen Elzayn.
