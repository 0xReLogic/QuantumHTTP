# QuantumHTTP

QuantumHTTP is a Rust library that builds a post‑quantum resistant HTTP/TLS foundation. It currently provides Kyber (ML‑KEM) KEM, ML‑DSA/Dilithium signatures (via liboqs), X.509 self‑signed certificates, and a CLI for key/signature/certificate management. The goal is to enable incremental PQC adoption with solid security practices and interoperability.


## Project Status (2025-08-12)

- X.509 self‑signed certificates now include default v3 extensions:
  - Subject Alternative Name: DNS:localhost (mirrors `--subject-cn`)
  - KeyUsage: digitalSignature (critical)
  - ExtendedKeyUsage: serverAuth
  - BasicConstraints: CA=false (critical)
- CLI supports PEM‑like output for PK/SK/CT/SS/Certificate via `--pem` with clear labels (see Quickstart below).
- Integration tests cover Kyber KEM, ML‑DSA signatures, and X.509 with extensions.


## Workspace Layout
- `crates/quantumhttp-oqs-sys`: Low-level FFI bindings to liboqs (C). By default it uses a safe stub so the workspace can build without liboqs installed.
- `crates/quantumhttp-core`: Safe Rust wrappers and higher-level API (work in progress).
- `crates/quantumhttp-cli`: CLI tools for key/certificate management and diagnostics.

## Build

### 1) Stub mode (no liboqs)
This verifies the workspace compiles and the toolchain works.

```bash
cargo build
```

### 2) With liboqs
Enable the `oqs` feature (transitively via `quantumhttp-core`).

Requirements:
- A working liboqs installation (headers and library).
- Either:
  - pkg-config can find `liboqs`, or
  - Environment variables are set: `OQS_INCLUDE_DIR` and `OQS_LIB_DIR`.

Example:

```bash
# Using environment variables (Windows)
set OQS_INCLUDE_DIR=C:\path\to\liboqs\include
set OQS_LIB_DIR=C:\path\to\liboqs\lib
cargo build --features oqs
```

> Note: On Linux/macOS use `export` instead of `set`.

The build script links `-l oqs` dynamically. Adjust if you build liboqs statically.

### Windows setup (liboqs)

Set environment variables for headers and libs, and ensure the DLL is on PATH:

```powershell
$env:OQS_INCLUDE_DIR="D:\oqs\include"
$env:OQS_LIB_DIR="D:\oqs\lib"
$env:Path = "D:\oqs\bin;" + $env:Path
# Optional (MSVC linker search path):
$env:LIB = "D:\oqs\lib;" + $env:LIB

# Build and run tests with feature `oqs`
cargo test -p quantumhttp-core --features oqs -- --nocapture

# Run only the integration test in tests/kyber_kem.rs
cargo test -p quantumhttp-core --features oqs --test kyber_kem -- --nocapture
```

Persisting env vars (applies to new terminals):

```powershell
setx OQS_INCLUDE_DIR "D:\oqs\include"
setx OQS_LIB_DIR "D:\oqs\lib"
# Avoid using `setx PATH` because it can truncate PATH at 1024 chars. Prefer the System Environment UI.
# If needed for the MSVC linker:
setx LIB "D:\oqs\lib;%LIB%"
```

### Troubleshooting (Windows)

- __Header found but bindings.rs missing__:
  - Ensure `OQS_INCLUDE_DIR` points to a directory that contains `oqs/oqs.h`.
  - The build script logs probed include paths and fails fast if the header is missing.
- __LNK1181: cannot open input file 'oqs.lib'__:
  - Ensure `OQS_LIB_DIR` is set and accessible.
  - Add `D:\oqs\lib` to the MSVC linker search via `$env:LIB = "D:\oqs\lib;" + $env:LIB`.
  - You can also pass a one-off flag: `$env:RUSTFLAGS = "-L native=D:\oqs\lib"`.
- __DLL not found at runtime__:
  - Ensure `oqs.dll` is present in `D:\oqs\bin` and that directory is on `PATH`.

## CLI

### Quickstart (with `--features oqs`)

```bash
# Show environment/build status
cargo run -p quantumhttp-cli --features oqs -- status

# Kyber KEM keypair (raw files)
cargo run -p quantumhttp-cli --features oqs -- gen-key --alg kyber512 \
  --out-pk kyber_pk.bin --out-sk kyber_sk.bin

# Kyber encapsulation → ciphertext + shared secret (write PEM files)
cargo run -p quantumhttp-cli --features oqs -- kem-encap --alg kyber512 \
  --pk kyber_pk.bin --out-ct ct.pem --out-ss ss.pem --pem

# Kyber decapsulation → shared secret (write PEM file)
cargo run -p quantumhttp-cli --features oqs -- kem-decap --alg kyber512 \
  --sk kyber_sk.bin --ct ct.pem --out-ss ss_dec.pem --pem

# ML-DSA keypair (raw files)
cargo run -p quantumhttp-cli --features oqs -- sig-gen --alg ml-dsa-44 \
  --out-pk mldsa_pk.bin --out-sk mldsa_sk.bin

# Sign message with ML-DSA (signature in PEM)
cargo run -p quantumhttp-cli --features oqs -- sig-sign --alg ml-dsa-44 \
  --sk mldsa_sk.bin --in message.bin --out-sig sig.pem --pem

# Verify signature
cargo run -p quantumhttp-cli --features oqs -- sig-verify --alg ml-dsa-44 \
  --pk mldsa_pk.bin --in message.bin --sig sig.pem

# X.509 self-signed certificate (DER)
cargo run -p quantumhttp-cli --features oqs -- x509-selfsign \
  --alg ml-dsa-44 --pk mldsa_pk.bin --sk mldsa_sk.bin \
  --subject-cn localhost --days 7 --out cert.der

# X.509 self-signed certificate (PEM)
cargo run -p quantumhttp-cli --features oqs -- x509-selfsign \
  --alg ml-dsa-44 --pk mldsa_pk.bin --sk mldsa_sk.bin \
  --subject-cn localhost --days 7 --out cert.pem --pem
```

### Verify certificate with OpenSSL

```bash
# DER
openssl x509 -in cert.der -inform DER -text -noout

# PEM
openssl x509 -in cert.pem -text -noout
```

### PEM labels

- KYBER PUBLIC KEY, KYBER SECRET KEY
- KYBER CIPHERTEXT, SHARED SECRET
- ML-DSA PUBLIC KEY, ML-DSA SECRET KEY, ML-DSA SIGNATURE
- CERTIFICATE

PEM is Base64-wrapped at 64 characters per line.

### Security of secret material

- Secret keys (SK) and shared secrets (SS) are sensitive. Store them safely.
- The CLI zeroizes sensitive buffers in memory where possible.
- Avoid committing SK/SS to public repos. Use strict file permissions.

## License
Licensed under the Apache License, Version 2.0 (LICENSE-APACHE).

Copyright 2025 Allen Elzayn.
