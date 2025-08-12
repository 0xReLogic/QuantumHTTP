use clap::{Parser, Subcommand};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroize;

#[derive(Parser, Debug)]
#[command(name = "quantumhttp", version, about = "QuantumHTTP CLI tools", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Show environment and build status
    Status,
    /// Generate PQC keypair (stub until liboqs integration is enabled)
    GenKey {
        /// Algorithm name (e.g., kyber512, kyber768)
        #[arg(long, default_value = "kyber512")]
        alg: String,
        /// Optional path to write raw public key bytes
        #[arg(long)]
        out_pk: Option<PathBuf>,
        /// Optional path to write raw secret key bytes
        #[arg(long)]
        out_sk: Option<PathBuf>,
        /// Print secret key to stdout (base64). Default: false
        #[arg(long, default_value_t = false)]
        print_secret: bool,
        /// Write outputs in PEM-like format instead of raw bytes
        #[arg(long, default_value_t = false)]
        pem: bool,
    },
    /// KEM Encapsulation: PK -> (CT, SS)
    #[command(name = "kem-encap")]
    KemEncap {
        /// Algorithm name (e.g., kyber512, kyber768)
        #[arg(long, default_value = "kyber512")]
        alg: String,
        /// Public key file (raw bytes)
        #[arg(long)]
        pk: PathBuf,
        /// Optional path to write raw ciphertext bytes
        #[arg(long)]
        out_ct: Option<PathBuf>,
        /// Optional path to write raw shared secret bytes
        #[arg(long)]
        out_ss: Option<PathBuf>,
        /// Print shared secret to stdout (base64). Default: false
        #[arg(long, default_value_t = false)]
        print_secret: bool,
        /// Write outputs in PEM-like format instead of raw bytes
        #[arg(long, default_value_t = false)]
        pem: bool,
    },
    /// KEM Decapsulation: SK + CT -> SS
    #[command(name = "kem-decap")]
    KemDecap {
        /// Algorithm name (e.g., kyber512, kyber768)
        #[arg(long, default_value = "kyber512")]
        alg: String,
        /// Secret key file (raw bytes)
        #[arg(long)]
        sk: PathBuf,
        /// Ciphertext file (raw bytes)
        #[arg(long)]
        ct: PathBuf,
        /// Optional path to write raw shared secret bytes
        #[arg(long)]
        out_ss: Option<PathBuf>,
        /// Print shared secret to stdout (base64). Default: false
        #[arg(long, default_value_t = false)]
        print_secret: bool,
        /// Write outputs in PEM-like format instead of raw bytes
        #[arg(long, default_value_t = false)]
        pem: bool,
    },
    /// SIG Keypair Generation (Dilithium/ML-DSA): produce (PK, SK)
    #[command(name = "sig-gen")]
    SigGen {
        /// Algorithm name (e.g., ml-dsa-44, ml-dsa-65, ml-dsa-87, dilithium2/3/5)
        #[arg(long, default_value = "ml-dsa-44")]
        alg: String,
        /// Optional path to write raw public key bytes
        #[arg(long)]
        out_pk: Option<PathBuf>,
        /// Optional path to write raw secret key bytes
        #[arg(long)]
        out_sk: Option<PathBuf>,
        /// Print secret key to stdout (base64). Default: false
        #[arg(long, default_value_t = false)]
        print_secret: bool,
        /// Write outputs in PEM-like format instead of raw bytes
        #[arg(long, default_value_t = false)]
        pem: bool,
    },
    /// SIG Sign: SK + MESSAGE -> SIGNATURE
    #[command(name = "sig-sign")]
    SigSign {
        /// Algorithm name (e.g., ml-dsa-44, ml-dsa-65, ml-dsa-87, dilithium2/3/5)
        #[arg(long, default_value = "ml-dsa-44")]
        alg: String,
        /// Secret key file (raw bytes)
        #[arg(long)]
        sk: PathBuf,
        /// Input message file to sign (raw bytes)
        #[arg(long, alias = "in", value_name = "in")]
        in_path: PathBuf,
        /// Optional path to write raw signature bytes
        #[arg(long)]
        out_sig: Option<PathBuf>,
        /// Print signature to stdout (base64). Default: false
        #[arg(long, default_value_t = false)]
        print_signature: bool,
        /// Write outputs in PEM-like format instead of raw bytes
        #[arg(long, default_value_t = false)]
        pem: bool,
    },
    /// SIG Verify: PK + MESSAGE + SIGNATURE -> valid?
    #[command(name = "sig-verify")]
    SigVerify {
        /// Algorithm name (e.g., ml-dsa-44, ml-dsa-65, ml-dsa-87, dilithium2/3/5)
        #[arg(long, default_value = "ml-dsa-44")]
        alg: String,
        /// Public key file (raw bytes)
        #[arg(long)]
        pk: PathBuf,
        /// Input message file (raw bytes)
        #[arg(long, alias = "in", value_name = "in")]
        in_path: PathBuf,
        /// Signature file (raw bytes)
        #[arg(long)]
        sig: PathBuf,
    },
    /// X.509 Self-signed certificate (ML-DSA/Dilithium)
    #[command(name = "x509-selfsign")]
    X509SelfSign {
        /// Signature algorithm (e.g., ml-dsa-44, ml-dsa-65, ml-dsa-87)
        #[arg(long, default_value = "ml-dsa-44")]
        alg: String,
        /// Public key file (raw bytes)
        #[arg(long)]
        pk: PathBuf,
        /// Secret key file (raw bytes)
        #[arg(long)]
        sk: PathBuf,
        /// Subject Common Name (CN)
        #[arg(long, default_value = "localhost")]
        subject_cn: String,
        /// Validity in days
        #[arg(long, default_value_t = 365u32)]
        days: u32,
        /// Output certificate path (DER)
        #[arg(long)]
        out: PathBuf,
        /// Write certificate in PEM format instead of DER
        #[arg(long, default_value_t = false)]
        pem: bool,
    },
}

fn encode_pem(label: &str, data: &[u8]) -> String {
    let b64 = B64.encode(data);
    let mut s = String::new();
    s.push_str(&format!("-----BEGIN {}-----\n", label));
    for chunk in b64.as_bytes().chunks(64) {
        // safe: base64 is ASCII
        s.push_str(std::str::from_utf8(chunk).unwrap());
        s.push('\n');
    }
    s.push_str(&format!("-----END {}-----\n", label));
    s
}

fn write_bytes_or_pem(path: &PathBuf, label: &str, data: &[u8], pem: bool) -> std::io::Result<()> {
    if pem {
        let mut s = encode_pem(label, data);
        let res = fs::write(path, s.as_bytes());
        s.zeroize();
        res
    } else {
        fs::write(path, data)
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => {
            let available = quantumhttp_core::status::oqs_available();
            println!("liboqs available: {}", available);
            if !available {
                println!("tip: build with `--features oqs` and set OQS_INCLUDE_DIR/OQS_LIB_DIR, or install liboqs with pkg-config");
            }
        }
        Commands::SigGen { alg, out_pk, out_sk, print_secret, pem } => {
            match quantumhttp_core::DilithiumSig::generate_keypair_with_alg_secret(&alg) {
                Ok((pk, sk)) => {
                    println!("algorithm: {}", alg);
                    println!("public_key_len: {} bytes", pk.len());
                    println!("secret_key_len: {} bytes", sk.as_ref().len());

                    // stdout base64 for PK
                    println!("public_key_b64: {}", B64.encode(&pk));
                    if print_secret {
                        let mut b64 = B64.encode(sk.as_ref());
                        println!("secret_key_b64: {}", b64);
                        b64.zeroize();
                    }

                    // optional file outputs
                    if let Some(path) = out_pk {
                        if let Err(e) = write_bytes_or_pem(&path, "ML-DSA PUBLIC KEY", &pk, pem) {
                            eprintln!("failed to write public key to {}: {}", path.display(), e);
                            std::process::exit(2);
                        }
                    }
                    if let Some(path) = out_sk {
                        if let Err(e) = write_bytes_or_pem(&path, "ML-DSA SECRET KEY", sk.as_ref(), pem) {
                            eprintln!("failed to write secret key to {}: {}", path.display(), e);
                            std::process::exit(2);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                    std::process::exit(2);
                }
            }
        }
        Commands::SigSign { alg, sk, in_path, out_sig, print_signature, pem } => {
            let sk_bytes = match fs::read(&sk) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("failed to read secret key {}: {}", sk.display(), e);
                    std::process::exit(2);
                }
            };
            let msg = match fs::read(&in_path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("failed to read input {}: {}", in_path.display(), e);
                    // zeroize sk before exit
                    let mut sk_bytes = sk_bytes;
                    sk_bytes.zeroize();
                    std::process::exit(2);
                }
            };
            match quantumhttp_core::DilithiumSig::sign_with_alg(&alg, &sk_bytes, &msg) {
                Ok(sig) => {
                    println!("algorithm: {}", alg);
                    println!("signature_len: {} bytes", sig.len());
                    if print_signature {
                        println!("signature_b64: {}", B64.encode(&sig));
                    }
                    if let Some(path) = out_sig {
                        if let Err(e) = write_bytes_or_pem(&path, "ML-DSA SIGNATURE", &sig, pem) {
                            eprintln!("failed to write signature to {}: {}", path.display(), e);
                            // zeroize secret key buffer before exit
                            let mut sk_bytes = sk_bytes;
                            sk_bytes.zeroize();
                            std::process::exit(2);
                        }
                    }
                    // zeroize secret key buffer before returning
                    let mut sk_bytes = sk_bytes;
                    sk_bytes.zeroize();
                }
                Err(e) => {
                    // zeroize secret key buffer before exit
                    let mut sk_bytes = sk_bytes;
                    sk_bytes.zeroize();
                    eprintln!("error: {}", e);
                    std::process::exit(2);
                }
            }
        }
        Commands::SigVerify { alg, pk, in_path, sig } => {
            let pk_bytes = match fs::read(&pk) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("failed to read public key {}: {}", pk.display(), e);
                    std::process::exit(2);
                }
            };
            let msg = match fs::read(&in_path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("failed to read input {}: {}", in_path.display(), e);
                    std::process::exit(2);
                }
            };
            let sig_bytes = match fs::read(&sig) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("failed to read signature {}: {}", sig.display(), e);
                    std::process::exit(2);
                }
            };
            match quantumhttp_core::DilithiumSig::verify_with_alg(&alg, &pk_bytes, &msg, &sig_bytes) {
                Ok(valid) => {
                    println!("algorithm: {}", alg);
                    println!("valid: {}", valid);
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                    std::process::exit(2);
                }
            }
        }
        Commands::X509SelfSign { alg, pk, sk, subject_cn, days, out, pem } => {
            let pk_bytes = match fs::read(&pk) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("failed to read public key {}: {}", pk.display(), e);
                    std::process::exit(2);
                }
            };
            let sk_bytes = match fs::read(&sk) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("failed to read secret key {}: {}", sk.display(), e);
                    std::process::exit(2);
                }
            };
            match quantumhttp_core::X509::self_signed_der(&alg, &pk_bytes, &sk_bytes, &subject_cn, days) {
                Ok(der) => {
                    if pem {
                        let pem_str = encode_pem("CERTIFICATE", &der);
                        if let Err(e) = fs::write(&out, pem_str.as_bytes()) {
                            eprintln!("failed to write certificate to {}: {}", out.display(), e);
                            let mut sk_bytes = sk_bytes; sk_bytes.zeroize();
                            std::process::exit(2);
                        }
                    } else if let Err(e) = fs::write(&out, &der) {
                        eprintln!("failed to write certificate to {}: {}", out.display(), e);
                        let mut sk_bytes = sk_bytes; sk_bytes.zeroize();
                        std::process::exit(2);
                    }
                    println!("algorithm: {}", alg);
                    println!("subject_cn: {}", subject_cn);
                    println!("valid_days: {}", days);
                    if pem { println!("out: {} (PEM)", out.display()); } else { println!("out: {} (DER, {} bytes)", out.display(), der.len()); }
                    let mut sk_bytes = sk_bytes; sk_bytes.zeroize();
                }
                Err(e) => {
                    let mut sk_bytes = sk_bytes; sk_bytes.zeroize();
                    eprintln!("error: {}", e);
                    std::process::exit(2);
                }
            }
        }
        Commands::GenKey { alg, out_pk, out_sk, print_secret, pem } => {
            if alg.to_lowercase().starts_with("kyber") || alg.to_lowercase().starts_with("ml-kem") {
                match quantumhttp_core::KyberKem::generate_keypair_with_alg_secret(&alg) {
                    Ok((pk, sk)) => {
                        println!("algorithm: {}", alg);
                        println!("public_key_len: {} bytes", pk.len());
                        println!("secret_key_len: {} bytes", sk.as_ref().len());

                        // stdout base64
                        println!("public_key_b64: {}", B64.encode(&pk));
                        if print_secret {
                            let mut b64 = B64.encode(sk.as_ref());
                            println!("secret_key_b64: {}", b64);
                            b64.zeroize();
                        }

                        // optional file outputs
                        if let Some(path) = out_pk {
                            if let Err(e) = write_bytes_or_pem(&path, "KYBER PUBLIC KEY", &pk, pem) {
                                eprintln!("failed to write public key to {}: {}", path.display(), e);
                                std::process::exit(2);
                            }
                        }
                        if let Some(path) = out_sk {
                            if let Err(e) = write_bytes_or_pem(&path, "KYBER SECRET KEY", sk.as_ref(), pem) {
                                eprintln!("failed to write secret key to {}: {}", path.display(), e);
                                std::process::exit(2);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {}", e);
                        std::process::exit(2);
                    }
                }
            } else {
                eprintln!("unsupported algorithm: {}", alg);
                std::process::exit(2);
            }
        }
        Commands::KemEncap { alg, pk, out_ct, out_ss, print_secret, pem } => {
            if !(alg.to_lowercase().starts_with("kyber") || alg.to_lowercase().starts_with("ml-kem")) {
                eprintln!("unsupported algorithm: {}", alg);
                std::process::exit(2);
            }
            let pk_bytes = match fs::read(&pk) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("failed to read public key {}: {}", pk.display(), e);
                    std::process::exit(2);
                }
            };
            match quantumhttp_core::KyberKem::encapsulate_with_alg_secret(&alg, &pk_bytes) {
                Ok((ct, ss)) => {
                    println!("algorithm: {}", alg);
                    println!("ciphertext_len: {} bytes", ct.len());
                    println!("shared_secret_len: {} bytes", ss.as_ref().len());
                    println!("ciphertext_b64: {}", B64.encode(&ct));
                    if print_secret {
                        let mut b64 = B64.encode(ss.as_ref());
                        println!("shared_secret_b64: {}", b64);
                        b64.zeroize();
                    }
                    if let Some(path) = out_ct {
                        if let Err(e) = write_bytes_or_pem(&path, "KYBER CIPHERTEXT", &ct, pem) {
                            eprintln!("failed to write ciphertext to {}: {}", path.display(), e);
                            std::process::exit(2);
                        }
                    }
                    if let Some(path) = out_ss {
                        if let Err(e) = write_bytes_or_pem(&path, "SHARED SECRET", ss.as_ref(), pem) {
                            eprintln!("failed to write shared secret to {}: {}", path.display(), e);
                            std::process::exit(2);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                    std::process::exit(2);
                }
            }
        }
        Commands::KemDecap { alg, sk, ct, out_ss, print_secret, pem } => {
            if !(alg.to_lowercase().starts_with("kyber") || alg.to_lowercase().starts_with("ml-kem")) {
                eprintln!("unsupported algorithm: {}", alg);
                std::process::exit(2);
            }
            let sk_bytes = match fs::read(&sk) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("failed to read secret key {}: {}", sk.display(), e);
                    std::process::exit(2);
                }
            };
            let ct_bytes = match fs::read(&ct) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("failed to read ciphertext {}: {}", ct.display(), e);
                    std::process::exit(2);
                }
            };
            match quantumhttp_core::KyberKem::decapsulate_with_alg_secret(&alg, &sk_bytes, &ct_bytes) {
                Ok(ss) => {
                    println!("algorithm: {}", alg);
                    println!("shared_secret_len: {} bytes", ss.as_ref().len());
                    if print_secret {
                        let mut b64 = B64.encode(ss.as_ref());
                        println!("shared_secret_b64: {}", b64);
                        b64.zeroize();
                    }
                    if let Some(path) = out_ss {
                        if let Err(e) = write_bytes_or_pem(&path, "SHARED SECRET", ss.as_ref(), pem) {
                            eprintln!("failed to write shared secret to {}: {}", path.display(), e);
                            // zeroize secret key buffer before exit
                            let mut sk_bytes = sk_bytes;
                            sk_bytes.zeroize();
                            std::process::exit(2);
                        }
                    }
                    // zeroize secret key buffer before returning
                    let mut sk_bytes = sk_bytes;
                    sk_bytes.zeroize();
                }
                Err(e) => {
                    // zeroize secret key buffer before exit
                    let mut sk_bytes = sk_bytes;
                    sk_bytes.zeroize();
                    eprintln!("error: {}", e);
                    std::process::exit(2);
                }
            }
        }
    }

    Ok(())
}
