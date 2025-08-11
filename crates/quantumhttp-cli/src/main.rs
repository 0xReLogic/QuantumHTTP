use clap::{Parser, Subcommand};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use std::fs;
use std::path::PathBuf;

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
    },
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
        Commands::GenKey { alg, out_pk, out_sk, print_secret } => {
            if alg.to_lowercase().starts_with("kyber") || alg.to_lowercase().starts_with("ml-kem") {
                match quantumhttp_core::KyberKem::generate_keypair_with_alg(&alg) {
                    Ok((pk, sk)) => {
                        println!("algorithm: {}", alg);
                        println!("public_key_len: {} bytes", pk.len());
                        println!("secret_key_len: {} bytes", sk.len());

                        // stdout base64
                        println!("public_key_b64: {}", B64.encode(&pk));
                        if print_secret {
                            println!("secret_key_b64: {}", B64.encode(&sk));
                        }

                        // optional file outputs (raw bytes)
                        if let Some(path) = out_pk {
                            if let Err(e) = fs::write(&path, &pk) {
                                eprintln!("failed to write public key to {}: {}", path.display(), e);
                                std::process::exit(2);
                            }
                        }
                        if let Some(path) = out_sk {
                            if let Err(e) = fs::write(&path, &sk) {
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
        Commands::KemEncap { alg, pk, out_ct, out_ss, print_secret } => {
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
            match quantumhttp_core::KyberKem::encapsulate_with_alg(&alg, &pk_bytes) {
                Ok((ct, ss)) => {
                    println!("algorithm: {}", alg);
                    println!("ciphertext_len: {} bytes", ct.len());
                    println!("shared_secret_len: {} bytes", ss.len());
                    println!("ciphertext_b64: {}", B64.encode(&ct));
                    if print_secret {
                        println!("shared_secret_b64: {}", B64.encode(&ss));
                    }
                    if let Some(path) = out_ct {
                        if let Err(e) = fs::write(&path, &ct) {
                            eprintln!("failed to write ciphertext to {}: {}", path.display(), e);
                            std::process::exit(2);
                        }
                    }
                    if let Some(path) = out_ss {
                        if let Err(e) = fs::write(&path, &ss) {
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
        Commands::KemDecap { alg, sk, ct, out_ss, print_secret } => {
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
            match quantumhttp_core::KyberKem::decapsulate_with_alg(&alg, &sk_bytes, &ct_bytes) {
                Ok(ss) => {
                    println!("algorithm: {}", alg);
                    println!("shared_secret_len: {} bytes", ss.len());
                    if print_secret {
                        println!("shared_secret_b64: {}", B64.encode(&ss));
                    }
                    if let Some(path) = out_ss {
                        if let Err(e) = fs::write(&path, &ss) {
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
    }

    Ok(())
}
