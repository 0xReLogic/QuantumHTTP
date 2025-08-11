//! QuantumHTTP core: safe Rust wrappers (stub for now).

pub mod status {
    /// Return whether liboqs is available (feature `oqs` compiled and found at build-time).
    pub fn oqs_available() -> bool {
        quantumhttp_oqs_sys::OQS_AVAILABLE
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("liboqs not available; build with `--features oqs` and ensure liboqs is installed")] 
    OqsUnavailable,
    #[error("failed to create KEM context")] 
    OqsCreateKemFailed,
    #[error("failed to generate keypair")] 
    OqsKeypairFailed,
    #[error("unsupported algorithm")] 
    UnsupportedAlgorithm,
    #[error("failed to encapsulate")] 
    OqsEncapsFailed,
    #[error("failed to decapsulate")] 
    OqsDecapsFailed,
    #[error("invalid public key length")] 
    InvalidPublicKeyLen,
    #[error("invalid secret key length")] 
    InvalidSecretKeyLen,
    #[error("invalid ciphertext length")] 
    InvalidCiphertextLen,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Placeholder KEM API (Kyber). Real implementation will appear under feature `oqs`.
pub struct KyberKem;

impl KyberKem {
    /// Default: Kyber/ML-KEM 512
    pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
        if !status::oqs_available() {
            return Err(Error::OqsUnavailable);
        }
        #[cfg(feature = "oqs")]
        unsafe {
            use std::ffi::CString;
            // Prefer ML-KEM-512 (new name), fallback to Kyber512 for older liboqs
            let mlkem = CString::new("ML-KEM-512").unwrap();
            let mut kem = quantumhttp_oqs_sys::OQS_KEM_new(mlkem.as_ptr());
            if kem.is_null() {
                let kyber = CString::new("Kyber512").unwrap();
                kem = quantumhttp_oqs_sys::OQS_KEM_new(kyber.as_ptr());
            }
            if kem.is_null() {
                return Err(Error::OqsCreateKemFailed);
            }

            // Read key sizes
            let pk_len = (*kem).length_public_key as usize;
            let sk_len = (*kem).length_secret_key as usize;
            let mut pk = vec![0u8; pk_len];
            let mut sk = vec![0u8; sk_len];

            // Generate keypair
            let status = quantumhttp_oqs_sys::OQS_KEM_keypair(kem, pk.as_mut_ptr(), sk.as_mut_ptr());

            // Free KEM context regardless of result
            quantumhttp_oqs_sys::OQS_KEM_free(kem);

            if status != 0 {
                return Err(Error::OqsKeypairFailed);
            }

            Ok((pk, sk))
        }

        #[cfg(not(feature = "oqs"))]
        {
            Err(Error::OqsUnavailable)
        }
    }

    /// Generate keypair for the specified Kyber/ML-KEM algorithm: kyber512|kyber768|kyber1024
    pub fn generate_keypair_with_alg(alg: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        if !status::oqs_available() {
            return Err(Error::OqsUnavailable);
        }
        #[cfg(feature = "oqs")]
        unsafe {
            use std::ffi::CString;
            let alg_norm = alg.to_ascii_lowercase();
            let (primary, fallback) = match alg_norm.as_str() {
                "kyber512" | "ml-kem-512" | "mlkem512" => ("ML-KEM-512", "Kyber512"),
                "kyber768" | "ml-kem-768" | "mlkem768" => ("ML-KEM-768", "Kyber768"),
                "kyber1024" | "ml-kem-1024" | "mlkem1024" => ("ML-KEM-1024", "Kyber1024"),
                _ => return Err(Error::UnsupportedAlgorithm),
            };

            let prim = CString::new(primary).unwrap();
            let mut kem = quantumhttp_oqs_sys::OQS_KEM_new(prim.as_ptr());
            if kem.is_null() {
                let fb = CString::new(fallback).unwrap();
                kem = quantumhttp_oqs_sys::OQS_KEM_new(fb.as_ptr());
            }
            if kem.is_null() {
                return Err(Error::OqsCreateKemFailed);
            }

            let pk_len = (*kem).length_public_key as usize;
            let sk_len = (*kem).length_secret_key as usize;
            let mut pk = vec![0u8; pk_len];
            let mut sk = vec![0u8; sk_len];

            let status = quantumhttp_oqs_sys::OQS_KEM_keypair(kem, pk.as_mut_ptr(), sk.as_mut_ptr());
            quantumhttp_oqs_sys::OQS_KEM_free(kem);
            if status != 0 {
                return Err(Error::OqsKeypairFailed);
            }
            Ok((pk, sk))
        }

        #[cfg(not(feature = "oqs"))]
        {
            Err(Error::OqsUnavailable)
        }
    }

    /// KEM encapsulation: given public key, produce (ciphertext, shared_secret)
    pub fn encapsulate_with_alg(alg: &str, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        if !status::oqs_available() {
            return Err(Error::OqsUnavailable);
        }
        #[cfg(feature = "oqs")]
        unsafe {
            use std::ffi::CString;
            let alg_norm = alg.to_ascii_lowercase();
            let (primary, fallback) = match alg_norm.as_str() {
                "kyber512" | "ml-kem-512" | "mlkem512" => ("ML-KEM-512", "Kyber512"),
                "kyber768" | "ml-kem-768" | "mlkem768" => ("ML-KEM-768", "Kyber768"),
                "kyber1024" | "ml-kem-1024" | "mlkem1024" => ("ML-KEM-1024", "Kyber1024"),
                _ => return Err(Error::UnsupportedAlgorithm),
            };
            let prim = CString::new(primary).unwrap();
            let mut kem = quantumhttp_oqs_sys::OQS_KEM_new(prim.as_ptr());
            if kem.is_null() {
                let fb = CString::new(fallback).unwrap();
                kem = quantumhttp_oqs_sys::OQS_KEM_new(fb.as_ptr());
            }
            if kem.is_null() {
                return Err(Error::OqsCreateKemFailed);
            }

            let pk_len = (*kem).length_public_key as usize;
            let ct_len = (*kem).length_ciphertext as usize;
            let ss_len = (*kem).length_shared_secret as usize;
            if public_key.len() != pk_len {
                quantumhttp_oqs_sys::OQS_KEM_free(kem);
                return Err(Error::InvalidPublicKeyLen);
            }
            let mut ct = vec![0u8; ct_len];
            let mut ss = vec![0u8; ss_len];

            let status = quantumhttp_oqs_sys::OQS_KEM_encaps(
                kem,
                ct.as_mut_ptr(),
                ss.as_mut_ptr(),
                public_key.as_ptr(),
            );
            quantumhttp_oqs_sys::OQS_KEM_free(kem);
            if status != 0 {
                return Err(Error::OqsEncapsFailed);
            }
            Ok((ct, ss))
        }

        #[cfg(not(feature = "oqs"))]
        {
            Err(Error::OqsUnavailable)
        }
    }

    /// KEM decapsulation: given secret key and ciphertext, recover shared_secret
    pub fn decapsulate_with_alg(alg: &str, secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if !status::oqs_available() {
            return Err(Error::OqsUnavailable);
        }
        #[cfg(feature = "oqs")]
        unsafe {
            use std::ffi::CString;
            let alg_norm = alg.to_ascii_lowercase();
            let (primary, fallback) = match alg_norm.as_str() {
                "kyber512" | "ml-kem-512" | "mlkem512" => ("ML-KEM-512", "Kyber512"),
                "kyber768" | "ml-kem-768" | "mlkem768" => ("ML-KEM-768", "Kyber768"),
                "kyber1024" | "ml-kem-1024" | "mlkem1024" => ("ML-KEM-1024", "Kyber1024"),
                _ => return Err(Error::UnsupportedAlgorithm),
            };
            let prim = CString::new(primary).unwrap();
            let mut kem = quantumhttp_oqs_sys::OQS_KEM_new(prim.as_ptr());
            if kem.is_null() {
                let fb = CString::new(fallback).unwrap();
                kem = quantumhttp_oqs_sys::OQS_KEM_new(fb.as_ptr());
            }
            if kem.is_null() {
                return Err(Error::OqsCreateKemFailed);
            }

            let sk_len = (*kem).length_secret_key as usize;
            let ct_len = (*kem).length_ciphertext as usize;
            let ss_len = (*kem).length_shared_secret as usize;
            if secret_key.len() != sk_len {
                quantumhttp_oqs_sys::OQS_KEM_free(kem);
                return Err(Error::InvalidSecretKeyLen);
            }
            if ciphertext.len() != ct_len {
                quantumhttp_oqs_sys::OQS_KEM_free(kem);
                return Err(Error::InvalidCiphertextLen);
            }
            let mut ss = vec![0u8; ss_len];
            let status = quantumhttp_oqs_sys::OQS_KEM_decaps(
                kem,
                ss.as_mut_ptr(),
                ciphertext.as_ptr(),
                secret_key.as_ptr(),
            );
            quantumhttp_oqs_sys::OQS_KEM_free(kem);
            if status != 0 {
                return Err(Error::OqsDecapsFailed);
            }
            Ok(ss)
        }

        #[cfg(not(feature = "oqs"))]
        {
            Err(Error::OqsUnavailable)
        }
    }
}
