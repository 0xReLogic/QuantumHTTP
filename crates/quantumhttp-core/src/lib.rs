//! QuantumHTTP core: safe Rust wrappers (stub for now).

pub mod status {
    /// Return whether liboqs is available (feature `oqs` compiled and found at build-time).
    pub fn oqs_available() -> bool {
        quantumhttp_oqs_sys::OQS_AVAILABLE
    }
}

impl DilithiumSig {
    /// Generate keypair for the specified Dilithium/ML-DSA algorithm: dilithium2|3|5 or ml-dsa-44|65|87
    pub fn generate_keypair_with_alg(alg: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        if !status::oqs_available() {
            return Err(Error::OqsUnavailable);
        }
        #[cfg(feature = "oqs")]
        unsafe {
            use std::ffi::CString;
            let alg_norm = alg.to_ascii_lowercase();
            let (primary, fallback) = match alg_norm.as_str() {
                // New ML-DSA names with fallbacks to Dilithium
                "ml-dsa-44" | "dilithium2" => ("ML-DSA-44", "Dilithium2"),
                "ml-dsa-65" | "dilithium3" => ("ML-DSA-65", "Dilithium3"),
                "ml-dsa-87" | "dilithium5" => ("ML-DSA-87", "Dilithium5"),
                _ => return Err(Error::UnsupportedAlgorithm),
            };

            let prim = CString::new(primary).unwrap();
            let mut sig = quantumhttp_oqs_sys::OQS_SIG_new(prim.as_ptr());
            if sig.is_null() {
                let fb = CString::new(fallback).unwrap();
                sig = quantumhttp_oqs_sys::OQS_SIG_new(fb.as_ptr());
            }
            if sig.is_null() {
                return Err(Error::OqsCreateSigFailed);
            }

            let pk_len = (*sig).length_public_key as usize;
            let sk_len = (*sig).length_secret_key as usize;
            let mut pk = vec![0u8; pk_len];
            let mut sk = vec![0u8; sk_len];

            let status = quantumhttp_oqs_sys::OQS_SIG_keypair(sig, pk.as_mut_ptr(), sk.as_mut_ptr());
            quantumhttp_oqs_sys::OQS_SIG_free(sig);
            if status != 0 {
                #[allow(unused_mut)]
                #[cfg(feature = "oqs")]
                {
                    use zeroize::Zeroize;
                    sk.zeroize();
                    pk.zeroize();
                }
                return Err(Error::OqsSigKeypairFailed);
            }
            Ok((pk, sk))
        }

        #[cfg(not(feature = "oqs"))]
        {
            let _ = alg;
            Err(Error::OqsUnavailable)
        }
    }

    /// Same as `generate_keypair_with_alg` but returns secret key wrapped in `SecretKey`.
    pub fn generate_keypair_with_alg_secret(alg: &str) -> Result<(Vec<u8>, SecretKey)> {
        let (pk, sk) = Self::generate_keypair_with_alg(alg)?;
        Ok((pk, SecretKey(sk)))
    }

    /// Sign message with the specified algorithm and secret key.
    pub fn sign_with_alg(alg: &str, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        if !status::oqs_available() {
            return Err(Error::OqsUnavailable);
        }
        #[cfg(feature = "oqs")]
        unsafe {
            use std::ffi::CString;
            let alg_norm = alg.to_ascii_lowercase();
            let (primary, fallback) = match alg_norm.as_str() {
                "ml-dsa-44" | "dilithium2" => ("ML-DSA-44", "Dilithium2"),
                "ml-dsa-65" | "dilithium3" => ("ML-DSA-65", "Dilithium3"),
                "ml-dsa-87" | "dilithium5" => ("ML-DSA-87", "Dilithium5"),
                _ => return Err(Error::UnsupportedAlgorithm),
            };

            let prim = CString::new(primary).unwrap();
            let mut sig = quantumhttp_oqs_sys::OQS_SIG_new(prim.as_ptr());
            if sig.is_null() {
                let fb = CString::new(fallback).unwrap();
                sig = quantumhttp_oqs_sys::OQS_SIG_new(fb.as_ptr());
            }
            if sig.is_null() {
                return Err(Error::OqsCreateSigFailed);
            }

            let sk_len = (*sig).length_secret_key as usize;
            let sig_len_max = (*sig).length_signature as usize;
            if secret_key.len() != sk_len {
                quantumhttp_oqs_sys::OQS_SIG_free(sig);
                return Err(Error::InvalidSecretKeyLen);
            }

            let mut sig_buf = vec![0u8; sig_len_max];
            let mut sig_len_written: usize = 0;
            let status = quantumhttp_oqs_sys::OQS_SIG_sign(
                sig,
                sig_buf.as_mut_ptr(),
                &mut sig_len_written as *mut usize,
                message.as_ptr(),
                message.len(),
                secret_key.as_ptr(),
            );
            quantumhttp_oqs_sys::OQS_SIG_free(sig);
            if status != 0 {
                return Err(Error::OqsSignFailed);
            }
            sig_buf.truncate(sig_len_written);
            Ok(sig_buf)
        }

        #[cfg(not(feature = "oqs"))]
        {
            let _ = (alg, secret_key, message);
            Err(Error::OqsUnavailable)
        }
    }

    /// Verify signature; returns Ok(true) if valid, Ok(false) if invalid.
    pub fn verify_with_alg(alg: &str, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        if !status::oqs_available() {
            return Err(Error::OqsUnavailable);
        }
        #[cfg(feature = "oqs")]
        unsafe {
            use std::ffi::CString;
            let alg_norm = alg.to_ascii_lowercase();
            let (primary, fallback) = match alg_norm.as_str() {
                "ml-dsa-44" | "dilithium2" => ("ML-DSA-44", "Dilithium2"),
                "ml-dsa-65" | "dilithium3" => ("ML-DSA-65", "Dilithium3"),
                "ml-dsa-87" | "dilithium5" => ("ML-DSA-87", "Dilithium5"),
                _ => return Err(Error::UnsupportedAlgorithm),
            };

            let prim = CString::new(primary).unwrap();
            let mut sig = quantumhttp_oqs_sys::OQS_SIG_new(prim.as_ptr());
            if sig.is_null() {
                let fb = CString::new(fallback).unwrap();
                sig = quantumhttp_oqs_sys::OQS_SIG_new(fb.as_ptr());
            }
            if sig.is_null() {
                return Err(Error::OqsCreateSigFailed);
            }

            let pk_len = (*sig).length_public_key as usize;
            let _sk_len = (*sig).length_secret_key as usize;
            let _sig_len_max = (*sig).length_signature as usize;
            if public_key.len() != pk_len {
                quantumhttp_oqs_sys::OQS_SIG_free(sig);
                return Err(Error::InvalidPublicKeyLen);
            }

            let status = quantumhttp_oqs_sys::OQS_SIG_verify(
                sig,
                message.as_ptr(),
                message.len(),
                signature.as_ptr(),
                signature.len(),
                public_key.as_ptr(),
            );
            quantumhttp_oqs_sys::OQS_SIG_free(sig);
            Ok(status == 0)
        }

        #[cfg(not(feature = "oqs"))]
        {
            let _ = (alg, public_key, message, signature);
            Err(Error::OqsUnavailable)
        }
    }
}

#[cfg(feature = "oqs")]
use zeroize::Zeroize;

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
    #[error("failed to create SIG context")] 
    OqsCreateSigFailed,
    #[error("failed to generate signature keypair")] 
    OqsSigKeypairFailed,
    #[error("failed to sign message")] 
    OqsSignFailed,
    #[error("signature verification failed")] 
    OqsVerifyFailed,
    #[error("invalid signature length")] 
    InvalidSignatureLen,
    #[error("x509 self-signed certificate generation not yet implemented")] 
    X509NotImplemented,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Placeholder KEM API (Kyber). Real implementation will appear under feature `oqs`.
pub struct KyberKem;

/// Placeholder SIG API (Dilithium/ML-DSA)
pub struct DilithiumSig;

/// Secret material wrappers that zeroize on drop.
#[derive(Debug, Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SecretKey(pub Vec<u8>);

impl SecretKey {
    pub fn into_bytes(mut self) -> Vec<u8> { std::mem::take(&mut self.0) }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

#[derive(Debug, Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SharedSecret(pub Vec<u8>);

impl SharedSecret {
    pub fn into_bytes(mut self) -> Vec<u8> { std::mem::take(&mut self.0) }
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

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
                // Zeroize sensitive buffers before returning error
                sk.zeroize();
                pk.zeroize();
                return Err(Error::OqsKeypairFailed);
            }

            Ok((pk, sk))
        }

        #[cfg(not(feature = "oqs"))]
        {
            Err(Error::OqsUnavailable)
        }
    }

    /// Same as `generate_keypair_with_alg` but returns secret key wrapped in `SecretKey`.
    pub fn generate_keypair_with_alg_secret(alg: &str) -> Result<(Vec<u8>, SecretKey)> {
        let (pk, sk) = Self::generate_keypair_with_alg(alg)?;
        Ok((pk, SecretKey(sk)))
    }

    /// Same as `generate_keypair` but returns secret key wrapped in `SecretKey` (auto-zeroize on drop).
    pub fn generate_keypair_secret() -> Result<(Vec<u8>, SecretKey)> {
        let (pk, sk) = Self::generate_keypair()?;
        Ok((pk, SecretKey(sk)))
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
                // Zeroize sensitive buffers before returning error
                sk.zeroize();
                pk.zeroize();
                return Err(Error::OqsKeypairFailed);
            }
            Ok((pk, sk))
        }

        #[cfg(not(feature = "oqs"))]
        {
            let _ = alg;
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
                // Zeroize sensitive buffers before returning error
                ss.zeroize();
                ct.zeroize();
                return Err(Error::OqsEncapsFailed);
            }
            Ok((ct, ss))
        }

        #[cfg(not(feature = "oqs"))]
        {
            let _ = (alg, public_key);
            Err(Error::OqsUnavailable)
        }
    }

    /// Same as `encapsulate_with_alg` but returns shared secret wrapped in `SharedSecret` (auto-zeroize on drop).
    pub fn encapsulate_with_alg_secret(alg: &str, public_key: &[u8]) -> Result<(Vec<u8>, SharedSecret)> {
        let (ct, ss) = Self::encapsulate_with_alg(alg, public_key)?;
        Ok((ct, SharedSecret(ss)))
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
                // Zeroize sensitive buffers before returning error
                ss.zeroize();
                return Err(Error::OqsDecapsFailed);
            }
            Ok(ss)
        }

        #[cfg(not(feature = "oqs"))]
        {
            let _ = (alg, secret_key, ciphertext);
            Err(Error::OqsUnavailable)
        }
    }

    /// Same as `decapsulate_with_alg` but returns shared secret wrapped in `SharedSecret`.
    pub fn decapsulate_with_alg_secret(alg: &str, secret_key: &[u8], ciphertext: &[u8]) -> Result<SharedSecret> {
        let ss = Self::decapsulate_with_alg(alg, secret_key, ciphertext)?;
        Ok(SharedSecret(ss))
    }
}

/// X.509 related helpers
pub struct X509;

impl X509 {
    /// Map ML-DSA alg string to private OIDs (spki alg, sig alg)
    fn mldsa_private_oids(alg: &str) -> Result<(spki::ObjectIdentifier, spki::ObjectIdentifier)> {
        let a = alg.to_ascii_lowercase();
        match a.as_str() {
            "ml-dsa-44" | "dilithium2" => Ok((
                spki::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1.44"),
                spki::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.2.44"),
            )),
            "ml-dsa-65" | "dilithium3" => Ok((
                spki::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1.65"),
                spki::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.2.65"),
            )),
            "ml-dsa-87" | "dilithium5" => Ok((
                spki::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1.87"),
                spki::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.2.87"),
            )),
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }

    /// Build a minimal self-signed X.509 certificate and return DER bytes.
    pub fn self_signed_der(
        alg: &str,
        public_key: &[u8],
        secret_key: &[u8],
        subject_cn: &str,
        days: u32,
    ) -> Result<Vec<u8>> {
        if !status::oqs_available() {
            return Err(Error::OqsUnavailable);
        }

        // OIDs
        let (spki_oid, sig_oid) = Self::mldsa_private_oids(alg)?;

        // Build Name: CN=<subject_cn>
        use core::str::FromStr;
        use x509_cert::name::Name;
        let name = Name::from_str(&format!("CN={}", subject_cn))
            .map_err(|_| Error::X509NotImplemented)?; // fallback error kind for now

        // Validity window: now-5m .. now+days
        use std::time::{Duration, SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::from_secs(0));
        let not_before_secs = now.saturating_sub(Duration::from_secs(300)).as_secs();
        let not_after_secs = now.saturating_add(Duration::from_secs(days as u64 * 86_400)).as_secs();
        use der::asn1::GeneralizedTime;
        let not_before = x509_cert::time::Time::GeneralTime(
            GeneralizedTime::from_unix_duration(Duration::from_secs(not_before_secs))
                .map_err(|_| Error::X509NotImplemented)?,
        );
        let not_after = x509_cert::time::Time::GeneralTime(
            GeneralizedTime::from_unix_duration(Duration::from_secs(not_after_secs))
                .map_err(|_| Error::X509NotImplemented)?,
        );
        let validity = x509_cert::time::Validity { not_before, not_after };

        // Serial number: derive pseudo-random from public key (first 20 bytes, force positive)
        let mut serial_bytes = [0u8; 20];
        for (i, b) in public_key.iter().take(20).enumerate() { serial_bytes[i] = *b; }
        if serial_bytes.iter().all(|&b| b == 0) { serial_bytes[0] = 1; }
        serial_bytes[0] &= 0x7F; // ensure positive
        let serial = x509_cert::serial_number::SerialNumber::new(&serial_bytes)
            .map_err(|_| Error::X509NotImplemented)?;

        // SubjectPublicKeyInfo
        use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
        let spki_alg = AlgorithmIdentifierOwned { oid: spki_oid, parameters: None };
        let subject_public_key = der::asn1::BitString::new(0, public_key.to_vec())
            .map_err(|_| Error::X509NotImplemented)?;
        let spki = SubjectPublicKeyInfoOwned { algorithm: spki_alg.clone(), subject_public_key };

        // Default X.509 v3 extensions
        use der::asn1::{Ia5String, Ia5StringRef};
        use x509_cert::ext::{AsExtension, Extension};
        use x509_cert::ext::pkix::{ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName};
        use x509_cert::ext::pkix::constraints::BasicConstraints;
        use x509_cert::ext::pkix::name::GeneralName;

        let mut extensions: Vec<Extension> = Vec::new();

        // Subject Alternative Name: DNSName = subject CN
        let dns_ref = Ia5StringRef::new(&subject_cn)
            .map_err(|_| Error::X509NotImplemented)?;
        let dns = Ia5String::from(dns_ref);
        let san = SubjectAltName::from(vec![GeneralName::DnsName(dns)]);
        extensions.push(
            san.to_extension(&name, &extensions)
                .map_err(|_| Error::X509NotImplemented)?,
        );

        // Key Usage: digitalSignature
        let ku = KeyUsage(KeyUsages::DigitalSignature.into());
        extensions.push(
            ku.to_extension(&name, &extensions)
                .map_err(|_| Error::X509NotImplemented)?,
        );

        // Extended Key Usage: serverAuth (1.3.6.1.5.5.7.3.1)
        let server_auth = spki::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
        let eku = ExtendedKeyUsage::from(vec![server_auth]);
        extensions.push(
            eku.to_extension(&name, &extensions)
                .map_err(|_| Error::X509NotImplemented)?,
        );

        // Basic Constraints: CA = false (end-entity)
        let bc = BasicConstraints { ca: false, path_len_constraint: None };
        extensions.push(
            bc.to_extension(&name, &extensions)
                .map_err(|_| Error::X509NotImplemented)?,
        );

        // TBS Certificate
        use x509_cert::certificate::{Certificate, TbsCertificate};
        let tbs = TbsCertificate {
            version: x509_cert::certificate::Version::V3,
            serial_number: serial,
            signature: AlgorithmIdentifierOwned { oid: sig_oid, parameters: None },
            issuer: name.clone(),
            validity,
            subject: name,
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(extensions),
        };

        // DER encode TBS, sign it with ML-DSA
        use der::Encode;
        let tbs_der = tbs.to_der().map_err(|_| Error::X509NotImplemented)?;
        let signature = crate::DilithiumSig::sign_with_alg(alg, secret_key, &tbs_der)?;
        let signature_bitstring = der::asn1::BitString::new(0, signature)
            .map_err(|_| Error::X509NotImplemented)?;

        // Final certificate
        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: AlgorithmIdentifierOwned { oid: sig_oid, parameters: None },
            signature: signature_bitstring,
        };
        let cert_der = cert.to_der().map_err(|_| Error::X509NotImplemented)?;
        Ok(cert_der)
    }
}
