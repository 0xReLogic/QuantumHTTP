use quantumhttp_core::{status, DilithiumSig, Error};

fn run_sig_roundtrip_and_errors(alg: &str) {
    if !status::oqs_available() {
        eprintln!("oqs not available; skipping tests for {alg}");
        return;
    }

    // Keypair
    let (pk, sk) = match DilithiumSig::generate_keypair_with_alg(alg) {
        Ok(v) => v,
        Err(Error::OqsUnavailable) => {
            eprintln!("oqs unavailable at runtime; skipping {alg}");
            return;
        }
        Err(e) => panic!("keypair failed for {alg}: {e:?}"),
    };
    assert!(!pk.is_empty() && !sk.is_empty());

    // Message
    let msg = b"quantumhttp::dilithium::roundtrip".to_vec();

    // Sign
    let sig = DilithiumSig::sign_with_alg(alg, &sk, &msg).expect("sign failed");
    assert!(!sig.is_empty());

    // Verify OK
    let valid = DilithiumSig::verify_with_alg(alg, &pk, &msg, &sig).expect("verify failed");
    assert!(valid, "signature must be valid for {alg}");

    // Error: invalid public key length
    if pk.len() > 0 {
        let mut bad_pk = pk.clone();
        bad_pk.pop();
        let err = DilithiumSig::verify_with_alg(alg, &bad_pk, &msg, &sig).unwrap_err();
        assert!(matches!(err, Error::InvalidPublicKeyLen));
    }

    // Error: invalid secret key length for signing
    if sk.len() > 0 {
        let mut bad_sk = sk.clone();
        bad_sk.pop();
        let err = DilithiumSig::sign_with_alg(alg, &bad_sk, &msg).unwrap_err();
        assert!(matches!(err, Error::InvalidSecretKeyLen));
    }

    // Negative: tamper signature -> verify should return Ok(false)
    if !sig.is_empty() {
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0x01;
        let is_valid = DilithiumSig::verify_with_alg(alg, &pk, &msg, &bad_sig).expect("verify (tampered) failed");
        assert!(!is_valid, "tampered signature must be invalid for {alg}");
    }

    // Negative: tamper message -> verify should return Ok(false)
    let mut bad_msg = msg.clone();
    bad_msg.push(0u8);
    let is_valid = DilithiumSig::verify_with_alg(alg, &pk, &bad_msg, &sig).expect("verify (wrong message) failed");
    assert!(!is_valid, "wrong message must yield invalid signature for {alg}");
}

#[test]
fn mldsa44_roundtrip_and_errors() {
    run_sig_roundtrip_and_errors("ml-dsa-44");
}

#[test]
fn mldsa65_roundtrip_and_errors() {
    run_sig_roundtrip_and_errors("ml-dsa-65");
}

#[test]
fn mldsa87_roundtrip_and_errors() {
    run_sig_roundtrip_and_errors("ml-dsa-87");
}
