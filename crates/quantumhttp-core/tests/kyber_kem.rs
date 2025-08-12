use quantumhttp_core::{status, Error, KyberKem};

fn run_roundtrip_for_alg(alg: &str) {
    if !status::oqs_available() {
        eprintln!("oqs not available; skipping tests for {alg}");
        return;
    }

    // Keypair
    let (pk, sk) = match KyberKem::generate_keypair_with_alg(alg) {
        Ok(v) => v,
        Err(Error::OqsUnavailable) => {
            eprintln!("oqs unavailable at runtime; skipping {alg}");
            return;
        }
        Err(e) => panic!("keypair failed for {alg}: {e:?}"),
    };
    assert!(!pk.is_empty() && !sk.is_empty());

    // Encapsulate
    let (ct, ss1) = KyberKem::encapsulate_with_alg(alg, &pk).expect("encapsulate failed");
    assert!(!ct.is_empty() && !ss1.is_empty());

    // Decapsulate
    let ss2 = KyberKem::decapsulate_with_alg(alg, &sk, &ct).expect("decapsulate failed");
    assert_eq!(ss1, ss2, "shared secrets must match for {alg}");

    // Error cases: length validation
    // Invalid public key length
    if pk.len() > 0 {
        let mut bad_pk = pk.clone();
        bad_pk.pop();
        let err = KyberKem::encapsulate_with_alg(alg, &bad_pk).unwrap_err();
        assert!(matches!(err, Error::InvalidPublicKeyLen));
    }

    // Invalid secret key length
    if sk.len() > 0 {
        let mut bad_sk = sk.clone();
        bad_sk.pop();
        let err = KyberKem::decapsulate_with_alg(alg, &bad_sk, &ct).unwrap_err();
        assert!(matches!(err, Error::InvalidSecretKeyLen));
    }

    // Invalid ciphertext length
    if ct.len() > 0 {
        let mut bad_ct = ct.clone();
        bad_ct.pop();
        let err = KyberKem::decapsulate_with_alg(alg, &sk, &bad_ct).unwrap_err();
        assert!(matches!(err, Error::InvalidCiphertextLen));
    }
}

#[test]
fn kyber512_roundtrip_and_errors() {
    run_roundtrip_for_alg("kyber512");
}

#[test]
fn kyber768_roundtrip_and_errors() {
    run_roundtrip_for_alg("kyber768");
}

#[test]
fn kyber1024_roundtrip_and_errors() {
    run_roundtrip_for_alg("kyber1024");
}
