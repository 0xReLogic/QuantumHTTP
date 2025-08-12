//! Integration test for X.509 self-signed certificate (ML-DSA/Dilithium)

#[test]
fn x509_self_signed_mldsa44() {
    if !quantumhttp_core::status::oqs_available() {
        eprintln!("liboqs unavailable; skipping x509_self_signed_mldsa44");
        return;
    }

    // Generate ML-DSA-44 keypair
    let (pk, sk) = quantumhttp_core::DilithiumSig::generate_keypair_with_alg("ml-dsa-44")
        .expect("keypair generation should succeed");

    // Build self-signed certificate
    let der = quantumhttp_core::X509::self_signed_der(
        "ml-dsa-44",
        &pk,
        &sk,
        "localhost",
        7,
    ).expect("self-signed certificate generation should succeed");

    // Parse DER
    use der::Decode;
    use x509_cert::certificate::Certificate;
    let cert = Certificate::from_der(&der).expect("DER should parse as Certificate");

    // Basic invariants
    assert_eq!(cert.tbs_certificate.issuer, cert.tbs_certificate.subject, "issuer == subject for self-signed");

    // OID checks (private, as decided):
    let spki_expected = spki::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1.44");
    let sig_expected  = spki::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.2.44");
    assert_eq!(cert.tbs_certificate.subject_public_key_info.algorithm.oid, spki_expected, "SPKI alg OID");
    assert_eq!(cert.signature_algorithm.oid, sig_expected, "signature alg OID");

    // Public key matches
    let bitstr = &cert.tbs_certificate.subject_public_key_info.subject_public_key;
    let pk_bits: Vec<u8> = bitstr
        .as_bytes()
        .expect("subjectPublicKey must be whole-byte aligned with 0 unused bits")
        .to_vec();
    assert_eq!(pk_bits, pk, "embedded public key must match input pk");

    // Extensions present and correct
    let exts = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .expect("v3 cert should include extensions");

    // Subject Alternative Name: DNS:localhost
    use x509_cert::ext::pkix::SubjectAltName;
    use x509_cert::ext::pkix::name::GeneralName;
    let san_oid = spki::ObjectIdentifier::new_unwrap("2.5.29.17");
    let san_ext = exts.iter().find(|e| e.extn_id == san_oid).expect("SAN ext present");
    let san = SubjectAltName::from_der(san_ext.extn_value.as_bytes()).expect("SAN decode");
    let names: Vec<GeneralName> = san.into();
    assert!(names.iter().any(|gn| matches!(gn, GeneralName::DnsName(s) if s.as_str() == "localhost")), "SAN must include DNS:localhost");

    // Key Usage: digitalSignature
    use x509_cert::ext::pkix::KeyUsage;
    let ku_oid = spki::ObjectIdentifier::new_unwrap("2.5.29.15");
    let ku_ext = exts.iter().find(|e| e.extn_id == ku_oid).expect("KeyUsage ext present");
    let ku = KeyUsage::from_der(ku_ext.extn_value.as_bytes()).expect("KeyUsage decode");
    assert!(ku.digital_signature(), "KeyUsage.digitalSignature must be set");

    // Extended Key Usage: serverAuth
    use x509_cert::ext::pkix::ExtendedKeyUsage;
    let eku_oid = spki::ObjectIdentifier::new_unwrap("2.5.29.37");
    let eku_ext = exts.iter().find(|e| e.extn_id == eku_oid).expect("ExtendedKeyUsage ext present");
    let eku = ExtendedKeyUsage::from_der(eku_ext.extn_value.as_bytes()).expect("EKU decode");
    let server_auth = spki::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
    let purposes: Vec<spki::ObjectIdentifier> = eku.into();
    assert!(purposes.iter().any(|oid| *oid == server_auth), "EKU must include serverAuth");

    // Basic Constraints: CA=false
    use x509_cert::ext::pkix::constraints::BasicConstraints;
    let bc_oid = spki::ObjectIdentifier::new_unwrap("2.5.29.19");
    let bc_ext = exts.iter().find(|e| e.extn_id == bc_oid).expect("BasicConstraints ext present");
    let bc = BasicConstraints::from_der(bc_ext.extn_value.as_bytes()).expect("BasicConstraints decode");
    assert!(!bc.ca, "BasicConstraints.ca must be false for end-entity cert");
}
