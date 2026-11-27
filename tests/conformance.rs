//! WebAuthn Level 3 conformance tests, run for every signature algorithm
//! the build supports (ES256, EdDSA, RS256, and ML-DSA-44/65/87 with the
//! `pqc` feature) and for every backup-flag combination.

mod support;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use ciborium::value::Value as Cbor;
use passkey_auth::{Error, PasskeyCredential, Webauthn};
use support::*;

fn webauthn() -> Webauthn {
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    #[cfg(feature = "pqc")]
    let wa = wa.allow_ml_dsa(true);
    wa
}

fn register(
    wa: &Webauthn,
    authenticator: &Authenticator,
) -> passkey_auth::Result<PasskeyCredential> {
    let (challenge, state) = wa.start_registration(b"user-1", "alice", "Alice", &[]);
    wa.finish_registration(&state, &authenticator.register(&challenge))
}

fn authenticate(
    wa: &Webauthn,
    authenticator: &mut Authenticator,
    credential: &PasskeyCredential,
) -> passkey_auth::Result<passkey_auth::AuthSuccess> {
    let (challenge, state) = wa.start_authentication(std::slice::from_ref(&credential.id));
    wa.finish_authentication(&state, &authenticator.assert(&challenge), credential)
}

// ---------- per algorithm --------------------------------------------------

#[test]
fn register_and_authenticate_every_algorithm() {
    let wa = webauthn();
    for alg in Alg::all() {
        let mut authenticator = Authenticator::new(alg, 9);
        let credential =
            register(&wa, &authenticator).unwrap_or_else(|e| panic!("{}: {e}", alg.name()));
        assert_eq!(
            credential.public_key_cose.as_bytes(),
            authenticator.cose_public_key()
        );
        for expected in 1..=3 {
            let outcome = authenticate(&wa, &mut authenticator, &credential)
                .unwrap_or_else(|e| panic!("{}: {e}", alg.name()));
            assert_eq!(outcome.new_counter, expected);
        }
    }
}

#[test]
fn packed_self_attestation_every_algorithm() {
    let wa = webauthn();
    for alg in Alg::all() {
        let authenticator = Authenticator::new(alg, 10);
        let (challenge, state) = wa.start_registration(b"user-1", "alice", "Alice", &[]);
        wa.finish_registration(&state, &authenticator.register_packed_self(&challenge))
            .unwrap_or_else(|e| panic!("{}: {e}", alg.name()));
    }
}

#[test]
fn tampered_signature_rejected_every_algorithm() {
    let wa = webauthn();
    for alg in Alg::all() {
        let mut authenticator = Authenticator::new(alg, 11);
        let credential = register(&wa, &authenticator).unwrap();
        let (challenge, state) = wa.start_authentication(std::slice::from_ref(&credential.id));
        let mut response = authenticator.assert(&challenge);
        let mut sig = B64URL.decode(&response.signature).unwrap();
        let last = sig.len() - 1;
        sig[last] ^= 0x01;
        response.signature = B64URL.encode(&sig);
        let err = wa
            .finish_authentication(&state, &response, &credential)
            .unwrap_err();
        assert!(
            matches!(err, Error::BadSignature),
            "{}: {err:?}",
            alg.name()
        );

        response.signature = B64URL.encode(&sig[..last]);
        let err = wa
            .finish_authentication(&state, &response, &credential)
            .unwrap_err();
        assert!(
            matches!(err, Error::BadSignature),
            "{} truncated: {err:?}",
            alg.name()
        );
    }
}

#[test]
fn signature_from_another_key_rejected_every_algorithm() {
    let wa = webauthn();
    for alg in Alg::all() {
        let authenticator = Authenticator::new(alg, 12);
        let credential = register(&wa, &authenticator).unwrap();
        let mut impostor = Authenticator::new(alg, 13);
        if alg == Alg::Rs256 {
            impostor = Authenticator::with_key(rsa_key(RSA_4096), 13);
        }
        impostor.credential_id = authenticator.credential_id;
        let err = authenticate(&wa, &mut impostor, &credential).unwrap_err();
        assert!(
            matches!(err, Error::BadSignature),
            "{}: {err:?}",
            alg.name()
        );
    }
}

#[test]
fn packed_self_attestation_alg_mismatch_rejected() {
    let wa = webauthn();
    let authenticator = Authenticator::new(Alg::Es256, 14);
    let (challenge, state) = wa.start_registration(b"user-1", "alice", "Alice", &[]);
    let client_data = client_data_json("webauthn.create", &challenge.challenge, ORIGIN);
    let auth_data = authenticator.registration_auth_data();
    let sig = authenticator.sign(&signed_message(&auth_data, &client_data));
    let stmt = Cbor::Map(vec![
        (text("alg"), int(-257)),
        (text("sig"), Cbor::Bytes(sig)),
    ]);
    let response = registration_response(
        &authenticator.credential_id,
        attestation_object("packed", stmt, auth_data),
        &client_data,
    );
    assert!(wa.finish_registration(&state, &response).is_err());
}

// ---------- RS256 key policy -------------------------------------------------

#[test]
fn rs256_accepts_4096_bit_keys() {
    let wa = webauthn();
    let mut authenticator = Authenticator::with_key(rsa_key(RSA_4096), 1);
    let credential = register(&wa, &authenticator).unwrap();
    authenticate(&wa, &mut authenticator, &credential).unwrap();
}

#[test]
fn rs256_refuses_1024_bit_keys() {
    let wa = webauthn();
    let authenticator = Authenticator::with_key(rsa_key(RSA_1024), 1);
    let err = register(&wa, &authenticator).unwrap_err();
    assert!(matches!(err, Error::Cbor(_)), "{err:?}");
}

#[test]
fn stored_rs256_key_with_bad_exponent_is_refused_at_authentication() {
    let wa = webauthn();
    let mut authenticator = Authenticator::new(Alg::Rs256, 1);
    let mut credential = register(&wa, &authenticator).unwrap();
    // Swap e = 65537 (0x010001, the last 3 bytes) for e = 65536.
    let mut cose = credential.public_key_cose.as_bytes().to_vec();
    let n = cose.len();
    assert_eq!(&cose[n - 3..], [0x01, 0x00, 0x01]);
    cose[n - 1] = 0x00;
    credential.public_key_cose = passkey_auth::CosePublicKey(cose);
    let err = authenticate(&wa, &mut authenticator, &credential).unwrap_err();
    assert!(matches!(err, Error::Cbor(_)), "{err:?}");
}

// ---------- algorithm policy -------------------------------------------------

#[test]
fn classical_algorithm_order() {
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let (challenge, _) = wa.start_registration(b"u", "u", "U", &[]);
    let algs: Vec<i64> = challenge
        .pub_key_cred_params
        .iter()
        .map(|p| p.alg)
        .collect();
    assert_eq!(algs, [-7, -8, -257]);
}

#[cfg(feature = "pqc")]
#[test]
fn ml_dsa_leads_when_allowed() {
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN).allow_ml_dsa(true);
    let (challenge, _) = wa.start_registration(b"u", "u", "U", &[]);
    let algs: Vec<i64> = challenge
        .pub_key_cred_params
        .iter()
        .map(|p| p.alg)
        .collect();
    assert_eq!(algs, [-48, -49, -50, -7, -8, -257]);
}

#[cfg(feature = "pqc")]
#[test]
fn ml_dsa_refused_at_registration_unless_allowed() {
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    for alg in Alg::ML_DSA {
        let err = register(&wa, &Authenticator::new(alg, 2)).unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedAlg(a) if a == alg.cose()),
            "{err:?}"
        );
    }
}

#[cfg(feature = "pqc")]
#[test]
fn ml_dsa_credentials_authenticate_without_the_registration_switch() {
    let mut authenticator = Authenticator::new(Alg::MlDsa65, 3);
    let credential = register(&webauthn(), &authenticator).unwrap();
    let plain = Webauthn::new(RP_ID, "Example", ORIGIN);
    authenticate(&plain, &mut authenticator, &credential).unwrap();
}

#[cfg(feature = "pqc")]
#[test]
fn ml_dsa_key_of_wrong_size_refused() {
    use passkey_auth::RegistrationResponse;
    let wa = webauthn();
    let authenticator = Authenticator::new(Alg::MlDsa44, 4);
    let (challenge, state) = wa.start_registration(b"u", "u", "U", &[]);
    // A 1312-byte ML-DSA-44 key labelled ML-DSA-65.
    let cose = cbor(&Cbor::Map(vec![
        (int(1), int(7)),
        (int(3), int(-49)),
        (int(-1), Cbor::Bytes(vec![0x55; 1312])),
    ]));
    let mut auth_data = authenticator.registration_auth_data();
    let len = auth_data.len() - authenticator.cose_public_key().len();
    auth_data.truncate(len);
    auth_data.extend_from_slice(&cose);
    let client_data = client_data_json("webauthn.create", &challenge.challenge, ORIGIN);
    let response: RegistrationResponse = registration_response(
        &authenticator.credential_id,
        Authenticator::none_attestation(auth_data),
        &client_data,
    );
    let err = wa.finish_registration(&state, &response).unwrap_err();
    assert!(matches!(err, Error::Cbor(_)), "{err:?}");
}

#[cfg(not(feature = "pqc"))]
#[test]
fn ml_dsa_unsupported_without_the_feature() {
    let cose = cbor(&Cbor::Map(vec![
        (int(1), int(7)),
        (int(3), int(-49)),
        (int(-1), Cbor::Bytes(vec![0x55; 1952])),
    ]));
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    let mut authenticator = Authenticator::new(Alg::Es256, 5);
    let mut credential = register(&wa, &authenticator).unwrap();
    credential.public_key_cose = passkey_auth::CosePublicKey(cose);
    let err = authenticate(&wa, &mut authenticator, &credential).unwrap_err();
    assert!(matches!(err, Error::UnsupportedAlg(-49)), "{err:?}");
}

// ---------- backup flags ------------------------------------------------------

/// (flags, valid) for every BE/BS combination (WebAuthn-3 §6.1.3).
const BACKUP_COMBINATIONS: [(u8, bool); 4] = [
    (0, true),
    (FLAG_BE, true),
    (FLAG_BE | FLAG_BS, true),
    (FLAG_BS, false),
];

#[test]
fn registration_backup_flag_combinations() {
    let wa = webauthn();
    for alg in Alg::all() {
        for (backup, valid) in BACKUP_COMBINATIONS {
            let mut authenticator = Authenticator::new(alg, 20);
            authenticator.flags = FLAG_UP | FLAG_UV | backup;
            let result = register(&wa, &authenticator);
            assert_eq!(
                result.is_ok(),
                valid,
                "{} flags {backup:#04x}: {result:?}",
                alg.name()
            );
            if !valid {
                assert!(matches!(result, Err(Error::AuthData(_))));
            }
        }
    }
}

#[test]
fn authentication_backup_flag_combinations() {
    let wa = webauthn();
    for alg in Alg::all() {
        for (backup, valid) in BACKUP_COMBINATIONS {
            let mut authenticator = Authenticator::new(alg, 21);
            let credential = register(&wa, &authenticator).unwrap();
            authenticator.flags = FLAG_UP | FLAG_UV | backup;
            let result = authenticate(&wa, &mut authenticator, &credential);
            assert_eq!(
                result.is_ok(),
                valid,
                "{} flags {backup:#04x}: {result:?}",
                alg.name()
            );
            if !valid {
                assert!(matches!(result, Err(Error::AuthData(_))));
            }
        }
    }
}

// ---------- flags, counter, rpIdHash -----------------------------------------

#[test]
fn user_presence_required_in_both_ceremonies() {
    let wa = webauthn();
    let mut authenticator = Authenticator::new(Alg::Es256, 22);
    authenticator.flags = FLAG_UV;
    assert!(matches!(
        register(&wa, &authenticator),
        Err(Error::UserNotPresent)
    ));
    authenticator.flags = FLAG_UP | FLAG_UV;
    let credential = register(&wa, &authenticator).unwrap();
    authenticator.flags = FLAG_UV;
    assert!(matches!(
        authenticate(&wa, &mut authenticator, &credential),
        Err(Error::UserNotPresent)
    ));
}

#[test]
fn user_verification_enforced_only_when_required() {
    let lenient = webauthn();
    let strict = webauthn().require_user_verification(true);
    let mut authenticator = Authenticator::new(Alg::EdDsa, 23);
    authenticator.flags = FLAG_UP;
    let credential = register(&lenient, &authenticator).unwrap();
    assert!(matches!(
        register(&strict, &authenticator),
        Err(Error::UserNotVerified)
    ));
    let outcome = authenticate(&lenient, &mut authenticator, &credential).unwrap();
    assert!(!outcome.user_verified);
    let err = authenticate(&strict, &mut authenticator, &credential).unwrap_err();
    assert!(matches!(err, Error::UserNotVerified));
}

#[test]
fn sign_counter_rules() {
    let wa = webauthn();
    let authenticator = Authenticator::new(Alg::Es256, 24);
    let mut credential = register(&wa, &authenticator).unwrap();
    let run = |credential: &PasskeyCredential, count: u32| {
        let (challenge, state) = wa.start_authentication(std::slice::from_ref(&credential.id));
        let response = authenticator.assertion_with(
            &challenge.challenge,
            authenticator.assertion_auth_data(count),
        );
        wa.finish_authentication(&state, &response, credential)
    };
    // Both zero: the authenticator has no counter.
    assert_eq!(run(&credential, 0).unwrap().new_counter, 0);
    credential.counter = 5;
    assert_eq!(run(&credential, 6).unwrap().new_counter, 6);
    assert!(matches!(
        run(&credential, 5),
        Err(Error::CounterReplay { stored: 5, new: 5 })
    ));
    assert!(matches!(
        run(&credential, 4),
        Err(Error::CounterReplay { .. })
    ));
    assert!(matches!(
        run(&credential, 0),
        Err(Error::CounterReplay { .. })
    ));
}

#[test]
fn rp_id_hash_mismatch_rejected() {
    let wa = webauthn();
    let other = Webauthn::new("other.example", "Example", ORIGIN);
    let mut authenticator = Authenticator::new(Alg::Es256, 25);
    let credential = register(&wa, &authenticator).unwrap();
    assert!(matches!(
        register(&other, &authenticator),
        Err(Error::RpIdHashMismatch)
    ));
    let err = authenticate(&other, &mut authenticator, &credential).unwrap_err();
    assert!(matches!(err, Error::RpIdHashMismatch));
}

#[test]
fn trailing_bytes_after_authenticator_data_rejected() {
    let wa = webauthn();
    let authenticator = Authenticator::new(Alg::Es256, 26);
    let credential = register(&wa, &authenticator).unwrap();
    let (challenge, state) = wa.start_authentication(std::slice::from_ref(&credential.id));
    let mut auth_data = authenticator.assertion_auth_data(1);
    auth_data.push(0xa0);
    let response = authenticator.assertion_with(&challenge.challenge, auth_data);
    let err = wa
        .finish_authentication(&state, &response, &credential)
        .unwrap_err();
    assert!(matches!(err, Error::AuthData(_)), "{err:?}");
}

#[test]
fn extensions_after_attested_data_accepted() {
    let wa = webauthn();
    let mut authenticator = Authenticator::new(Alg::Es256, 27);
    authenticator.flags |= FLAG_ED;
    let (challenge, state) = wa.start_registration(b"u", "u", "U", &[]);
    let mut auth_data = authenticator.registration_auth_data();
    auth_data.extend_from_slice(&cbor(&Cbor::Map(vec![(text("credProtect"), int(2))])));
    let client_data = client_data_json("webauthn.create", &challenge.challenge, ORIGIN);
    let response = registration_response(
        &authenticator.credential_id,
        Authenticator::none_attestation(auth_data),
        &client_data,
    );
    wa.finish_registration(&state, &response).unwrap();
}

// ---------- clientDataJSON ------------------------------------------------------

#[test]
fn cross_origin_and_top_origin_rejected_in_both_ceremonies() {
    let wa = webauthn();
    let authenticator = Authenticator::new(Alg::Es256, 28);
    let credential = register(&wa, &authenticator).unwrap();
    for extra in [
        r#","crossOrigin":true"#,
        r#","crossOrigin":false,"topOrigin":"https://evil.example""#,
    ] {
        let (challenge, state) = wa.start_registration(b"u", "u", "U", &[]);
        let client_data =
            client_data_json_with("webauthn.create", &challenge.challenge, ORIGIN, extra);
        let response = registration_response(
            &authenticator.credential_id,
            Authenticator::none_attestation(authenticator.registration_auth_data()),
            &client_data,
        );
        assert!(matches!(
            wa.finish_registration(&state, &response),
            Err(Error::ClientData(_))
        ));

        let (challenge, state) = wa.start_authentication(std::slice::from_ref(&credential.id));
        let client_data =
            client_data_json_with("webauthn.get", &challenge.challenge, ORIGIN, extra);
        let response =
            authenticator.assertion_over(authenticator.assertion_auth_data(1), &client_data);
        let err = wa
            .finish_authentication(&state, &response, &credential)
            .unwrap_err();
        assert!(matches!(err, Error::ClientData(_)), "{extra}: {err:?}");
    }
}

#[test]
fn client_data_type_must_match_ceremony() {
    let wa = webauthn();
    let authenticator = Authenticator::new(Alg::Es256, 29);
    let credential = register(&wa, &authenticator).unwrap();
    let (challenge, state) = wa.start_authentication(std::slice::from_ref(&credential.id));
    let client_data = client_data_json("webauthn.create", &challenge.challenge, ORIGIN);
    let response = authenticator.assertion_over(authenticator.assertion_auth_data(1), &client_data);
    let err = wa
        .finish_authentication(&state, &response, &credential)
        .unwrap_err();
    assert!(matches!(err, Error::ClientDataType { .. }), "{err:?}");
}

#[test]
fn challenge_from_another_ceremony_rejected() {
    let wa = webauthn();
    let mut authenticator = Authenticator::new(Alg::EdDsa, 30);
    let credential = register(&wa, &authenticator).unwrap();
    let (first, _) = wa.start_authentication(std::slice::from_ref(&credential.id));
    let (_, second_state) = wa.start_authentication(std::slice::from_ref(&credential.id));
    let response = authenticator.assert(&first);
    let err = wa
        .finish_authentication(&second_state, &response, &credential)
        .unwrap_err();
    assert!(matches!(err, Error::ChallengeMismatch), "{err:?}");
}

// ---------- allowCredentials and userHandle -----------------------------------

#[test]
fn credential_outside_allow_list_rejected() {
    let wa = webauthn();
    let mut authenticator = Authenticator::new(Alg::Es256, 31);
    let credential = register(&wa, &authenticator).unwrap();
    let other = passkey_auth::CredentialId(b"some-other-credential".to_vec());
    let (challenge, state) = wa.start_authentication(std::slice::from_ref(&other));
    let response = authenticator.assert(&challenge);
    let err = wa
        .finish_authentication(&state, &response, &credential)
        .unwrap_err();
    assert!(matches!(err, Error::BadSignature), "{err:?}");
}

#[test]
fn discoverable_flow_requires_user_handle() {
    let wa = webauthn();
    let mut authenticator = Authenticator::new(Alg::Es256, 32);
    let credential = register(&wa, &authenticator).unwrap();

    let (challenge, state) = wa.start_authentication(&[]);
    let response = authenticator.assert(&challenge);
    let err = wa
        .finish_authentication(&state, &response, &credential)
        .unwrap_err();
    assert!(matches!(err, Error::UserHandleMismatch), "{err:?}");

    let (challenge, state) = wa.start_authentication(&[]);
    let mut response = authenticator.assert(&challenge);
    response.user_handle = Some(B64URL.encode(b"user-1"));
    wa.finish_authentication(&state, &response, &credential)
        .unwrap();
}

// ---------- attestation formats ------------------------------------------------

fn x5c_registration(
    wa: &Webauthn,
    cert_key: &Key,
    alg: i64,
    x5c: Vec<Vec<u8>>,
    aaguid: [u8; 16],
) -> passkey_auth::Result<PasskeyCredential> {
    let mut authenticator = Authenticator::new(Alg::Es256, 40);
    authenticator.aaguid = aaguid;
    let (challenge, state) = wa.start_registration(b"u", "u", "U", &[]);
    let client_data = client_data_json("webauthn.create", &challenge.challenge, ORIGIN);
    let attestation = packed_x5c_attestation(
        authenticator.registration_auth_data(),
        &client_data,
        cert_key,
        alg,
        x5c,
    );
    wa.finish_registration(
        &state,
        &registration_response(&authenticator.credential_id, attestation, &client_data),
    )
}

const AAGUID: [u8; 16] = *b"passkey-auth-tst";

#[test]
fn packed_x5c_es256_and_rs256_certificates() {
    let wa = webauthn();
    for (key, alg) in [(Key::new(Alg::Es256, 41), -7), (rsa_key(RSA_2048), -257)] {
        let cert = certificate(
            &key,
            PACKED_SUBJECT,
            vec![aaguid_extension(AAGUID, false), basic_constraints(false)],
        );
        let credential = x5c_registration(&wa, &key, alg, vec![cert], AAGUID)
            .unwrap_or_else(|e| panic!("alg {alg}: {e}"));
        assert_eq!(credential.aaguid, AAGUID);
    }
}

#[test]
fn packed_x5c_alg_must_match_certificate_key() {
    let wa = webauthn();
    let es = Key::new(Alg::Es256, 42);
    let rs = rsa_key(RSA_2048);
    let es_cert = certificate(&es, PACKED_SUBJECT, vec![basic_constraints(false)]);
    let rs_cert = certificate(&rs, PACKED_SUBJECT, vec![basic_constraints(false)]);
    for (key, alg, cert) in [(&es, -257, es_cert), (&rs, -7, rs_cert)] {
        let err = x5c_registration(&wa, key, alg, vec![cert], [0; 16]).unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match the certificate key"),
            "{err}"
        );
    }
}

#[test]
fn packed_x5c_certificate_requirements() {
    let wa = webauthn();
    let key = Key::new(Alg::Es256, 43);
    let ok = || vec![basic_constraints(false)];
    let cases = [
        ("CN=x,O=passkey-auth,C=US", ok(), "OU"),
        ("CN=x,OU=Some Other Unit,O=passkey-auth,C=US", ok(), "OU"),
        ("CN=x,OU=Authenticator Attestation,C=US", ok(), "C or O"),
        (
            "OU=Authenticator Attestation,O=passkey-auth,C=US",
            ok(),
            "CN",
        ),
        (
            PACKED_SUBJECT,
            vec![aaguid_extension(AAGUID, false)],
            "Basic Constraints",
        ),
        (PACKED_SUBJECT, Vec::new(), "version 3"),
        (
            PACKED_SUBJECT,
            vec![basic_constraints(true)],
            "Basic Constraints",
        ),
        (
            PACKED_SUBJECT,
            vec![basic_constraints(false), aaguid_extension(AAGUID, true)],
            "critical",
        ),
    ];
    for (subject, extensions, expected) in cases {
        let cert = certificate(&key, subject, extensions);
        let err = x5c_registration(&wa, &key, -7, vec![cert], AAGUID).unwrap_err();
        assert!(err.to_string().contains(expected), "{subject}: {err}");
    }
}

#[test]
fn attestation_statement_shape() {
    let wa = webauthn();
    let authenticator = Authenticator::new(Alg::Es256, 47);
    let (challenge, state) = wa.start_registration(b"u", "u", "U", &[]);
    let client_data = client_data_json("webauthn.create", &challenge.challenge, ORIGIN);
    let auth_data = authenticator.registration_auth_data();
    let run = |object: Vec<u8>| {
        wa.finish_registration(
            &state,
            &registration_response(&authenticator.credential_id, object, &client_data),
        )
    };
    let none_with = |stmt: Cbor| attestation_object("none", stmt, auth_data.clone());
    run(none_with(Cbor::Map(Vec::new()))).unwrap();
    assert!(
        run(none_with(Cbor::Map(vec![(
            text("sig"),
            Cbor::Bytes(vec![1])
        )])))
        .is_err()
    );
    assert!(run(none_with(Cbor::Array(Vec::new()))).is_err());
    let no_statement = cbor(&Cbor::Map(vec![
        (text("fmt"), text("none")),
        (text("authData"), Cbor::Bytes(auth_data.clone())),
    ]));
    let err = run(no_statement).unwrap_err();
    assert!(err.to_string().contains("missing attStmt"), "{err}");
}

#[test]
fn fido_u2f_requires_exactly_one_certificate() {
    let wa = webauthn();
    let authenticator = Authenticator::new(Alg::Es256, 44);
    let cert_key = Key::new(Alg::Es256, 45);
    let cert = certificate(&cert_key, "CN=U2F", Vec::new());
    let (challenge, state) = wa.start_registration(b"u", "u", "U", &[]);
    let client_data = client_data_json("webauthn.create", &challenge.challenge, ORIGIN);
    let auth_data = authenticator.registration_auth_data();

    let make = |x5c: Vec<Vec<u8>>| {
        // U2F pre-image: 0x00 || rpIdHash || clientDataHash || credId || pubKey
        use sha2::{Digest, Sha256};
        let point = match &authenticator.key {
            Key::Es256(sk) => sk.verifying_key().to_sec1_point(false),
            _ => unreachable!(),
        };
        let mut pre_image = vec![0x00];
        pre_image.extend_from_slice(&auth_data[..32]);
        pre_image.extend_from_slice(&Sha256::digest(&client_data));
        pre_image.extend_from_slice(&authenticator.credential_id);
        pre_image.extend_from_slice(point.as_bytes());
        let stmt = Cbor::Map(vec![
            (text("sig"), Cbor::Bytes(cert_key.sign(&pre_image))),
            (
                text("x5c"),
                Cbor::Array(x5c.into_iter().map(Cbor::Bytes).collect()),
            ),
        ]);
        registration_response(
            &authenticator.credential_id,
            attestation_object("fido-u2f", stmt, auth_data.clone()),
            &client_data,
        )
    };
    wa.finish_registration(&state, &make(vec![cert.clone()]))
        .unwrap();
    let err = wa
        .finish_registration(&state, &make(vec![cert.clone(), cert]))
        .unwrap_err();
    assert!(matches!(err, Error::Cbor(_)), "{err:?}");
}

#[test]
fn unsupported_attestation_format_rejected() {
    let wa = webauthn();
    let authenticator = Authenticator::new(Alg::Es256, 46);
    let (challenge, state) = wa.start_registration(b"u", "u", "U", &[]);
    let client_data = client_data_json("webauthn.create", &challenge.challenge, ORIGIN);
    for fmt in ["tpm", "apple", "android-key", "Packed"] {
        let attestation = attestation_object(
            fmt,
            Cbor::Map(Vec::new()),
            authenticator.registration_auth_data(),
        );
        let response =
            registration_response(&authenticator.credential_id, attestation, &client_data);
        assert!(wa.finish_registration(&state, &response).is_err(), "{fmt}");
    }
}
