//! Synthetic authenticator shared by the conformance tests, the
//! allocation test and the benchmarks. It produces the bytes a real
//! authenticator and browser would: COSE keys, authenticator data,
//! attestationObjects, clientDataJSON, assertion signatures and
//! attestation certificates.

#![allow(dead_code)] // each test binary uses a different subset

use std::str::FromStr;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use ciborium::value::Value as Cbor;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256};
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::certificate::TbsCertificate;
use x509_cert::der::Encode;
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{SubjectPublicKeyInfo, SubjectPublicKeyInfoRef};
use x509_cert::time::Validity;

use passkey_auth::{
    AuthenticationChallenge, AuthenticationResponse, RegistrationChallenge, RegistrationResponse,
};

pub const RP_ID: &str = "example.com";
pub const ORIGIN: &str = "https://example.com";

pub const FLAG_UP: u8 = 1 << 0;
pub const FLAG_UV: u8 = 1 << 2;
pub const FLAG_BE: u8 = 1 << 3;
pub const FLAG_BS: u8 = 1 << 4;
pub const FLAG_AT: u8 = 1 << 6;
pub const FLAG_ED: u8 = 1 << 7;

/// Test-only RSA keys (PKCS#8 DER). They sign synthetic credentials and
/// attestation certificates and protect nothing.
pub const RSA_1024: &[u8] = include_bytes!("../fixtures/rsa-1024-test-key.pk8.der");
pub const RSA_2048: &[u8] = include_bytes!("../fixtures/rsa-2048-test-key.pk8.der");
pub const RSA_4096: &[u8] = include_bytes!("../fixtures/rsa-4096-test-key.pk8.der");

/// Signature algorithm of a synthetic credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    Es256,
    EdDsa,
    Rs256,
    #[cfg(feature = "pqc")]
    MlDsa44,
    #[cfg(feature = "pqc")]
    MlDsa65,
    #[cfg(feature = "pqc")]
    MlDsa87,
}

impl Alg {
    pub const CLASSICAL: [Alg; 3] = [Alg::Es256, Alg::EdDsa, Alg::Rs256];
    #[cfg(feature = "pqc")]
    pub const ML_DSA: [Alg; 3] = [Alg::MlDsa44, Alg::MlDsa65, Alg::MlDsa87];

    /// Every algorithm this build supports.
    pub fn all() -> Vec<Alg> {
        let algs = Self::CLASSICAL.to_vec();
        #[cfg(feature = "pqc")]
        let algs = [algs, Self::ML_DSA.to_vec()].concat();
        algs
    }

    pub fn name(self) -> &'static str {
        match self {
            Alg::Es256 => "ES256",
            Alg::EdDsa => "EdDSA",
            Alg::Rs256 => "RS256",
            #[cfg(feature = "pqc")]
            Alg::MlDsa44 => "ML-DSA-44",
            #[cfg(feature = "pqc")]
            Alg::MlDsa65 => "ML-DSA-65",
            #[cfg(feature = "pqc")]
            Alg::MlDsa87 => "ML-DSA-87",
        }
    }

    /// COSE algorithm identifier.
    pub fn cose(self) -> i64 {
        match self {
            Alg::Es256 => -7,
            Alg::EdDsa => -8,
            Alg::Rs256 => -257,
            #[cfg(feature = "pqc")]
            Alg::MlDsa44 => -48,
            #[cfg(feature = "pqc")]
            Alg::MlDsa65 => -49,
            #[cfg(feature = "pqc")]
            Alg::MlDsa87 => -50,
        }
    }
}

/// A private key of any supported algorithm.
pub enum Key {
    Es256(p256::ecdsa::SigningKey),
    EdDsa(ed25519_dalek::SigningKey),
    Rs256(Box<rsa::pkcs1v15::SigningKey<Sha256>>),
    #[cfg(feature = "pqc")]
    MlDsa44(Box<ml_dsa::SigningKey<ml_dsa::MlDsa44>>),
    #[cfg(feature = "pqc")]
    MlDsa65(Box<ml_dsa::SigningKey<ml_dsa::MlDsa65>>),
    #[cfg(feature = "pqc")]
    MlDsa87(Box<ml_dsa::SigningKey<ml_dsa::MlDsa87>>),
}

pub fn rsa_key(pkcs8_der: &[u8]) -> Key {
    let private = rsa::PrivateKey::from_pkcs8_der(pkcs8_der).expect("RSA test key");
    Key::Rs256(Box::new(rsa::pkcs1v15::SigningKey::new(private)))
}

impl Key {
    /// Deterministic key for `alg` derived from `seed` (RS256 uses the
    /// 2048-bit test key).
    pub fn new(alg: Alg, seed: u8) -> Self {
        match alg {
            Alg::Es256 => {
                Key::Es256(p256::ecdsa::SigningKey::from_bytes(&[seed; 32].into()).expect("p256"))
            }
            Alg::EdDsa => Key::EdDsa(ed25519_dalek::SigningKey::from_bytes(&[seed; 32])),
            Alg::Rs256 => rsa_key(RSA_2048),
            #[cfg(feature = "pqc")]
            Alg::MlDsa44 => {
                Key::MlDsa44(Box::new(ml_dsa::SigningKey::from_seed(&[seed; 32].into())))
            }
            #[cfg(feature = "pqc")]
            Alg::MlDsa65 => {
                Key::MlDsa65(Box::new(ml_dsa::SigningKey::from_seed(&[seed; 32].into())))
            }
            #[cfg(feature = "pqc")]
            Alg::MlDsa87 => {
                Key::MlDsa87(Box::new(ml_dsa::SigningKey::from_seed(&[seed; 32].into())))
            }
        }
    }

    pub fn alg(&self) -> Alg {
        match self {
            Key::Es256(_) => Alg::Es256,
            Key::EdDsa(_) => Alg::EdDsa,
            Key::Rs256(_) => Alg::Rs256,
            #[cfg(feature = "pqc")]
            Key::MlDsa44(_) => Alg::MlDsa44,
            #[cfg(feature = "pqc")]
            Key::MlDsa65(_) => Alg::MlDsa65,
            #[cfg(feature = "pqc")]
            Key::MlDsa87(_) => Alg::MlDsa87,
        }
    }

    /// COSE_Key encoding of the public key.
    pub fn cose_public_key(&self) -> Vec<u8> {
        let (kty, params) = match self {
            Key::Es256(sk) => {
                let point = sk.verifying_key().to_sec1_point(false);
                (
                    2,
                    vec![
                        (int(-1), int(1)),
                        (int(-2), Cbor::Bytes(point.x().expect("x").to_vec())),
                        (int(-3), Cbor::Bytes(point.y().expect("y").to_vec())),
                    ],
                )
            }
            Key::EdDsa(sk) => (
                1,
                vec![
                    (int(-1), int(6)),
                    (int(-2), Cbor::Bytes(sk.verifying_key().to_bytes().to_vec())),
                ],
            ),
            Key::Rs256(sk) => {
                let public = sk.as_ref().as_ref();
                (
                    3,
                    vec![
                        (
                            int(-1),
                            Cbor::Bytes(public.n().to_be_bytes_trimmed_vartime().to_vec()),
                        ),
                        (
                            int(-2),
                            Cbor::Bytes(public.e().to_be_bytes_trimmed_vartime().to_vec()),
                        ),
                    ],
                )
            }
            #[cfg(feature = "pqc")]
            Key::MlDsa44(sk) => (7, vec![(int(-1), Cbor::Bytes(ml_dsa_pub(sk.as_ref())))]),
            #[cfg(feature = "pqc")]
            Key::MlDsa65(sk) => (7, vec![(int(-1), Cbor::Bytes(ml_dsa_pub(sk.as_ref())))]),
            #[cfg(feature = "pqc")]
            Key::MlDsa87(sk) => (7, vec![(int(-1), Cbor::Bytes(ml_dsa_pub(sk.as_ref())))]),
        };
        let mut entries = vec![(int(1), int(kty)), (int(3), int(self.alg().cose()))];
        entries.extend(params);
        cbor(&Cbor::Map(entries))
    }

    /// Signs `msg` with the WebAuthn signature encoding of the algorithm
    /// (DER for ECDSA, raw bytes otherwise).
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        use rsa::signature::{SignatureEncoding, Signer};
        match self {
            Key::Es256(sk) => {
                let sig: p256::ecdsa::Signature = sk.sign(msg);
                sig.to_der().to_bytes().to_vec()
            }
            Key::EdDsa(sk) => sk.sign(msg).to_bytes().to_vec(),
            Key::Rs256(sk) => sk.sign(msg).to_vec(),
            #[cfg(feature = "pqc")]
            Key::MlDsa44(sk) => sk.sign(msg).encode().to_vec(),
            #[cfg(feature = "pqc")]
            Key::MlDsa65(sk) => sk.sign(msg).encode().to_vec(),
            #[cfg(feature = "pqc")]
            Key::MlDsa87(sk) => sk.sign(msg).encode().to_vec(),
        }
    }
}

#[cfg(feature = "pqc")]
fn ml_dsa_pub<P: ml_dsa::MlDsaParams>(sk: &ml_dsa::SigningKey<P>) -> Vec<u8> {
    use ml_dsa::Keypair;
    sk.verifying_key().encode().to_vec()
}

/// One credential on a synthetic authenticator.
pub struct Authenticator {
    pub key: Key,
    pub credential_id: Vec<u8>,
    pub counter: u32,
    /// Flag bits for every authenticator data this authenticator emits
    /// (AT is added for registration).
    pub flags: u8,
    pub aaguid: [u8; 16],
}

pub fn cbor(value: &Cbor) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).expect("CBOR encode");
    out
}

pub fn int(n: i64) -> Cbor {
    Cbor::Integer(n.into())
}

pub fn text(s: &str) -> Cbor {
    Cbor::Text(s.into())
}

impl Authenticator {
    /// Creates a credential with a deterministic key derived from `seed`.
    pub fn new(alg: Alg, seed: u8) -> Self {
        Self::with_key(Key::new(alg, seed), seed)
    }

    pub fn with_key(key: Key, seed: u8) -> Self {
        Self {
            credential_id: format!("credential-{}-{seed}", key.alg().name()).into_bytes(),
            key,
            counter: 0,
            flags: FLAG_UP | FLAG_UV,
            aaguid: [0; 16],
        }
    }

    pub fn alg(&self) -> Alg {
        self.key.alg()
    }

    pub fn cose_public_key(&self) -> Vec<u8> {
        self.key.cose_public_key()
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.key.sign(msg)
    }

    /// Authenticator data for registration: flags | AT, then the
    /// attested credential data.
    pub fn registration_auth_data(&self) -> Vec<u8> {
        let mut data = Sha256::digest(RP_ID.as_bytes()).to_vec();
        data.push(self.flags | FLAG_AT);
        data.extend_from_slice(&self.counter.to_be_bytes());
        data.extend_from_slice(&self.aaguid);
        data.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
        data.extend_from_slice(&self.credential_id);
        data.extend_from_slice(&self.cose_public_key());
        data
    }

    /// Authenticator data for an assertion with the given counter.
    pub fn assertion_auth_data(&self, counter: u32) -> Vec<u8> {
        let mut data = Sha256::digest(RP_ID.as_bytes()).to_vec();
        data.push(self.flags);
        data.extend_from_slice(&counter.to_be_bytes());
        data
    }

    /// `fmt: "none"` attestationObject around `auth_data`.
    pub fn none_attestation(auth_data: Vec<u8>) -> Vec<u8> {
        attestation_object("none", Cbor::Map(Vec::new()), auth_data)
    }

    /// `fmt: "packed"` self-attestation signed with the credential key.
    pub fn packed_self_attestation(&self, auth_data: Vec<u8>, client_data: &[u8]) -> Vec<u8> {
        let sig = self.sign(&signed_message(&auth_data, client_data));
        let stmt = Cbor::Map(vec![
            (text("alg"), int(self.alg().cose())),
            (text("sig"), Cbor::Bytes(sig)),
        ]);
        attestation_object("packed", stmt, auth_data)
    }

    /// Registration response for `challenge` with `fmt: "none"`.
    pub fn register(&self, challenge: &RegistrationChallenge) -> RegistrationResponse {
        let client_data = client_data_json("webauthn.create", &challenge.challenge, ORIGIN);
        registration_response(
            &self.credential_id,
            Self::none_attestation(self.registration_auth_data()),
            &client_data,
        )
    }

    /// Registration response for `challenge` with packed self-attestation.
    pub fn register_packed_self(&self, challenge: &RegistrationChallenge) -> RegistrationResponse {
        let client_data = client_data_json("webauthn.create", &challenge.challenge, ORIGIN);
        let attestation = self.packed_self_attestation(self.registration_auth_data(), &client_data);
        registration_response(&self.credential_id, attestation, &client_data)
    }

    /// Assertion for `challenge`; advances the counter by one.
    pub fn assert(&mut self, challenge: &AuthenticationChallenge) -> AuthenticationResponse {
        self.counter += 1;
        let auth_data = self.assertion_auth_data(self.counter);
        self.assertion_with(&challenge.challenge, auth_data)
    }

    /// Assertion over caller-supplied authenticator data.
    pub fn assertion_with(
        &self,
        challenge_b64: &str,
        auth_data: Vec<u8>,
    ) -> AuthenticationResponse {
        let client_data = client_data_json("webauthn.get", challenge_b64, ORIGIN);
        self.assertion_over(auth_data, &client_data)
    }

    /// Assertion over caller-supplied authenticator data and client data.
    pub fn assertion_over(&self, auth_data: Vec<u8>, client_data: &[u8]) -> AuthenticationResponse {
        let sig = self.sign(&signed_message(&auth_data, client_data));
        AuthenticationResponse {
            id: B64URL.encode(&self.credential_id),
            authenticator_data: B64URL.encode(&auth_data),
            signature: B64URL.encode(sig),
            client_data_json: B64URL.encode(client_data),
            user_handle: None,
        }
    }
}

/// `authData || SHA-256(clientDataJSON)`.
pub fn signed_message(auth_data: &[u8], client_data: &[u8]) -> Vec<u8> {
    let mut msg = auth_data.to_vec();
    msg.extend_from_slice(&Sha256::digest(client_data));
    msg
}

pub fn attestation_object(fmt: &str, att_stmt: Cbor, auth_data: Vec<u8>) -> Vec<u8> {
    cbor(&Cbor::Map(vec![
        (text("fmt"), text(fmt)),
        (text("attStmt"), att_stmt),
        (text("authData"), Cbor::Bytes(auth_data)),
    ]))
}

pub fn client_data_json(kind: &str, challenge_b64: &str, origin: &str) -> Vec<u8> {
    client_data_json_with(kind, challenge_b64, origin, r#","crossOrigin":false"#)
}

/// clientDataJSON with `extra` appended inside the object.
pub fn client_data_json_with(
    kind: &str,
    challenge_b64: &str,
    origin: &str,
    extra: &str,
) -> Vec<u8> {
    format!(r#"{{"type":"{kind}","challenge":"{challenge_b64}","origin":"{origin}"{extra}}}"#)
        .into_bytes()
}

pub fn registration_response(
    credential_id: &[u8],
    attestation_object: Vec<u8>,
    client_data: &[u8],
) -> RegistrationResponse {
    RegistrationResponse {
        id: B64URL.encode(credential_id),
        transports: vec!["internal".into()],
        attestation_object: B64URL.encode(attestation_object),
        client_data_json: B64URL.encode(client_data),
    }
}

// ---------- attestation certificates ----------------------------------------

/// The subject WebAuthn-3 §8.2.1 asks of a `packed` attestation cert.
pub const PACKED_SUBJECT: &str =
    "CN=passkey-auth test attestation,OU=Authenticator Attestation,O=passkey-auth,C=US";

/// Self-issued certificate profile that adds only `extensions`.
pub struct TestProfile {
    pub subject: Name,
    pub extensions: Vec<Extension>,
}

impl BuilderProfile for TestProfile {
    fn get_issuer(&self, subject: &Name) -> Name {
        subject.clone()
    }
    fn get_subject(&self) -> Name {
        self.subject.clone()
    }
    fn build_extensions(
        &self,
        _spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        _tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        Ok(self.extensions.clone())
    }
}

/// FIDO AAGUID extension (OCTET STRING wrapping a 16-byte OCTET STRING).
pub fn aaguid_extension(aaguid: [u8; 16], critical: bool) -> Extension {
    let mut inner = vec![0x04, 0x10];
    inner.extend_from_slice(&aaguid);
    Extension {
        extn_id: x509_cert::der::oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.45724.1.1.4"),
        critical,
        extn_value: x509_cert::der::asn1::OctetString::new(inner).expect("octet string"),
    }
}

/// Basic Constraints extension with the given CA bit.
pub fn basic_constraints(ca: bool) -> Extension {
    let value = x509_cert::ext::pkix::BasicConstraints {
        ca,
        path_len_constraint: None,
    };
    Extension {
        extn_id: const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS,
        critical: true,
        extn_value: x509_cert::der::asn1::OctetString::new(value.to_der().expect("DER"))
            .expect("octet string"),
    }
}

/// Self-signed DER certificate for `key` (ES256 or RS256).
pub fn certificate(key: &Key, subject: &str, extensions: Vec<Extension>) -> Vec<u8> {
    let profile = TestProfile {
        subject: Name::from_str(subject).expect("name"),
        extensions,
    };
    let validity = Validity::from_now(Duration::from_secs(3600)).expect("validity");
    let serial = SerialNumber::from(1u32);
    let cert = match key {
        Key::Es256(sk) => {
            let spki = SubjectPublicKeyInfo::from_key(sk.verifying_key()).expect("spki");
            CertificateBuilder::new(profile, serial, validity, spki)
                .expect("builder")
                .build::<_, p256::ecdsa::DerSignature>(sk)
                .expect("build")
        }
        Key::Rs256(sk) => {
            use rsa::signature::Keypair;
            let spki = SubjectPublicKeyInfo::from_key(&sk.verifying_key()).expect("spki");
            CertificateBuilder::new(profile, serial, validity, spki)
                .expect("builder")
                .build::<_, rsa::pkcs1v15::Signature>(sk.as_ref())
                .expect("build")
        }
        _ => panic!("attestation certificates are ES256 or RS256"),
    };
    cert.to_der().expect("cert DER")
}

/// `fmt: "packed"` with `x5c`, signed by `cert_key` with COSE alg `alg`.
pub fn packed_x5c_attestation(
    auth_data: Vec<u8>,
    client_data: &[u8],
    cert_key: &Key,
    alg: i64,
    x5c: Vec<Vec<u8>>,
) -> Vec<u8> {
    let sig = cert_key.sign(&signed_message(&auth_data, client_data));
    let stmt = Cbor::Map(vec![
        (text("alg"), int(alg)),
        (text("sig"), Cbor::Bytes(sig)),
        (
            text("x5c"),
            Cbor::Array(x5c.into_iter().map(Cbor::Bytes).collect()),
        ),
    ]);
    attestation_object("packed", stmt, auth_data)
}
