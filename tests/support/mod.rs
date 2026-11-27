//! Synthetic authenticator shared by the conformance tests, the
//! allocation test and the benchmarks. It produces the bytes a real
//! authenticator and browser would: COSE keys, authenticator data,
//! attestationObjects, clientDataJSON and assertion signatures.

#![allow(dead_code)] // each test binary uses a different subset

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use ciborium::value::Value as Cbor;
use sha2::{Digest, Sha256};

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

/// Signature algorithm of a synthetic credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    Es256,
    EdDsa,
}

impl Alg {
    pub const CLASSICAL: [Alg; 2] = [Alg::Es256, Alg::EdDsa];

    pub fn name(self) -> &'static str {
        match self {
            Alg::Es256 => "ES256",
            Alg::EdDsa => "EdDSA",
        }
    }
}

enum Key {
    Es256(p256::ecdsa::SigningKey),
    EdDsa(ed25519_dalek::SigningKey),
}

/// One credential on a synthetic authenticator.
pub struct Authenticator {
    key: Key,
    pub alg: Alg,
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
        let key = match alg {
            Alg::Es256 => {
                Key::Es256(p256::ecdsa::SigningKey::from_bytes(&[seed; 32].into()).expect("p256"))
            }
            Alg::EdDsa => Key::EdDsa(ed25519_dalek::SigningKey::from_bytes(&[seed; 32])),
        };
        Self {
            key,
            alg,
            credential_id: format!("credential-{}-{seed}", alg.name()).into_bytes(),
            counter: 0,
            flags: FLAG_UP | FLAG_UV,
            aaguid: [0; 16],
        }
    }

    /// COSE_Key encoding of the credential public key.
    pub fn cose_public_key(&self) -> Vec<u8> {
        match &self.key {
            Key::Es256(sk) => {
                let point = sk.verifying_key().to_sec1_point(false);
                cbor(&Cbor::Map(vec![
                    (int(1), int(2)),
                    (int(3), int(-7)),
                    (int(-1), int(1)),
                    (int(-2), Cbor::Bytes(point.x().expect("x").to_vec())),
                    (int(-3), Cbor::Bytes(point.y().expect("y").to_vec())),
                ]))
            }
            Key::EdDsa(sk) => cbor(&Cbor::Map(vec![
                (int(1), int(1)),
                (int(3), int(-8)),
                (int(-1), int(6)),
                (int(-2), Cbor::Bytes(sk.verifying_key().to_bytes().to_vec())),
            ])),
        }
    }

    /// Signs `msg` the way the credential's algorithm encodes signatures
    /// in WebAuthn (DER for ECDSA, raw for EdDSA).
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        match &self.key {
            Key::Es256(sk) => {
                use p256::ecdsa::signature::Signer;
                let sig: p256::ecdsa::Signature = sk.sign(msg);
                sig.to_der().to_bytes().to_vec()
            }
            Key::EdDsa(sk) => {
                use ed25519_dalek::Signer;
                sk.sign(msg).to_bytes().to_vec()
            }
        }
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
            (text("alg"), int(self.cose_alg())),
            (text("sig"), Cbor::Bytes(sig)),
        ]);
        attestation_object("packed", stmt, auth_data)
    }

    pub fn cose_alg(&self) -> i64 {
        match self.alg {
            Alg::Es256 => -7,
            Alg::EdDsa => -8,
        }
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
        let sig = self.sign(&signed_message(&auth_data, &client_data));
        AuthenticationResponse {
            id: B64URL.encode(&self.credential_id),
            authenticator_data: B64URL.encode(&auth_data),
            signature: B64URL.encode(sig),
            client_data_json: B64URL.encode(&client_data),
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
    format!(
        r#"{{"type":"{kind}","challenge":"{challenge_b64}","origin":"{origin}","crossOrigin":false}}"#
    )
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
