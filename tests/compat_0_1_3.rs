//! Credentials stored by passkey-auth 0.1.3 keep working.
//!
//! `fixtures/credentials-0.1.3.json` was produced by the published 0.1.3
//! crate: one ES256 and one EdDSA credential, each registered with
//! `finish_registration`, then authenticated once with
//! `finish_authentication`. The fixture keeps the credential JSON as
//! 0.1.3 serialised it (before and after that authentication), the
//! serialised `AuthenticationState`, the assertion the browser posted,
//! and the test-only private key so new assertions can be signed.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde_json::Value;
use sha2::{Digest, Sha256};

use passkey_auth::{
    AuthenticationResponse, AuthenticationState, Error, PasskeyCredential, Webauthn,
};

const FIXTURE: &str = include_str!("fixtures/credentials-0.1.3.json");

fn fixtures() -> (Webauthn, Vec<Value>) {
    let root: Value = serde_json::from_str(FIXTURE).expect("fixture JSON");
    let wa = Webauthn::new(
        root["rp_id"].as_str().expect("rp_id"),
        "Example",
        root["origin"].as_str().expect("origin"),
    );
    (
        wa,
        root["credentials"].as_array().expect("credentials").clone(),
    )
}

fn field<'a>(entry: &'a Value, name: &str) -> &'a str {
    entry[name]
        .as_str()
        .unwrap_or_else(|| panic!("fixture field {name}"))
}

fn secret(entry: &Value) -> [u8; 32] {
    hex::decode(field(entry, "secret_key_hex"))
        .expect("hex")
        .try_into()
        .expect("32 bytes")
}

/// Signs `authData || SHA-256(clientDataJSON)` with the fixture key.
fn sign(entry: &Value, msg: &[u8]) -> Vec<u8> {
    match field(entry, "name") {
        "es256" => {
            use p256::ecdsa::signature::Signer;
            let sk = p256::ecdsa::SigningKey::from_bytes(&secret(entry).into()).expect("p256 key");
            let sig: p256::ecdsa::Signature = sk.sign(msg);
            sig.to_der().to_bytes().to_vec()
        }
        "eddsa" => {
            use ed25519_dalek::Signer;
            ed25519_dalek::SigningKey::from_bytes(&secret(entry))
                .sign(msg)
                .to_bytes()
                .to_vec()
        }
        other => panic!("unknown fixture {other}"),
    }
}

#[test]
fn stored_assertion_verifies_against_stored_credential() {
    let (wa, entries) = fixtures();
    for entry in &entries {
        let credential: PasskeyCredential =
            serde_json::from_str(field(entry, "credential_registered")).expect("credential");
        let state: AuthenticationState =
            serde_json::from_str(field(entry, "authentication_state")).expect("state");
        let response: AuthenticationResponse =
            serde_json::from_str(field(entry, "authentication_response")).expect("response");

        let outcome = wa
            .finish_authentication(&state, &response, &credential)
            .unwrap_or_else(|e| panic!("{}: {e}", field(entry, "name")));
        assert_eq!(
            u64::from(outcome.new_counter),
            entry["counter_after"].as_u64().unwrap()
        );
        assert!(outcome.user_verified);
    }
}

#[test]
fn credential_json_round_trips_byte_for_byte() {
    let (_, entries) = fixtures();
    for entry in &entries {
        for name in ["credential_registered", "credential_after_authentication"] {
            let stored = field(entry, name);
            let credential: PasskeyCredential = serde_json::from_str(stored).expect("credential");
            assert_eq!(
                serde_json::to_string(&credential).expect("serialise"),
                stored
            );
        }
    }
}

#[test]
fn new_assertion_verifies_against_updated_credential() {
    let (wa, entries) = fixtures();
    for entry in &entries {
        let credential: PasskeyCredential =
            serde_json::from_str(field(entry, "credential_after_authentication"))
                .expect("credential");
        let (challenge, state) = wa
            .start_authentication_with_creds_for_user(b"user-1", std::slice::from_ref(&credential));

        let mut auth_data = Sha256::digest(b"example.com").to_vec();
        auth_data.push(0x05); // UP | UV
        auth_data.extend_from_slice(&(credential.counter + 1).to_be_bytes());
        let client_data = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://example.com","crossOrigin":false}}"#,
            challenge.challenge
        );
        let mut msg = auth_data.clone();
        msg.extend_from_slice(&Sha256::digest(client_data.as_bytes()));
        let response = AuthenticationResponse {
            id: credential.id.to_b64url(),
            authenticator_data: B64URL.encode(&auth_data),
            signature: B64URL.encode(sign(entry, &msg)),
            client_data_json: B64URL.encode(client_data.as_bytes()),
            user_handle: Some(B64URL.encode(b"user-1")),
        };

        let outcome = wa
            .finish_authentication(&state, &response, &credential)
            .unwrap_or_else(|e| panic!("{}: {e}", field(entry, "name")));
        assert_eq!(outcome.new_counter, credential.counter + 1);
    }
}

#[test]
fn replayed_stored_assertion_is_rejected_after_counter_update() {
    let (wa, entries) = fixtures();
    for entry in &entries {
        let credential: PasskeyCredential =
            serde_json::from_str(field(entry, "credential_after_authentication"))
                .expect("credential");
        let state: AuthenticationState =
            serde_json::from_str(field(entry, "authentication_state")).expect("state");
        let response: AuthenticationResponse =
            serde_json::from_str(field(entry, "authentication_response")).expect("response");
        let err = wa
            .finish_authentication(&state, &response, &credential)
            .unwrap_err();
        assert!(matches!(err, Error::CounterReplay { .. }), "got {err:?}");
    }
}
