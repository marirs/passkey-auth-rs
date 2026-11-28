//! Every type that appears in the public API can be named from the crate
//! root, so callers can write it in their own signatures.

use passkey_auth::{
    AuthenticationChallenge, AuthenticatorSelection, CredentialDescriptor, CredentialId,
    PubKeyCredParam, RegistrationChallenge, RpInfo, UserInfo, Webauthn,
};

fn rp(challenge: &RegistrationChallenge) -> &RpInfo {
    &challenge.rp
}

fn user(challenge: &RegistrationChallenge) -> &UserInfo {
    &challenge.user
}

fn params(challenge: &RegistrationChallenge) -> &[PubKeyCredParam] {
    &challenge.pub_key_cred_params
}

fn selection(challenge: &RegistrationChallenge) -> &AuthenticatorSelection {
    &challenge.authenticator_selection
}

fn allowed(challenge: &AuthenticationChallenge) -> &[CredentialDescriptor] {
    &challenge.allow_credentials
}

#[test]
fn challenge_field_types_are_nameable() {
    let wa = Webauthn::new("example.com", "Example", "https://example.com");
    let ids = [CredentialId(vec![1, 2, 3])];

    let (registration, _) = wa.start_registration(b"user-1", "alice", "Alice", &ids);
    assert_eq!(rp(&registration).id, "example.com");
    assert_eq!(user(&registration).name, "alice");
    assert_eq!(params(&registration)[0].alg, -7);
    assert_eq!(selection(&registration).user_verification, "preferred");
    assert_eq!(registration.exclude_credentials[0].id, ids[0].to_b64url());

    let (authentication, _) = wa.start_authentication(&ids);
    assert_eq!(allowed(&authentication)[0].id, ids[0].to_b64url());
}
