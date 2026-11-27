//! Parse the binary `authenticatorData` structure.
//!
//! Layout (big-endian where multi-byte):
//! ```text
//!   offset  bytes  field
//!   ─────────────────────────────────────────────
//!   0       32     rpIdHash         (SHA-256 of RP ID)
//!   32      1      flags
//!   33      4      signCount        (counter)
//!   37..    var    attestedCredentialData  (only if AT bit set)
//!                    16   aaguid
//!                    2    credentialIdLength
//!                    var  credentialId
//!                    var  credentialPublicKey  (COSE_Key, CBOR)
//!   ...     var    extensions        (only if ED bit set; ignored)
//! ```
//!
//! Flag bits (LSB first):
//!   bit 0 (UP) - user present
//!   bit 2 (UV) - user verified
//!   bit 3 (BE) - backup eligible
//!   bit 4 (BS) - backed up (only valid together with BE)
//!   bit 6 (AT) - attestedCredentialData present
//!   bit 7 (ED) - extensionData present
//!
//! The data must end exactly where the last present field ends: with ED
//! set the extensions map is the rest of the data, with ED clear nothing
//! follows the attested credential data.

use ciborium::value::Value as CborValue;

use crate::error::{Error, Result};
use crate::types::{CosePublicKey, CredentialId};

pub(crate) const FLAG_UP: u8 = 1 << 0;
pub(crate) const FLAG_UV: u8 = 1 << 2;
pub(crate) const FLAG_BE: u8 = 1 << 3;
pub(crate) const FLAG_BS: u8 = 1 << 4;
pub(crate) const FLAG_AT: u8 = 1 << 6;
pub(crate) const FLAG_ED: u8 = 1 << 7;

#[derive(Debug)]
pub(crate) struct AuthenticatorData {
    pub rp_id_hash: [u8; 32],
    pub flags: u8,
    pub sign_count: u32,
    /// Present when the AT flag is set (registration; sometimes auth).
    pub attested: Option<AttestedCredentialData>,
}

#[derive(Debug)]
pub(crate) struct AttestedCredentialData {
    pub aaguid: [u8; 16],
    pub credential_id: CredentialId,
    pub public_key_cose: CosePublicKey,
}

impl AuthenticatorData {
    /// Strict binary parse. Returns the parsed struct AND a borrow of
    /// any unconsumed bytes (extensions / trailing data) so callers
    /// can use them when computing the signed message.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 37 {
            return Err(Error::AuthData("too short (need >= 37 bytes)"));
        }
        let mut rp_id_hash = [0u8; 32];
        rp_id_hash.copy_from_slice(&bytes[0..32]);
        let flags = bytes[32];
        let sign_count = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);

        let mut pos = 37_usize;
        let attested = if flags & FLAG_AT != 0 {
            if bytes.len() < pos + 18 {
                return Err(Error::AuthData("attestedCredentialData truncated header"));
            }
            let mut aaguid = [0u8; 16];
            aaguid.copy_from_slice(&bytes[pos..pos + 16]);
            pos += 16;
            let cred_id_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
            pos += 2;
            if cred_id_len > 1023 {
                return Err(Error::AuthData("credentialIdLength > 1023"));
            }
            if bytes.len() < pos + cred_id_len {
                return Err(Error::AuthData("credentialId truncated"));
            }
            let credential_id = CredentialId(bytes[pos..pos + cred_id_len].to_vec());
            pos += cred_id_len;

            // credentialPublicKey is a CBOR map; we need to determine
            // how many bytes it consumes so we can leave any extensions
            // alone. ciborium can tell us by deserializing once into a
            // CborValue and re-serializing to bytes.
            let tail = &bytes[pos..];
            let cose_len = cose_blob_length(tail)?;
            let public_key_cose = CosePublicKey(tail[..cose_len].to_vec());
            pos += cose_len;

            Some(AttestedCredentialData {
                aaguid,
                credential_id,
                public_key_cose,
            })
        } else {
            None
        };

        // With ED set the rest is the extensions CBOR map. No extension
        // is used, but the map must parse and fill the data exactly. With
        // ED clear, nothing may follow (WebAuthn-3 §6.1).
        if flags & FLAG_ED != 0 {
            let mut cur = std::io::Cursor::new(&bytes[pos..]);
            let extensions: CborValue = ciborium::de::from_reader(&mut cur)
                .map_err(|_| Error::AuthData("extensions CBOR parse failed"))?;
            if !extensions.is_map() {
                return Err(Error::AuthData("extensions are not a CBOR map"));
            }
            pos += cur.position() as usize;
        }
        if pos != bytes.len() {
            return Err(Error::AuthData("trailing bytes after authenticator data"));
        }

        Ok(Self {
            rp_id_hash,
            flags,
            sign_count,
            attested,
        })
    }

    pub(crate) fn user_present(&self) -> bool {
        self.flags & FLAG_UP != 0
    }
    pub(crate) fn user_verified(&self) -> bool {
        self.flags & FLAG_UV != 0
    }

    /// Refuses BS (backed up) without BE (backup eligible), the invalid
    /// combination of WebAuthn-3 §6.1.3.
    pub(crate) fn check_backup_flags(&self) -> Result<()> {
        match self.flags & (FLAG_BE | FLAG_BS) {
            FLAG_BS => Err(Error::AuthData("BS flag set without BE")),
            _ => Ok(()),
        }
    }
}

/// Read a single CBOR item from `data` and return the byte length it
/// occupies. ciborium does not expose a direct "how many bytes did you
/// consume" API, so we wrap the slice in a `std::io::Cursor` and read
/// its `position()` after the parse. Cursor's position-tracking is a
/// documented part of std::io, so this is robust to any future
/// internal-buffering change in ciborium (whereas the earlier
/// `data.len() - cur.len()` trick relied on an implementation detail of
/// the `Read for &[u8]` impl — fine today, fragile tomorrow).
fn cose_blob_length(data: &[u8]) -> Result<usize> {
    let mut cur = std::io::Cursor::new(data);
    let _: CborValue =
        ciborium::de::from_reader(&mut cur).map_err(|e| Error::Cbor(format!("cose key: {e}")))?;
    // Cursor::position() is u64 but our data is a single AuthData blob
    // (capped at ~1 KiB by spec); the conversion cannot truncate.
    Ok(cur.position() as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_auth_data() {
        // 32-byte rpIdHash + flags=0x05 (UP|UV) + counter=42, no attested data.
        let mut buf = Vec::with_capacity(37);
        buf.extend(std::iter::repeat_n(0xAB, 32));
        buf.push(0x05); // UP | UV
        buf.extend_from_slice(&42u32.to_be_bytes());
        let ad = AuthenticatorData::parse(&buf).unwrap();
        assert_eq!(ad.rp_id_hash, [0xAB; 32]);
        assert!(ad.user_present());
        assert!(ad.user_verified());
        assert_eq!(ad.sign_count, 42);
        assert!(ad.attested.is_none());
    }

    #[test]
    fn parse_with_attested_data() {
        // Build a minimal attested-credential-data block with a tiny
        // COSE key (CBOR map {1: 2}) so we exercise cose_blob_length.
        let mut buf = Vec::new();
        buf.extend(std::iter::repeat_n(0xAB, 32));
        buf.push(0x05 | FLAG_AT); // UP | UV | AT
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend(std::iter::repeat_n(0xCD, 16)); // aaguid
        buf.extend_from_slice(&3u16.to_be_bytes()); // credIdLength
        buf.extend_from_slice(&[1, 2, 3]); // credential id
        // Tiny CBOR map {1: 2} → 0xa1 0x01 0x02
        buf.extend_from_slice(&[0xa1, 0x01, 0x02]);
        let ad = AuthenticatorData::parse(&buf).unwrap();
        let att = ad.attested.unwrap();
        assert_eq!(att.aaguid, [0xCD; 16]);
        assert_eq!(att.credential_id.as_bytes(), &[1, 2, 3]);
        assert_eq!(att.public_key_cose.as_bytes(), &[0xa1, 0x01, 0x02]);
    }

    #[test]
    fn too_short_rejected() {
        assert!(AuthenticatorData::parse(&[0u8; 36]).is_err());
    }

    fn header(flags: u8) -> Vec<u8> {
        let mut buf = vec![0xAB; 32];
        buf.push(flags);
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf
    }

    #[test]
    fn trailing_bytes_without_ed_rejected() {
        let mut buf = header(FLAG_UP);
        buf.push(0xa0);
        assert!(AuthenticatorData::parse(&buf).is_err());
    }

    #[test]
    fn extensions_must_fill_the_rest_exactly() {
        let mut buf = header(FLAG_UP | FLAG_ED);
        assert!(AuthenticatorData::parse(&buf).is_err(), "ED set, no map");
        buf.extend_from_slice(&[0xa1, 0x61, b'x', 0xf5]); // {"x": true}
        assert!(AuthenticatorData::parse(&buf).is_ok());
        buf.push(0x00);
        assert!(
            AuthenticatorData::parse(&buf).is_err(),
            "byte after the map"
        );
        let mut not_map = header(FLAG_UP | FLAG_ED);
        not_map.push(0x01);
        assert!(
            AuthenticatorData::parse(&not_map).is_err(),
            "extensions not a map"
        );
    }

    #[test]
    fn backup_flag_combinations() {
        for (flags, ok) in [
            (0, true),
            (FLAG_BE, true),
            (FLAG_BE | FLAG_BS, true),
            (FLAG_BS, false),
        ] {
            let ad = AuthenticatorData::parse(&header(FLAG_UP | flags)).unwrap();
            assert_eq!(ad.check_backup_flags().is_ok(), ok, "flags {flags:#04x}");
        }
    }
}
