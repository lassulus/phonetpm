//! age recipient/identity encodings and the `piv-p256` stanza (the format used
//! by age-plugin-yubikey and Secure Enclave plugins, so files are
//! interoperable across those hardware backends).

use age_core::format::{FileKey, Stanza, FILE_KEY_BYTES};
use age_core::primitives::{aead_decrypt, aead_encrypt, hkdf};
use anyhow::{anyhow, bail, Result};
use base64::prelude::{Engine, BASE64_STANDARD_NO_PAD};
use bech32::{FromBase32, ToBase32, Variant};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use p256::PublicKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const PLUGIN_NAME: &str = "phone";
pub const RECIPIENT_HRP: &str = "age1phone";
pub const IDENTITY_HRP: &str = "age-plugin-phone-";
pub const STANZA_TAG: &str = "piv-p256";
const STANZA_KEY_LABEL: &[u8] = b"piv-p256";
const TAG_BYTES: usize = 4;
const POINT_BYTES: usize = 33;

fn compressed(pk: &PublicKey) -> [u8; POINT_BYTES] {
    pk.to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed P-256 point is 33 bytes")
}

fn point_from_bytes(bytes: &[u8]) -> Result<PublicKey> {
    if bytes.len() != POINT_BYTES {
        bail!("expected a {POINT_BYTES}-byte compressed point, got {} bytes", bytes.len());
    }
    PublicKey::from_sec1_bytes(bytes).map_err(|_| anyhow!("invalid P-256 point"))
}

fn bech32_decode(s: &str, want_hrp: &str) -> Result<Vec<u8>> {
    let (hrp, data, variant) = bech32::decode(s).map_err(|e| anyhow!("invalid bech32: {e}"))?;
    if hrp != want_hrp || variant != Variant::Bech32 {
        bail!("expected a {want_hrp} string, got {hrp}");
    }
    Vec::<u8>::from_base32(&data).map_err(|e| anyhow!("invalid bech32 payload: {e}"))
}

/// A phone key someone can encrypt to. Encoded as `age1phone1…`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient(PublicKey);

impl Recipient {
    pub fn from_spki(der: &[u8]) -> Result<Self> {
        PublicKey::from_public_key_der(der)
            .map(Self)
            .map_err(|e| anyhow!("invalid SPKI public key: {e}"))
    }

    /// From the raw payload of an `age1phone` bech32 string.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        point_from_bytes(bytes).map(Self)
    }

    pub fn decode(s: &str) -> Result<Self> {
        Self::from_bytes(&bech32_decode(s, RECIPIENT_HRP)?)
    }

    pub fn encode(&self) -> String {
        bech32::encode(RECIPIENT_HRP, compressed(&self.0).to_base32(), Variant::Bech32)
            .expect("valid hrp")
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.0
    }

    /// `sha256(compressed point)[..4]`: identifies the recipient in a stanza.
    fn tag(&self) -> [u8; TAG_BYTES] {
        Sha256::digest(compressed(&self.0))[..TAG_BYTES].try_into().unwrap()
    }

    /// Wraps `file_key` for this recipient with a fresh ephemeral key. Runs
    /// entirely on the host; the phone is only needed to unwrap.
    pub fn wrap(&self, file_key: &[u8; FILE_KEY_BYTES]) -> Stanza {
        let esk = EphemeralSecret::random(&mut OsRng);
        let epk = compressed(&esk.public_key());
        let shared = esk.diffie_hellman(&self.0);
        let key = wrap_key(&epk, &compressed(&self.0), shared.raw_secret_bytes());
        Stanza {
            tag: STANZA_TAG.to_owned(),
            args: vec![BASE64_STANDARD_NO_PAD.encode(self.tag()), BASE64_STANDARD_NO_PAD.encode(epk)],
            body: aead_encrypt(&key, file_key),
        }
    }
}

fn wrap_key(epk: &[u8; POINT_BYTES], rpk: &[u8; POINT_BYTES], shared_x: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut salt = [0u8; 2 * POINT_BYTES];
    salt[..POINT_BYTES].copy_from_slice(epk);
    salt[POINT_BYTES..].copy_from_slice(rpk);
    Zeroizing::new(hkdf(&salt, STANZA_KEY_LABEL, shared_x))
}

/// A reference to a key on the phone. Encoded as `AGE-PLUGIN-PHONE-1…`; the
/// payload is the compressed public point followed by the phone-side key id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    recipient: Recipient,
    key_id: String,
}

impl Identity {
    pub fn new(recipient: Recipient, key_id: String) -> Self {
        Self { recipient, key_id }
    }

    /// From the raw payload of an `AGE-PLUGIN-PHONE-` bech32 string.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() <= POINT_BYTES {
            bail!("identity payload too short");
        }
        let (point, id) = bytes.split_at(POINT_BYTES);
        let key_id = std::str::from_utf8(id).map_err(|_| anyhow!("key id is not UTF-8"))?;
        Ok(Self { recipient: Recipient::from_bytes(point)?, key_id: key_id.to_owned() })
    }

    pub fn decode(s: &str) -> Result<Self> {
        Self::from_bytes(&bech32_decode(s, IDENTITY_HRP)?)
    }

    pub fn encode(&self) -> String {
        let mut payload = compressed(&self.recipient.0).to_vec();
        payload.extend_from_slice(self.key_id.as_bytes());
        bech32::encode(IDENTITY_HRP, payload.to_base32(), Variant::Bech32)
            .expect("valid hrp")
            .to_uppercase()
    }

    pub fn recipient(&self) -> &Recipient {
        &self.recipient
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Whether `stanza` was wrapped to this identity's key.
    pub fn matches(&self, stanza: &ParsedStanza) -> bool {
        stanza.tag == self.recipient.tag()
    }

    /// Recovers the file key given the ECDH result from the phone for the
    /// stanza's ephemeral key (see [`ParsedStanza::ephemeral_spki`]).
    pub fn unwrap(&self, stanza: &ParsedStanza, shared_x: &[u8]) -> Result<FileKey> {
        if shared_x.len() != 32 {
            bail!("expected a 32-byte shared secret, got {} bytes", shared_x.len());
        }
        let key = wrap_key(&stanza.epk, &compressed(&self.recipient.0), shared_x);
        let pt = Zeroizing::new(
            aead_decrypt(&key, FILE_KEY_BYTES, &stanza.body)
                .map_err(|_| anyhow!("file key decryption failed"))?,
        );
        Ok(FileKey::init_with_mut(|fk| fk.copy_from_slice(&pt)))
    }
}

/// A validated `piv-p256` stanza.
pub struct ParsedStanza {
    tag: [u8; TAG_BYTES],
    epk: [u8; POINT_BYTES],
    body: Vec<u8>,
}

impl ParsedStanza {
    /// `Ok(None)` for stanzas of other types (which must be ignored);
    /// `Err` for a malformed `piv-p256` stanza.
    pub fn parse(stanza: &Stanza) -> Result<Option<Self>> {
        if stanza.tag != STANZA_TAG {
            return Ok(None);
        }
        let [tag, epk] = stanza.args.as_slice() else {
            bail!("{STANZA_TAG} stanza must have exactly two arguments");
        };
        let tag = BASE64_STANDARD_NO_PAD.decode(tag).map_err(|_| anyhow!("invalid tag encoding"))?;
        let tag = tag.as_slice().try_into().map_err(|_| anyhow!("tag must be {TAG_BYTES} bytes"))?;
        let epk = BASE64_STANDARD_NO_PAD.decode(epk).map_err(|_| anyhow!("invalid ephemeral key encoding"))?;
        let epk = compressed(&point_from_bytes(&epk)?);
        if stanza.body.len() != FILE_KEY_BYTES + 16 {
            bail!("invalid {STANZA_TAG} stanza body length {}", stanza.body.len());
        }
        Ok(Some(Self { tag, epk, body: stanza.body.clone() }))
    }

    /// The ephemeral public key as SPKI DER, ready for `Request::Ecdh`.
    pub fn ephemeral_spki(&self) -> Vec<u8> {
        PublicKey::from_sec1_bytes(&self.epk)
            .expect("validated in parse")
            .to_public_key_der()
            .expect("P-256 keys encode")
            .into_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use age_core::secrecy::ExposeSecret;
    use p256::SecretKey;

    fn phone_key() -> (SecretKey, Recipient) {
        let sk = SecretKey::random(&mut OsRng);
        let spki = sk.public_key().to_public_key_der().unwrap();
        let recipient = Recipient::from_spki(spki.as_bytes()).unwrap();
        (sk, recipient)
    }

    /// What the phone does for `Request::Ecdh`.
    fn phone_ecdh(sk: &SecretKey, peer_spki: &[u8]) -> Vec<u8> {
        let peer = PublicKey::from_public_key_der(peer_spki).unwrap();
        p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine())
            .raw_secret_bytes()
            .to_vec()
    }

    #[test]
    fn recipient_and_identity_round_trip() {
        let (_, recipient) = phone_key();
        let s = recipient.encode();
        assert!(s.starts_with("age1phone1"), "{s}");
        assert_eq!(Recipient::decode(&s).unwrap(), recipient);

        let identity = Identity::new(recipient.clone(), "phonetpm-age-3f2a".into());
        let s = identity.encode();
        assert!(s.starts_with("AGE-PLUGIN-PHONE-1"), "{s}");
        assert_eq!(s, s.to_uppercase());
        let decoded = Identity::decode(&s).unwrap();
        assert_eq!(decoded, identity);
        assert_eq!(decoded.key_id(), "phonetpm-age-3f2a");
        assert_eq!(decoded.recipient(), &recipient);

        // Wrong HRPs are rejected, not silently accepted.
        let x25519 = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
        assert!(Recipient::decode(x25519).is_err());
        assert!(Identity::decode(&recipient.encode()).is_err());
        assert!(Recipient::decode(&identity.encode()).is_err());
    }

    #[test]
    fn stanza_wrap_unwrap_round_trip() {
        let (sk, recipient) = phone_key();
        let identity = Identity::new(recipient.clone(), "k1".into());
        let file_key = [7u8; FILE_KEY_BYTES];

        let stanza = recipient.wrap(&file_key);
        assert_eq!(stanza.tag, "piv-p256");
        assert_eq!(stanza.args.len(), 2);
        assert_eq!(stanza.body.len(), FILE_KEY_BYTES + 16);

        let parsed = ParsedStanza::parse(&stanza).unwrap().expect("piv-p256 stanza");
        assert!(identity.matches(&parsed));
        let shared = phone_ecdh(&sk, &parsed.ephemeral_spki());
        assert_eq!(identity.unwrap(&parsed, &shared).unwrap().expose_secret(), &file_key);

        // A different phone key neither matches nor decrypts.
        let (other_sk, other_recipient) = phone_key();
        let other = Identity::new(other_recipient, "k2".into());
        assert!(!other.matches(&parsed));
        let wrong = phone_ecdh(&other_sk, &parsed.ephemeral_spki());
        assert!(other.unwrap(&parsed, &wrong).is_err());

        // Foreign stanzas are ignored; malformed piv-p256 ones are errors.
        let x25519 = Stanza { tag: "X25519".into(), args: vec!["abc".into()], body: vec![0; 32] };
        assert!(ParsedStanza::parse(&x25519).unwrap().is_none());
        let mut bad = recipient.wrap(&file_key);
        bad.args.pop();
        assert!(ParsedStanza::parse(&bad).is_err());
    }
}
