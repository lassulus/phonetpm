//! Wire protocol between the host daemon and the phone.
//!
//! Transport: one iroh QUIC bi-directional stream per request. The initiator
//! writes exactly one length-prefixed [`Request`] and calls `finish()`; the
//! phone answers with exactly one length-prefixed [`Response`] and finishes.
//! Framing is a big-endian `u32` byte length followed by a postcard-encoded
//! message. The same framing is used on the host's local control socket.
//!
//! All public keys are X.509 `SubjectPublicKeyInfo` DER (P-256, uncompressed
//! point). Signatures are ASN.1 DER `ECDSA-Sig-Value` over SHA-256 of `data`.

use serde::{Deserialize, Serialize};

/// ALPN for the phone<->host QUIC connection.
pub const ALPN: &[u8] = b"phonetpm/1";

/// Upper bound on a single framed message (SSH sign payloads are small; age
/// ECDH is a single point).
pub const MAX_FRAME: usize = 64 * 1024;

/// Maximum length (in chars) of a request description shown on the phone.
pub const MAX_DESCRIPTION_CHARS: usize = 200;

/// Maximum length (in chars) of a host or key name shown on the phone.
pub const MAX_NAME_CHARS: usize = 64;

/// Make peer-supplied text safe to display: drops control (Cc) and format
/// (Cf: bidi overrides/isolates, zero-width chars, ...) characters, collapses
/// whitespace runs (including newlines) to one space, trims, and truncates
/// to `max_chars` chars, ending in '…' when truncated.
pub fn sanitize_text(s: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut pending_space = false;
    for c in s.chars() {
        if c.is_whitespace() {
            pending_space = !out.is_empty();
        } else if !is_control_or_format(c) {
            if pending_space {
                out.push(' ');
                pending_space = false;
            }
            out.push(c);
        }
    }
    if out.chars().count() <= max_chars {
        return out;
    }
    let mut cut: String = out.chars().take(max_chars.saturating_sub(1)).collect();
    cut.truncate(cut.trim_end().len());
    cut.push('…');
    cut
}

/// Unicode general categories Cc and Cf (Cf list per Unicode 15.1).
fn is_control_or_format(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061C}'
                | '\u{06DD}'
                | '\u{070F}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08E2}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206F}'
                | '\u{FEFF}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{110BD}'
                | '\u{110CD}'
                | '\u{13430}'..='\u{1343F}'
                | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D173}'..='\u{1D17A}'
                | '\u{E0001}'
                | '\u{E0020}'..='\u{E007F}'
        )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyKind {
    /// ECDSA P-256 signing key, exposed as `ecdsa-sha2-nistp256` via ssh-agent.
    Ssh,
    /// ECDH P-256 key, exposed as an age `piv-p256` identity.
    Age,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyInfo {
    /// Phone-side keystore alias. Opaque, stable, ASCII.
    pub id: String,
    /// Human label chosen on the phone.
    pub label: String,
    pub kind: KeyKind,
    /// SPKI DER of the P-256 public key.
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// First message from an unknown host. The phone prompts the user to
    /// allow the calling endpoint id; `host_name` is display-only.
    Pair { host_name: String },
    ListKeys,
    /// Sign `data` with the P-256 key `key_id` (SHA256withECDSA).
    /// `description` is free text from the requester, shown on the phone.
    Sign { key_id: String, data: Vec<u8>, description: Option<String> },
    /// ECDH between key `key_id` and `peer_public_key` (SPKI DER). Returns the
    /// raw 32-byte x-coordinate of the shared point. `description` is free text
    /// from the requester, shown on the phone next to the key.
    Ecdh { key_id: String, peer_public_key: Vec<u8>, description: Option<String> },
    /// Asks for the phone's current UnifiedPush endpoint. Hosts send it on
    /// every new connection, as the distributor may change the endpoint.
    PushEndpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    /// `push_endpoint`: see [`Response::PushEndpoint`].
    Paired { push_endpoint: Option<String> },
    Keys(Vec<KeyInfo>),
    Signature(Vec<u8>),
    SharedSecret(Vec<u8>),
    /// User declined on the phone, or the host is not paired.
    Denied,
    UnknownKey,
    Error(String),
    /// UnifiedPush endpoint URL that wakes the phone when the host POSTs to
    /// it, or `None` if the phone listens permanently (no push distributor).
    PushEndpoint(Option<String>),
}

#[derive(Debug)]
pub enum FrameError {
    TooLarge(usize),
    Codec(postcard::Error),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::TooLarge(n) => write!(f, "frame of {n} bytes exceeds {MAX_FRAME}"),
            FrameError::Codec(e) => write!(f, "postcard: {e}"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<postcard::Error> for FrameError {
    fn from(e: postcard::Error) -> Self {
        FrameError::Codec(e)
    }
}

/// Encode `msg` as `u32be len || postcard`.
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, FrameError> {
    let body = postcard::to_stdvec(msg)?;
    if body.len() > MAX_FRAME {
        return Err(FrameError::TooLarge(body.len()));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Validate a frame length read from the wire.
pub fn check_len(len: u32) -> Result<usize, FrameError> {
    let len = len as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    Ok(len)
}

/// Decode a frame body (without the length prefix).
pub fn decode<'a, T: Deserialize<'a>>(body: &'a [u8]) -> Result<T, FrameError> {
    Ok(postcard::from_bytes(body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let req = Request::Sign { key_id: "k1".into(), data: vec![1, 2, 3], description: None };
        let bytes = encode(&req).unwrap();
        let len = u32::from_be_bytes(bytes[..4].try_into().unwrap());
        assert_eq!(check_len(len).unwrap(), bytes.len() - 4);
        let back: Request = decode(&bytes[4..]).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn push_endpoint_roundtrip() {
        for resp in [
            Response::Paired { push_endpoint: Some("https://ntfy.sh/upAbc?up=1".into()) },
            Response::PushEndpoint(None),
        ] {
            let bytes = encode(&resp).unwrap();
            assert_eq!(decode::<Response>(&bytes[4..]).unwrap(), resp);
        }
    }

    #[test]
    fn sanitize_strips_bidi_and_zero_width() {
        assert_eq!(sanitize_text("ab\u{202E}cd\u{200B}ef\u{2066}g\u{FEFF}", 64), "abcdefg");
    }

    #[test]
    fn sanitize_collapses_whitespace_and_controls() {
        assert_eq!(sanitize_text("  git\r\n\n push \t origin\x1b[31m ", 64), "git push origin[31m");
    }

    #[test]
    fn sanitize_truncates_on_char_boundary() {
        assert_eq!(sanitize_text("äöüäöü", 6), "äöüäöü");
        assert_eq!(sanitize_text("äöüäöüx", 6), "äöüäö…");
        assert_eq!(sanitize_text("ab cd", 4), "ab…");
    }

    #[test]
    fn sanitize_empty_result() {
        assert_eq!(sanitize_text("\u{202E}\n\u{200B} \x07", 10), "");
    }
}
