//! ssh-agent protocol (draft-miller-ssh-agent) over a unix socket, backed by
//! the phone's `Ssh` keys.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use p256::ecdsa::Signature;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::DecodePublicKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::proto::{self, KeyInfo, KeyKind, Request, Response};
use crate::transport::{response_kind, Phone};

pub const KEY_TYPE: &str = "ecdsa-sha2-nistp256";
const CURVE: &str = "nistp256";

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

const MAX_MESSAGE: usize = 256 * 1024;
const CACHE_TTL: Duration = Duration::from_secs(60);

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// SSH `mpint`: big-endian, minimal, with a leading zero when the high bit is set.
fn put_mpint(out: &mut Vec<u8>, n: &[u8]) {
    let start = n.iter().position(|&b| b != 0).unwrap_or(n.len());
    let n = &n[start..];
    let pad = n.first().is_some_and(|b| b & 0x80 != 0) as usize;
    out.extend_from_slice(&((n.len() + pad) as u32).to_be_bytes());
    if pad == 1 {
        out.push(0);
    }
    out.extend_from_slice(n);
}

fn get_string<'a>(buf: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (len, rest) = buf.split_first_chunk::<4>()?;
    let len = u32::from_be_bytes(*len) as usize;
    if rest.len() < len {
        return None;
    }
    let (s, rest) = rest.split_at(len);
    *buf = rest;
    Some(s)
}

/// Uncompressed SEC1 point (65 bytes) from SPKI DER.
pub fn spki_to_point(spki: &[u8]) -> Result<Vec<u8>> {
    let pk = p256::PublicKey::from_public_key_der(spki).map_err(|e| anyhow!("bad SPKI: {e}"))?;
    Ok(pk.to_encoded_point(false).as_bytes().to_vec())
}

/// Public key blob: `string "ecdsa-sha2-nistp256" || string "nistp256" || string point`.
pub fn key_blob(point: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 * 3 + KEY_TYPE.len() + CURVE.len() + point.len());
    put_string(&mut out, KEY_TYPE.as_bytes());
    put_string(&mut out, CURVE.as_bytes());
    put_string(&mut out, point);
    out
}

/// DER `ECDSA-Sig-Value` → `string "ecdsa-sha2-nistp256" || string(mpint r || mpint s)`.
pub fn der_to_ssh_signature(der: &[u8]) -> Result<Vec<u8>> {
    let sig = Signature::from_der(der).map_err(|e| anyhow!("bad DER signature: {e}"))?;
    let (r, s) = sig.split_bytes();
    let mut inner = Vec::with_capacity(2 * (4 + 33));
    put_mpint(&mut inner, &r);
    put_mpint(&mut inner, &s);
    let mut out = Vec::with_capacity(4 + KEY_TYPE.len() + 4 + inner.len());
    put_string(&mut out, KEY_TYPE.as_bytes());
    put_string(&mut out, &inner);
    Ok(out)
}

/// Parses `string key_blob || string data || uint32 flags`.
fn parse_sign_request(mut payload: &[u8]) -> Option<(&[u8], &[u8])> {
    let blob = get_string(&mut payload)?;
    let data = get_string(&mut payload)?;
    (payload.len() == 4).then_some((blob, data))
}

const SSH_MSG_USERAUTH_REQUEST: u8 = 50;

/// What is being signed, for the phone's prompt: an `SSHSIG` blob from
/// `ssh-keygen -Y sign` (git signing among others) or an SSH userauth request.
/// `None` when the data is neither.
fn describe(data: &[u8]) -> Option<String> {
    let text = if let Some(mut rest) = data.strip_prefix(b"SSHSIG") {
        // byte[6] "SSHSIG" || string namespace || string reserved || string hash_alg || string H(message)
        let ns = String::from_utf8_lossy(get_string(&mut rest)?);
        if ns == "git" {
            "git commit/tag signing (ssh-keygen signature, namespace git)".to_owned()
        } else {
            format!("ssh-keygen signature, namespace {ns}")
        }
    } else {
        // string session_id || byte 50 || string user || string service || string "publickey" || ...
        let mut rest = data;
        get_string(&mut rest)?;
        let (&msg, mut rest) = rest.split_first()?;
        if msg != SSH_MSG_USERAUTH_REQUEST {
            return None;
        }
        let user = get_string(&mut rest)?;
        get_string(&mut rest)?;
        if get_string(&mut rest)? != b"publickey" {
            return None;
        }
        format!("SSH login as {}", String::from_utf8_lossy(user))
    };
    Some(proto::sanitize_text(&text, proto::MAX_DESCRIPTION_CHARS))
}

fn identities_answer(keys: &[(Vec<u8>, String)]) -> Vec<u8> {
    let mut out = vec![SSH_AGENT_IDENTITIES_ANSWER];
    out.extend_from_slice(&(keys.len() as u32).to_be_bytes());
    for (blob, comment) in keys {
        put_string(&mut out, blob);
        put_string(&mut out, comment.as_bytes());
    }
    out
}

struct CachedKey {
    id: String,
    blob: Vec<u8>,
    label: String,
}

fn cache_entries(keys: Vec<KeyInfo>) -> Vec<CachedKey> {
    keys.into_iter()
        .filter(|k| k.kind == KeyKind::Ssh)
        .filter_map(|k| match spki_to_point(&k.public_key) {
            Ok(point) => Some(CachedKey { id: k.id, blob: key_blob(&point), label: k.label }),
            Err(e) => {
                warn!(key = %k.id, "skipping key with unparsable public key: {e}");
                None
            }
        })
        .collect()
}

pub struct Agent {
    phone: Arc<Phone>,
    cache: Mutex<Option<(Instant, Arc<Vec<CachedKey>>)>>,
}

impl Agent {
    pub fn new(phone: Arc<Phone>) -> Self {
        Self { phone, cache: Mutex::new(None) }
    }

    /// Cached `Ssh` keys, refreshed from the phone after [`CACHE_TTL`] or when
    /// `force` is set. Failures are not cached.
    async fn keys(&self, force: bool) -> Result<Arc<Vec<CachedKey>>> {
        let mut cache = self.cache.lock().await;
        if !force {
            if let Some((at, keys)) = cache.as_ref() {
                if at.elapsed() < CACHE_TTL {
                    return Ok(keys.clone());
                }
            }
        }
        let keys = match self.phone.request(&Request::ListKeys).await? {
            Response::Keys(keys) => Arc::new(cache_entries(keys)),
            Response::Denied => bail!("phone denied key listing (host not paired?)"),
            other => bail!("unexpected response to ListKeys: {}", response_kind(&other)),
        };
        *cache = Some((Instant::now(), keys.clone()));
        Ok(keys)
    }

    async fn find_key(&self, blob: &[u8]) -> Result<Option<(String, String)>> {
        let hit = |keys: &[CachedKey]| {
            keys.iter().find(|k| k.blob == blob).map(|k| (k.id.clone(), k.label.clone()))
        };
        if let Some(found) = hit(&self.keys(false).await?) {
            return Ok(Some(found));
        }
        Ok(hit(&self.keys(true).await?))
    }

    async fn handle_message(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let (&kind, payload) = msg.split_first().ok_or_else(|| anyhow!("empty agent message"))?;
        match kind {
            SSH_AGENTC_REQUEST_IDENTITIES => {
                let keys = match self.keys(false).await {
                    Ok(keys) => keys,
                    Err(e) => {
                        warn!("listing keys failed, answering with no identities: {e:#}");
                        return Ok(identities_answer(&[]));
                    }
                };
                let list: Vec<_> =
                    keys.iter().map(|k| (k.blob.clone(), k.label.clone())).collect();
                Ok(identities_answer(&list))
            }
            SSH_AGENTC_SIGN_REQUEST => {
                let (blob, data) =
                    parse_sign_request(payload).ok_or_else(|| anyhow!("malformed sign request"))?;
                let (key_id, label) =
                    self.find_key(blob).await?.ok_or_else(|| anyhow!("unknown key in sign request"))?;
                info!(key = %label, "requesting signature from phone");
                let req = Request::Sign { key_id, data: data.to_vec(), description: describe(data) };
                let der = match self.phone.request(&req).await? {
                    Response::Signature(der) => der,
                    Response::Denied => bail!("phone denied the signature"),
                    Response::UnknownKey => bail!("phone no longer has key {label}"),
                    other => bail!("unexpected response to Sign: {}", response_kind(&other)),
                };
                let mut out = vec![SSH_AGENT_SIGN_RESPONSE];
                put_string(&mut out, &der_to_ssh_signature(&der)?);
                Ok(out)
            }
            other => bail!("unsupported agent message type {other}"),
        }
    }

    async fn handle_client(&self, mut stream: UnixStream) -> Result<()> {
        loop {
            let mut len = [0u8; 4];
            match stream.read_exact(&mut len).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(e) => return Err(e.into()),
            }
            let len = u32::from_be_bytes(len) as usize;
            if len == 0 || len > MAX_MESSAGE {
                bail!("agent message length {len} out of range");
            }
            let mut msg = vec![0u8; len];
            stream.read_exact(&mut msg).await?;
            let reply = match self.handle_message(&msg).await {
                Ok(reply) => reply,
                Err(e) => {
                    warn!("agent request failed: {e:#}");
                    vec![SSH_AGENT_FAILURE]
                }
            };
            stream.write_all(&(reply.len() as u32).to_be_bytes()).await?;
            stream.write_all(&reply).await.context("writing agent reply")?;
        }
    }
}

pub async fn serve(listener: UnixListener, agent: Arc<Agent>) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("agent accept failed: {e}");
                continue;
            }
        };
        let agent = agent.clone();
        tokio::spawn(async move {
            if let Err(e) = agent.handle_client(stream).await {
                debug!("agent client error: {e:#}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{
        signature::{Signer, Verifier},
        SigningKey, VerifyingKey,
    };
    use p256::pkcs8::EncodePublicKey;

    fn get_mpint(buf: &mut &[u8]) -> [u8; 32] {
        let m = get_string(buf).expect("mpint");
        assert!(!m.is_empty() && m.len() <= 33, "mpint length {}", m.len());
        assert!(m.len() == 1 || m[0] != 0 || m[1] & 0x80 != 0, "non-minimal mpint {m:02x?}");
        assert!(m[0] & 0x80 == 0, "negative mpint");
        let mut out = [0u8; 32];
        let n = m.strip_prefix(&[0]).unwrap_or(m);
        out[32 - n.len()..].copy_from_slice(n);
        out
    }

    #[test]
    fn der_signature_converts_to_ssh_wire_format_and_verifies() {
        let sk = SigningKey::random(&mut rand::rngs::OsRng);
        let vk = VerifyingKey::from(&sk);
        let data = b"ssh session id and request";
        // Several signatures so that high-bit / leading-zero cases both get exercised.
        for i in 0..32u8 {
            let mut msg = data.to_vec();
            msg.push(i);
            let sig: Signature = sk.sign(&msg);
            let ssh = der_to_ssh_signature(sig.to_der().as_bytes()).unwrap();

            let mut buf = ssh.as_slice();
            assert_eq!(get_string(&mut buf).unwrap(), KEY_TYPE.as_bytes());
            let mut inner = get_string(&mut buf).unwrap();
            assert!(buf.is_empty());
            let r = get_mpint(&mut inner);
            let s = get_mpint(&mut inner);
            assert!(inner.is_empty());

            let rebuilt = Signature::from_scalars(r, s).unwrap();
            assert_eq!(rebuilt, sig);
            vk.verify(&msg, &rebuilt).unwrap();
        }
    }

    #[test]
    fn mpint_encoding_edge_cases() {
        let enc = |n: &[u8]| {
            let mut out = Vec::new();
            put_mpint(&mut out, n);
            out
        };
        assert_eq!(enc(&[0, 0, 0x7f]), [0, 0, 0, 1, 0x7f]);
        assert_eq!(enc(&[0, 0x80]), [0, 0, 0, 2, 0, 0x80]);
        assert_eq!(enc(&[0, 0]), [0, 0, 0, 0]);
    }

    #[test]
    fn key_blob_round_trips_through_spki() {
        let sk = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let spki = sk.public_key().to_public_key_der().unwrap();
        let point = spki_to_point(spki.as_bytes()).unwrap();
        assert_eq!(point.len(), 65);
        assert_eq!(point[0], 4);
        let blob = key_blob(&point);
        let mut buf = blob.as_slice();
        assert_eq!(get_string(&mut buf).unwrap(), b"ecdsa-sha2-nistp256");
        assert_eq!(get_string(&mut buf).unwrap(), b"nistp256");
        assert_eq!(get_string(&mut buf).unwrap(), &point[..]);
        assert!(buf.is_empty());
    }

    #[test]
    fn describes_sshsig_blobs() {
        // As built by ssh-keygen -Y sign (sshsig.c, PROTOCOL.sshsig).
        let blob = |ns: &[u8]| {
            let mut b = b"SSHSIG".to_vec();
            put_string(&mut b, ns);
            put_string(&mut b, b"");
            put_string(&mut b, b"sha512");
            put_string(&mut b, &[0xab; 64]);
            b
        };
        assert_eq!(
            describe(&blob(b"git")).unwrap(),
            "git commit/tag signing (ssh-keygen signature, namespace git)"
        );
        assert_eq!(describe(&blob(b"file")).unwrap(), "ssh-keygen signature, namespace file");
        // Control and bidi characters in the namespace do not reach the phone.
        assert_eq!(
            describe(&blob("fi\u{202e}le\nx".as_bytes())).unwrap(),
            "ssh-keygen signature, namespace file x"
        );
        assert_eq!(describe(b"SSHSIG\0\0"), None);
    }

    #[test]
    fn describes_userauth_requests() {
        // RFC 4252 section 7 signed data for publickey authentication.
        let mut data = Vec::new();
        put_string(&mut data, &[0x11; 32]);
        data.push(SSH_MSG_USERAUTH_REQUEST);
        put_string(&mut data, b"alice");
        put_string(&mut data, b"ssh-connection");
        put_string(&mut data, b"publickey");
        data.push(1);
        put_string(&mut data, KEY_TYPE.as_bytes());
        put_string(&mut data, b"keyblob");
        assert_eq!(describe(&data).unwrap(), "SSH login as alice");

        let mut other = Vec::new();
        put_string(&mut other, &[0x11; 32]);
        other.push(SSH_MSG_USERAUTH_REQUEST);
        put_string(&mut other, b"alice");
        put_string(&mut other, b"ssh-connection");
        put_string(&mut other, b"hostbased");
        assert_eq!(describe(&other), None);
        assert_eq!(describe(b"arbitrary data"), None);
        assert_eq!(describe(b""), None);
    }

    #[test]
    fn sign_request_parsing() {
        let mut payload = Vec::new();
        put_string(&mut payload, b"blob");
        put_string(&mut payload, b"data");
        payload.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(parse_sign_request(&payload), Some((&b"blob"[..], &b"data"[..])));
        assert_eq!(parse_sign_request(&payload[..payload.len() - 1]), None);
        assert_eq!(parse_sign_request(&payload[..5]), None);
    }
}
