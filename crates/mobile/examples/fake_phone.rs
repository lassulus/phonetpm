//! In-memory stand-in for the Android app: runs the real iroh node with
//! software P-256 keys and auto-approves everything. For smoke tests only.
//!
//! Usage: `cargo run -p phonetpm-mobile --example fake_phone` and pass the
//! printed endpoint id to `phonetpm pair`.

use std::collections::HashSet;
use parking_lot::Mutex;

use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use p256::{PublicKey, SecretKey};
use phonetpm_mobile::{Handler, KeyInfo, KeyKind, Node, Request, Response};

struct FakeKey {
    info: KeyInfo,
    secret: SecretKey,
}

struct FakePhone {
    keys: Vec<FakeKey>,
    paired: Mutex<HashSet<String>>,
}

impl FakePhone {
    fn new() -> Self {
        let mut rng = rand::thread_rng();
        let mut mk = |id: &str, label: &str, kind: KeyKind| {
            let secret = SecretKey::random(&mut rng);
            let public_key = secret.public_key().to_public_key_der().unwrap().into_vec();
            FakeKey {
                info: KeyInfo { id: id.into(), label: label.into(), kind, public_key },
                secret,
            }
        };
        FakePhone {
            keys: vec![
                mk("0123456789abcdef", "fake ssh", KeyKind::Ssh),
                mk("fedcba9876543210", "fake age", KeyKind::Age),
            ],
            paired: Mutex::new(HashSet::new()),
        }
    }

    fn key(&self, id: &str) -> Option<&FakeKey> {
        self.keys.iter().find(|k| k.info.id == id)
    }
}

impl Handler for FakePhone {
    fn handle(&self, peer_id: String, request: Request) -> Response {
        eprintln!("[fake_phone] {peer_id}: {request:?}");
        if let Request::Pair { host_name } = &request {
            eprintln!("[fake_phone] auto-approving pair from {host_name}");
            self.paired.lock().insert(peer_id);
            return Response::Paired { push_endpoint: push_endpoint() };
        }
        if !self.paired.lock().contains(&peer_id) {
            return Response::Denied;
        }
        match request {
            Request::Pair { .. } => unreachable!(),
            Request::PushEndpoint => Response::PushEndpoint { endpoint: push_endpoint() },
            Request::ListKeys => {
                Response::Keys { keys: self.keys.iter().map(|k| k.info.clone()).collect() }
            }
            Request::Sign { key_id, data } => match self.key(&key_id) {
                Some(k) if k.info.kind == KeyKind::Ssh => {
                    let sig: Signature = SigningKey::from(&k.secret).sign(&data);
                    Response::Signature { der: sig.to_der().as_bytes().to_vec() }
                }
                Some(_) => Response::Error { message: "not a signing key".into() },
                None => Response::UnknownKey,
            },
            Request::Ecdh { key_id, peer_public_key } => match self.key(&key_id) {
                Some(k) if k.info.kind == KeyKind::Age => {
                    let peer = match PublicKey::from_public_key_der(&peer_public_key) {
                        Ok(p) => p,
                        Err(e) => return Response::Error { message: e.to_string() },
                    };
                    let shared =
                        p256::ecdh::diffie_hellman(k.secret.to_nonzero_scalar(), peer.as_affine());
                    Response::SharedSecret { secret: shared.raw_secret_bytes().to_vec() }
                }
                Some(_) => Response::Error { message: "not an agreement key".into() },
                None => Response::UnknownKey,
            },
        }
    }
}

/// `FAKE_PHONE_PUSH_ENDPOINT` is reported as the UnifiedPush endpoint.
fn push_endpoint() -> Option<String> {
    std::env::var("FAKE_PHONE_PUSH_ENDPOINT").ok().filter(|s| !s.is_empty())
}

fn main() {
    let secret = std::env::var("FAKE_PHONE_KEY")
        .ok()
        .map(|hex| hex_decode(&hex))
        .unwrap_or_else(phonetpm_mobile::generate_secret_key);
    let node = Node::start(secret, Box::new(FakePhone::new())).expect("start node");
    println!("{}", node.endpoint_id());
    loop {
        std::thread::park();
    }
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
