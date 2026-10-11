//! Phone-side transport: an iroh endpoint that accepts `phonetpm/1`
//! connections and hands every request to a foreign [`Handler`] (the Kotlin
//! app), which owns the Keystore and biometric UI.
//!
//! The Rust side is deliberately dumb: it does not know which peers are
//! paired, that is the handler's job (it gets the authenticated peer id).
//! Rust only asks [`Handler::accepts_peer`] right after the handshake so that
//! peers the app would refuse anyway cannot hold connection slots.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{presets, Connection, Incoming, QuicTransportConfig, RecvStream, SendStream, VarInt};
use iroh::{Endpoint, EndpointId, SecretKey};
use phonetpm_proto as proto;
use parking_lot::Mutex;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::Instant;

uniffi::setup_scaffolding!();

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum KeyKind {
    Ssh,
    Age,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct KeyInfo {
    pub id: String,
    pub label: String,
    pub kind: KeyKind,
    /// SPKI DER of the P-256 public key.
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum Request {
    Pair { host_name: String },
    ListKeys,
    Sign { key_id: String, data: Vec<u8>, description: Option<String> },
    Ecdh { key_id: String, peer_public_key: Vec<u8>, description: Option<String> },
    PushEndpoint,
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum Response {
    Paired { push_endpoint: Option<String> },
    Keys { keys: Vec<KeyInfo> },
    /// ASN.1 DER ECDSA signature.
    Signature { der: Vec<u8> },
    /// 32-byte x-coordinate of the shared point.
    SharedSecret { secret: Vec<u8> },
    Denied,
    UnknownKey,
    Error { message: String },
    /// UnifiedPush endpoint URL, `None` without a push distributor.
    PushEndpoint { endpoint: Option<String> },
}

impl From<proto::Request> for Request {
    fn from(r: proto::Request) -> Self {
        match r {
            proto::Request::Pair { host_name } => Request::Pair { host_name },
            proto::Request::ListKeys => Request::ListKeys,
            proto::Request::Sign { key_id, data, description } => {
                Request::Sign { key_id, data, description }
            }
            proto::Request::Ecdh { key_id, peer_public_key, description } => {
                Request::Ecdh { key_id, peer_public_key, description }
            }
            proto::Request::PushEndpoint => Request::PushEndpoint,
        }
    }
}

impl From<Response> for proto::Response {
    fn from(r: Response) -> Self {
        match r {
            Response::Paired { push_endpoint } => proto::Response::Paired { push_endpoint },
            Response::Keys { keys } => proto::Response::Keys(
                keys.into_iter()
                    .map(|k| proto::KeyInfo {
                        id: k.id,
                        label: k.label,
                        kind: match k.kind {
                            KeyKind::Ssh => proto::KeyKind::Ssh,
                            KeyKind::Age => proto::KeyKind::Age,
                        },
                        public_key: k.public_key,
                    })
                    .collect(),
            ),
            Response::Signature { der } => proto::Response::Signature(der),
            Response::SharedSecret { secret } => proto::Response::SharedSecret(secret),
            Response::Denied => proto::Response::Denied,
            Response::UnknownKey => proto::Response::UnknownKey,
            Response::Error { message } => proto::Response::Error(message),
            Response::PushEndpoint { endpoint } => proto::Response::PushEndpoint(endpoint),
        }
    }
}

/// Implemented by the app. `handle` is invoked on a blocking thread and may
/// take as long as the biometric prompt needs; requests are handled
/// concurrently, so the implementation must serialise UI itself.
#[uniffi::export(callback_interface)]
pub trait Handler: Send + Sync {
    fn handle(&self, peer_id: String, request: Request) -> Response;
    /// Whether connections from `peer_id` should be served at all: true iff
    /// the peer is paired or the pairing window is open. Called once per
    /// connection right after the handshake; must be cheap and never show UI.
    fn accepts_peer(&self, peer_id: String) -> bool;
}

#[derive(Debug, uniffi::Error)]
#[uniffi(flat_error)]
pub enum NodeError {
    InvalidSecretKey,
    Bind(String),
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeError::InvalidSecretKey => write!(f, "secret key must be 32 bytes"),
            NodeError::Bind(e) => write!(f, "bind: {e}"),
        }
    }
}

impl std::error::Error for NodeError {}

/// Random 32-byte iroh secret key; persist it so the endpoint id is stable.
#[uniffi::export]
pub fn generate_secret_key() -> Vec<u8> {
    SecretKey::generate().to_bytes().to_vec()
}

/// Endpoint id (hex) for a stored secret key, without binding.
#[uniffi::export]
pub fn endpoint_id_for(secret_key: Vec<u8>) -> Result<String, NodeError> {
    Ok(parse_secret(&secret_key)?.public().to_string())
}

fn parse_secret(bytes: &[u8]) -> Result<SecretKey, NodeError> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| NodeError::InvalidSecretKey)?;
    Ok(SecretKey::from_bytes(&arr))
}

#[derive(uniffi::Object)]
pub struct Node {
    rt: tokio::runtime::Runtime,
    ep: Endpoint,
}

#[uniffi::export]
impl Node {
    /// Bind the endpoint and start accepting connections. Blocks until bound.
    #[uniffi::constructor]
    pub fn start(secret_key: Vec<u8>, handler: Box<dyn Handler>) -> Result<Arc<Self>, NodeError> {
        init_logging();
        let secret = parse_secret(&secret_key)?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| NodeError::Bind(e.to_string()))?;
        // Remote peers are unauthenticated until the handler checks pairing,
        // so bound what any of them can make us hold: few streams per
        // connection, no uni streams (the protocol never uses them).
        let transport = QuicTransportConfig::builder()
            .max_concurrent_bidi_streams(VarInt::from_u32(MAX_STREAMS_PER_CONN))
            .max_concurrent_uni_streams(VarInt::from_u32(0))
            .build();
        let ep = rt
            .block_on(
                Endpoint::builder(presets::N0)
                    .secret_key(secret)
                    .alpns(vec![proto::ALPN.to_vec()])
                    .transport_config(transport)
                    .bind(),
            )
            .map_err(|e| NodeError::Bind(e.to_string()))?;
        let handler: Arc<dyn Handler> = Arc::from(handler);
        rt.spawn(accept_loop(ep.clone(), handler));
        tracing::info!(id = %ep.id(), "phonetpm node started");
        Ok(Arc::new(Node { rt, ep }))
    }

    pub fn endpoint_id(&self) -> String {
        self.ep.id().to_string()
    }

    /// Call after connectivity changes (wifi <-> cellular) to re-probe paths.
    pub fn network_changed(&self) {
        self.rt.block_on(self.ep.network_change());
    }

    /// Close the endpoint. The object is unusable afterwards.
    pub fn stop(&self) {
        let ep = self.ep.clone();
        self.rt.block_on(async move { ep.close().await });
    }
}

/// Concurrent in-flight handshakes; further incoming connections are refused.
const MAX_HANDSHAKES: usize = 32;
/// Concurrent accepted connections from all peers.
const MAX_CONNECTIONS: usize = 64;
/// Concurrent accepted connections from a single peer.
const MAX_CONNECTIONS_PER_PEER: usize = 4;
/// Concurrent bidi streams (requests) a single peer may open.
const MAX_STREAMS_PER_CONN: u32 = 4;
/// Concurrent handler calls, each occupying a blocking-pool thread.
const MAX_HANDLER_CALLS: usize = 8;
/// Deadline for a peer to deliver its complete request frame.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// A connection with no request in flight is closed after this long without
/// opening a stream (counted from the handshake or the last finished request).
const IDLE_TIMEOUT: Duration = Duration::from_secs(15);

/// Application close codes sent to the peer.
const CLOSE_NOT_ACCEPTED: u32 = 1;
const CLOSE_TOO_MANY: u32 = 2;
const CLOSE_IDLE: u32 = 3;

/// Counts live connections per peer and in total; a slot is released when its
/// [`ConnSlot`] is dropped.
struct ConnLimits<K: Eq + Hash> {
    per_peer: usize,
    total: usize,
    state: Mutex<ConnCounts<K>>,
}

struct ConnCounts<K> {
    total: usize,
    by_peer: HashMap<K, usize>,
}

struct ConnSlot<K: Eq + Hash + Clone> {
    limits: Arc<ConnLimits<K>>,
    peer: K,
}

impl<K: Eq + Hash + Clone> ConnLimits<K> {
    fn new(per_peer: usize, total: usize) -> Arc<Self> {
        Arc::new(ConnLimits {
            per_peer,
            total,
            state: Mutex::new(ConnCounts { total: 0, by_peer: HashMap::new() }),
        })
    }

    /// Take a slot for `peer`, or `None` if it or everyone is at the cap.
    fn try_acquire(self: &Arc<Self>, peer: K) -> Option<ConnSlot<K>> {
        let mut s = self.state.lock();
        if s.total >= self.total {
            return None;
        }
        let n = s.by_peer.entry(peer.clone()).or_insert(0);
        if *n >= self.per_peer {
            return None;
        }
        *n += 1;
        s.total += 1;
        Some(ConnSlot { limits: self.clone(), peer })
    }
}

impl<K: Eq + Hash + Clone> Drop for ConnSlot<K> {
    fn drop(&mut self) {
        let mut s = self.limits.state.lock();
        s.total -= 1;
        if let Some(n) = s.by_peer.get_mut(&self.peer) {
            *n -= 1;
            if *n == 0 {
                s.by_peer.remove(&self.peer);
            }
        }
    }
}

async fn accept_loop(ep: Endpoint, handler: Arc<dyn Handler>) {
    let handshakes = Arc::new(Semaphore::new(MAX_HANDSHAKES));
    let limits = ConnLimits::<EndpointId>::new(MAX_CONNECTIONS_PER_PEER, MAX_CONNECTIONS);
    let handler_calls = Arc::new(Semaphore::new(MAX_HANDLER_CALLS));
    while let Some(incoming) = ep.accept().await {
        let Ok(permit) = handshakes.clone().try_acquire_owned() else {
            tracing::warn!("handshake limit reached, refusing incoming connection");
            incoming.refuse();
            continue;
        };
        let handler = handler.clone();
        let limits = limits.clone();
        let handler_calls = handler_calls.clone();
        tokio::spawn(async move {
            // The handshake permit covers only the handshake and the cheap
            // admission check, never the lifetime of the connection.
            let admitted = admit(incoming, &handler, &limits).await;
            drop(permit);
            if let Some((conn, slot)) = admitted {
                serve_connection(conn, handler, handler_calls).await;
                drop(slot);
            }
        });
    }
}

/// Complete the handshake and decide whether to serve the connection: the
/// handler must accept the peer, and the peer must be within its connection
/// cap. Rejected connections are closed before any stream is accepted.
async fn admit(
    incoming: Incoming,
    handler: &Arc<dyn Handler>,
    limits: &Arc<ConnLimits<EndpointId>>,
) -> Option<(Connection, ConnSlot<EndpointId>)> {
    let conn = match incoming.await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("incoming connection failed: {e}");
            return None;
        }
    };
    let remote = conn.remote_id();
    let peer = remote.to_string();
    let h = handler.clone();
    let p = peer.clone();
    let accepted = tokio::task::spawn_blocking(move || h.accepts_peer(p))
        .await
        .unwrap_or(false);
    if !accepted {
        tracing::info!(%peer, "peer not accepted, closing connection");
        conn.close(VarInt::from_u32(CLOSE_NOT_ACCEPTED), b"not paired");
        return None;
    }
    let Some(slot) = limits.try_acquire(remote) else {
        tracing::warn!(%peer, "connection limit reached, closing connection");
        conn.close(VarInt::from_u32(CLOSE_TOO_MANY), b"too many connections");
        return None;
    };
    Some((conn, slot))
}

async fn serve_connection(
    conn: Connection,
    handler: Arc<dyn Handler>,
    handler_calls: Arc<Semaphore>,
) {
    let peer = conn.remote_id().to_string();
    tracing::info!(%peer, "connection accepted");
    let mut streams = JoinSet::new();
    let mut idle_deadline = Instant::now() + IDLE_TIMEOUT;
    loop {
        tokio::select! {
            accepted = conn.accept_bi() => {
                let (send, recv) = match accepted {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::info!(%peer, "connection closed: {e}");
                        break;
                    }
                };
                let handler = handler.clone();
                let handler_calls = handler_calls.clone();
                let peer = peer.clone();
                streams.spawn(async move {
                    if let Err(e) = serve_stream(peer.clone(), send, recv, handler, handler_calls).await {
                        tracing::warn!(%peer, "request failed: {e}");
                    }
                });
            }
            Some(_) = streams.join_next(), if !streams.is_empty() => {
                if streams.is_empty() {
                    idle_deadline = Instant::now() + IDLE_TIMEOUT;
                }
            }
            // Paused while any request is in flight.
            () = tokio::time::sleep_until(idle_deadline), if streams.is_empty() => {
                tracing::info!(%peer, "connection idle, closing");
                conn.close(VarInt::from_u32(CLOSE_IDLE), b"idle");
                break;
            }
        }
    }
    // A request still running must keep its handler permit until the
    // blocking handler call returns, so let the tasks finish on their own.
    streams.detach_all();
}

async fn read_request(recv: &mut RecvStream) -> Result<proto::Request, Box<dyn std::error::Error + Send + Sync>> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await?;
    let len = proto::check_len(u32::from_be_bytes(len))?;
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await?;
    Ok(proto::decode(&body)?)
}

async fn serve_stream(
    peer: String,
    mut send: SendStream,
    mut recv: RecvStream,
    handler: Arc<dyn Handler>,
    handler_calls: Arc<Semaphore>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let req = tokio::time::timeout(REQUEST_READ_TIMEOUT, read_request(&mut recv))
        .await
        .map_err(|_| "timed out reading request")??;
    let _permit = handler_calls.acquire_owned().await?;
    let resp = tokio::task::spawn_blocking(move || handler.handle(peer, req.into())).await?;
    let frame = proto::encode(&proto::Response::from(resp))?;
    send.write_all(&frame).await?;
    send.finish()?;
    // Keep the stream alive until the peer has read the response.
    let _ = tokio::time::timeout(Duration::from_secs(10), send.stopped()).await;
    Ok(())
}

#[cfg(target_os = "android")]
fn init_logging() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Info)
                .with_tag("phonetpm"),
        );
    });
}

#[cfg(not(target_os = "android"))]
fn init_logging() {}

/// Registers the JVM and application context with iroh so its DNS resolver
/// can read the system nameservers. Kotlin side:
/// `external fun nativeInit(ctx: Context)` in class `dev.phonetpm.app.Native`.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_dev_phonetpm_app_Native_nativeInit(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    ctx: jni::objects::JObject,
) {
    let vm = match env.get_java_vm() {
        Ok(vm) => vm.get_java_vm_pointer() as *mut std::ffi::c_void,
        Err(_) => return,
    };
    let Ok(global) = env.new_global_ref(ctx) else { return };
    let ctx_ptr = global.as_raw() as *mut std::ffi::c_void;
    std::mem::forget(global);
    unsafe { iroh::dns::install_android_jni_context(vm, ctx_ptr) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conn_limits_per_peer_and_total() {
        let limits = ConnLimits::<u8>::new(2, 3);
        let a1 = limits.try_acquire(1).unwrap();
        let a2 = limits.try_acquire(1).unwrap();
        assert!(limits.try_acquire(1).is_none(), "per-peer cap");
        let b1 = limits.try_acquire(2).unwrap();
        assert!(limits.try_acquire(3).is_none(), "total cap");
        drop(a1);
        assert!(limits.try_acquire(2).is_some(), "slot freed on drop");
        drop((a2, b1));
        let s = limits.state.lock();
        assert_eq!(s.total, 0);
        assert!(s.by_peer.is_empty());
    }
}
