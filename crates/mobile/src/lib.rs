//! Phone-side transport: an iroh endpoint that accepts `phonetpm/1`
//! connections and hands every request to a foreign [`Handler`] (the Kotlin
//! app), which owns the Keystore and biometric UI.
//!
//! The Rust side is deliberately dumb: it does not know which peers are
//! paired, that is the handler's job (it gets the authenticated peer id).

use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{presets, Connection, RecvStream, SendStream};
use iroh::{Endpoint, SecretKey};
use phonetpm_proto as proto;

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
    Sign { key_id: String, data: Vec<u8> },
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
            proto::Request::Sign { key_id, data } => Request::Sign { key_id, data },
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
        let ep = rt
            .block_on(
                Endpoint::builder(presets::N0)
                    .secret_key(secret)
                    .alpns(vec![proto::ALPN.to_vec()])
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

async fn accept_loop(ep: Endpoint, handler: Arc<dyn Handler>) {
    while let Some(incoming) = ep.accept().await {
        let handler = handler.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("incoming connection failed: {e}");
                    return;
                }
            };
            serve_connection(conn, handler).await;
        });
    }
}

async fn serve_connection(conn: Connection, handler: Arc<dyn Handler>) {
    let peer = conn.remote_id().to_string();
    tracing::info!(%peer, "connection accepted");
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(e) => {
                tracing::info!(%peer, "connection closed: {e}");
                return;
            }
        };
        let handler = handler.clone();
        let peer = peer.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_stream(peer.clone(), send, recv, handler).await {
                tracing::warn!(%peer, "request failed: {e}");
            }
        });
    }
}

async fn serve_stream(
    peer: String,
    mut send: SendStream,
    mut recv: RecvStream,
    handler: Arc<dyn Handler>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await?;
    let len = proto::check_len(u32::from_be_bytes(len))?;
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await?;
    let req: proto::Request = proto::decode(&body)?;
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
