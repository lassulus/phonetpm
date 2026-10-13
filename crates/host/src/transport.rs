//! iroh transport to the phone: one bi-stream per request, lazily connected,
//! connection reused and re-established once on failure. A phone that sleeps
//! between requests is woken via its UnifiedPush endpoint before connecting.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use iroh::endpoint::{presets, Connection};
use iroh::{Endpoint, EndpointId, SecretKey};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::config;
use crate::proto::{self, Request, Response};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// How long a phone woken by a push gets to come up.
const WAKE_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const WAKE_RETRY: Duration = Duration::from_secs(1);
const PUSH_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound on one request round trip, including the user's fingerprint prompt.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(90);

pub async fn bind(secret_key: SecretKey) -> Result<Endpoint> {
    Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .bind()
        .await
        .context("binding iroh endpoint")
}

pub struct Phone {
    endpoint: Endpoint,
    id: EndpointId,
    conn: Mutex<Option<Connection>>,
    last_request: std::sync::Mutex<Instant>,
    push: Option<Arc<Push>>,
}

impl Phone {
    pub fn new(endpoint: Endpoint, id: EndpointId) -> Self {
        Self {
            endpoint,
            id,
            conn: Mutex::new(None),
            last_request: std::sync::Mutex::new(Instant::now()),
            push: None,
        }
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Time since the last request started or finished (or since creation).
    pub fn idle_for(&self) -> Duration {
        self.last_request.lock().expect("not poisoned").elapsed()
    }

    fn touch(&self) {
        *self.last_request.lock().expect("not poisoned") = Instant::now();
    }

    /// Enables waking the phone via UnifiedPush and keeping its endpoint (and
    /// the config file) up to date. Without this the phone must be listening.
    pub fn with_push(mut self, endpoint: Option<String>) -> Result<Self> {
        self.push = Some(Arc::new(Push::new(endpoint)?));
        Ok(self)
    }

    async fn connect_once(&self, timeout: Duration) -> Result<Connection> {
        tokio::time::timeout(timeout, self.endpoint.connect(self.id, proto::ALPN))
            .await
            .map_err(|_| anyhow!("timed out connecting to phone"))?
            .context("connecting to phone")
    }

    /// Connects, first waking the phone if it has a push endpoint. A woken
    /// phone needs a few seconds to start its endpoint, so keep retrying.
    async fn connect(&self) -> Result<Connection> {
        info!(phone = %self.id.fmt_short(), "connecting to phone");
        let Some(push) = &self.push else { return self.connect_once(CONNECT_TIMEOUT).await };
        let conn = match push.endpoint() {
            None => self.connect_once(CONNECT_TIMEOUT).await?,
            Some(url) => {
                let pushed = push.wake(&url).await;
                if let Err(e) = &pushed {
                    warn!("wake push failed ({e:#}); trying to connect anyway");
                }
                let deadline = Instant::now() + WAKE_CONNECT_TIMEOUT;
                loop {
                    let left = deadline.saturating_duration_since(Instant::now());
                    match self.connect_once(left).await {
                        Ok(conn) => break conn,
                        Err(e) if left > WAKE_RETRY => {
                            debug!("phone not up yet: {e:#}");
                            tokio::time::sleep(WAKE_RETRY).await;
                        }
                        Err(e) => {
                            return Err(match pushed {
                                Ok(()) => e.context("phone did not come up after the wake push"),
                                Err(p) => e.context(format!(
                                    "wake push failed: {p:#}; phone did not come up"
                                )),
                            })
                        }
                    }
                }
            }
        };
        let (push, refresh) = (push.clone(), conn.clone());
        tokio::spawn(async move { push.refresh(&refresh).await });
        Ok(conn)
    }

    /// Sends one request; on transport failure drops the cached connection and
    /// retries exactly once on a fresh one.
    pub async fn request(&self, req: &Request) -> Result<Response> {
        self.touch();
        let resp = self.request_inner(req).await;
        self.touch();
        resp
    }

    async fn request_inner(&self, req: &Request) -> Result<Response> {
        let frame = proto::encode(req)?;
        let mut guard = self.conn.lock().await;
        let mut fresh = false;
        if guard.as_ref().map_or(true, |c| c.close_reason().is_some()) {
            *guard = Some(self.connect().await?);
            fresh = true;
        }
        let conn = guard.as_ref().expect("connection set above");
        match roundtrip(conn, &frame).await {
            Ok(resp) => Ok(resp),
            Err(e) if fresh => {
                *guard = None;
                Err(e)
            }
            Err(e) => {
                warn!("phone request failed ({e:#}); reconnecting");
                *guard = None;
                let conn = self.connect().await?;
                let resp = roundtrip(&conn, &frame).await?;
                *guard = Some(conn);
                Ok(resp)
            }
        }
    }
}

/// The phone's UnifiedPush endpoint and the HTTP client to wake it.
struct Push {
    endpoint: std::sync::Mutex<Option<String>>,
    http: reqwest::Client,
}

impl Push {
    fn new(endpoint: Option<String>) -> Result<Self> {
        // reqwest is built without a default provider; iroh already uses ring.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let endpoint = endpoint.and_then(checked_push_url);
        // No redirects: the phone chooses the URL, it must not be able to
        // bounce the host's POST elsewhere. No idle pooled connections: wakes
        // are minutes apart and a pooled connection the server or a NAT
        // dropped silently makes the next POST fail.
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(0)
            .timeout(PUSH_TIMEOUT)
            .build()
            .context("building HTTP client")?;
        Ok(Self { endpoint: std::sync::Mutex::new(endpoint), http })
    }

    fn endpoint(&self) -> Option<String> {
        self.endpoint.lock().expect("not poisoned").clone()
    }

    /// POSTs a wake message to the push endpoint. The body is a constant: the
    /// phone only needs to know someone wants to connect. `TTL`/`Urgency` are
    /// the Web Push headers UnifiedPush servers understand. Retried once.
    async fn wake(&self, url: &str) -> Result<()> {
        info!("waking phone via push");
        if let Err(e) = self.post_wake(url).await {
            warn!("wake push failed ({e:#}); retrying once");
            self.post_wake(url).await?;
        }
        Ok(())
    }

    async fn post_wake(&self, url: &str) -> Result<()> {
        self.http
            .post(url)
            .header("TTL", "60")
            .header("Urgency", "high")
            .body("wake")
            .send()
            .await
            .context("sending push")?
            .error_for_status()
            .context("push server")?;
        Ok(())
    }

    /// Asks the phone for its current endpoint and persists a change. Phones
    /// predating `PushEndpoint` fail the stream; that just keeps the old value.
    async fn refresh(&self, conn: &Connection) {
        let resp = match proto::encode(&Request::PushEndpoint) {
            Ok(frame) => roundtrip(conn, &frame).await,
            Err(e) => Err(e.into()),
        };
        let new = match resp {
            Ok(Response::PushEndpoint(new)) => new.and_then(checked_push_url),
            Ok(other) => {
                return debug!("unexpected response to PushEndpoint: {}", response_kind(&other))
            }
            Err(e) => return debug!("phone did not report a push endpoint: {e:#}"),
        };
        {
            let mut cur = self.endpoint.lock().expect("not poisoned");
            if *cur == new {
                return;
            }
            cur.clone_from(&new);
        }
        info!(present = new.is_some(), "phone push endpoint changed");
        let saved = config::load_config().and_then(|mut cfg| {
            cfg.push_endpoint = new;
            config::save_config(&cfg)
        });
        if let Err(e) = saved {
            warn!("saving push endpoint: {e:#}");
        }
    }
}

/// Accepts a push endpoint only if it is an `https` URL; anything else is
/// dropped (and never POSTed to). The URL itself is not logged.
pub fn checked_push_url(url: String) -> Option<String> {
    match reqwest::Url::parse(&url) {
        Ok(u) if u.scheme() == "https" && u.host().is_some() => Some(url),
        _ => {
            warn!("ignoring push endpoint from the phone: not an https URL");
            None
        }
    }
}

/// Variant name of a response, for logs and errors that must not carry the
/// payload.
pub fn response_kind(resp: &Response) -> &'static str {
    match resp {
        Response::Paired { .. } => "Paired",
        Response::Keys(_) => "Keys",
        Response::Signature(_) => "Signature",
        Response::SharedSecret(_) => "SharedSecret",
        Response::Denied => "Denied",
        Response::UnknownKey => "UnknownKey",
        Response::Error(_) => "Error",
        Response::PushEndpoint(_) => "PushEndpoint",
    }
}

async fn roundtrip(conn: &Connection, frame: &[u8]) -> Result<Response> {
    tokio::time::timeout(REQUEST_TIMEOUT, async {
        let (mut send, mut recv) = conn.open_bi().await.context("opening stream")?;
        send.write_all(frame).await.context("sending request")?;
        send.finish().context("finishing stream")?;
        let mut len = [0u8; 4];
        recv.read_exact(&mut len).await.context("reading response length")?;
        let len = proto::check_len(u32::from_be_bytes(len))?;
        let mut body = vec![0u8; len];
        recv.read_exact(&mut body).await.context("reading response body")?;
        let resp: Response = proto::decode(&body)?;
        // Never log payloads: they carry signatures, shared secrets, push URLs.
        debug!(response = response_kind(&resp), len, "phone response");
        Ok(resp)
    })
    .await
    .map_err(|_| anyhow!("timed out waiting for phone"))?
}
