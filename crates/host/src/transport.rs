//! iroh transport to the phone: one bi-stream per request, lazily connected,
//! connection reused and re-established once on failure.

use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use iroh::endpoint::{presets, Connection};
use iroh::{Endpoint, EndpointId, SecretKey};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::proto::{self, Request, Response};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
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
}

impl Phone {
    pub fn new(endpoint: Endpoint, id: EndpointId) -> Self {
        Self {
            endpoint,
            id,
            conn: Mutex::new(None),
            last_request: std::sync::Mutex::new(Instant::now()),
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

    async fn connect(&self) -> Result<Connection> {
        info!(phone = %self.id.fmt_short(), "connecting to phone");
        let conn = tokio::time::timeout(CONNECT_TIMEOUT, self.endpoint.connect(self.id, proto::ALPN))
            .await
            .map_err(|_| anyhow!("timed out connecting to phone"))?
            .context("connecting to phone")?;
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
        debug!(?resp, "phone response");
        Ok(resp)
    })
    .await
    .map_err(|_| anyhow!("timed out waiting for phone"))?
}
