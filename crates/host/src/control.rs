//! Local control socket: wire-protocol frames over a unix socket. Clients may
//! send several requests sequentially on one connection; the daemon forwards
//! each to the phone and answers with one response frame. Only `ListKeys` and
//! `Ecdh` (the age plugin's needs) are forwarded; anything else could be used
//! by local processes to get uninformed approvals (signatures, pairing).

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixListener;
use tracing::{debug, warn};

use crate::config;
use crate::proto::{self, Request, Response};
use crate::transport::Phone;

/// Reads one frame body; `Ok(None)` on clean EOF before any byte.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = proto::check_len(u32::from_be_bytes(len))?;
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(Some(body))
}

pub async fn write_frame<W: AsyncWrite + Unpin, T: serde::Serialize>(w: &mut W, msg: &T) -> Result<()> {
    w.write_all(&proto::encode(msg)?).await?;
    Ok(())
}

pub async fn serve(listener: UnixListener, phone: Arc<Phone>) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("control accept failed: {e}");
                continue;
            }
        };
        let phone = phone.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, phone).await {
                debug!("control client error: {e:#}");
            }
        });
    }
}

async fn handle(mut stream: tokio::net::UnixStream, phone: Arc<Phone>) -> Result<()> {
    while let Some(body) = read_frame(&mut stream).await? {
        let req: Request = proto::decode(&body)?;
        let resp = match req {
            Request::ListKeys | Request::Ecdh { .. } => match phone.request(&req).await {
                Ok(resp) => resp,
                Err(e) => {
                    warn!("forwarding control request failed: {e:#}");
                    Response::Error(format!("{e:#}"))
                }
            },
            _ => Response::Error("not allowed over the control socket".into()),
        };
        write_frame(&mut stream, &resp).await?;
    }
    Ok(())
}

/// Blocking client for the control socket.
pub struct Client {
    stream: UnixStream,
}

impl Client {
    pub fn connect() -> Result<Self> {
        let path = config::control_sock_path()?;
        let stream = UnixStream::connect(&path).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
                anyhow!("phonetpm daemon not running (no socket at {})", path.display())
            }
            _ => anyhow!("connecting to {}: {e}", path.display()),
        })?;
        Ok(Self { stream })
    }

    pub fn request(&mut self, req: &Request) -> Result<Response> {
        self.stream.write_all(&proto::encode(req)?).context("writing to daemon")?;
        let mut len = [0u8; 4];
        self.stream.read_exact(&mut len).context("daemon closed the connection")?;
        let len = proto::check_len(u32::from_be_bytes(len))?;
        let mut body = vec![0u8; len];
        self.stream.read_exact(&mut body).context("reading daemon response")?;
        Ok(proto::decode(&body)?)
    }
}
