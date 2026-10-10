use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::prelude::{Engine, BASE64_STANDARD};
use clap::{Parser, Subcommand};
use iroh::EndpointId;
use tokio::net::UnixListener;
use tracing::{error, info};

use phonetpm::agekey::{Identity, Recipient};
use phonetpm::config::{self, Config};
use phonetpm::control;
use phonetpm::proto::{KeyInfo, KeyKind, Request, Response};
use phonetpm::sshagent::{self, Agent};
use phonetpm::transport::{self, Phone};

#[derive(Parser)]
#[command(version, about = "Use your phone's hardware keys as an ssh-agent and age identity")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Pair this host with a phone (approve the request on the phone).
    Pair {
        /// The phone's endpoint id, as shown in the app.
        phone: EndpointId,
    },
    /// Run the daemon serving the ssh-agent and control sockets.
    Daemon,
    /// List the phone's keys (requires a running daemon).
    Keys,
    /// Print an age identity file for the given key id or label.
    Identity { key: String },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    match Cli::parse().cmd {
        Cmd::Pair { phone } => runtime()?.block_on(pair(phone)),
        Cmd::Daemon => {
            let activated = activated_sockets()?;
            runtime()?.block_on(daemon(activated))
        }
        Cmd::Keys => keys(),
        Cmd::Identity { key } => identity(&key),
    }
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting tokio runtime")
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: buf is valid for buf.len() bytes; gethostname NUL-terminates on success.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    let name = if rc == 0 {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).trim().to_owned()
    } else {
        String::new()
    };
    if name.is_empty() { "host".to_owned() } else { name }
}

async fn pair(phone_id: EndpointId) -> Result<()> {
    let secret = config::load_or_create_secret()?;
    let host_name = hostname();
    let mut cfg = Config { phone: phone_id.to_string(), host_name: host_name.clone(), push_endpoint: None };
    config::save_config(&cfg)?;
    let endpoint = transport::bind(secret).await?;
    println!("this host: {}", endpoint.id());
    println!("connecting to phone {phone_id}; approve the pairing request on the phone...");
    let phone = Phone::new(endpoint, phone_id);
    let resp = phone.request(&Request::Pair { host_name }).await;
    phone.endpoint().close().await;
    match resp? {
        Response::Paired { push_endpoint } => {
            println!("paired.");
            if push_endpoint.is_some() {
                println!("the phone sleeps between requests and is woken via UnifiedPush.");
                cfg.push_endpoint = push_endpoint;
                config::save_config(&cfg)?;
            }
            println!();
            println!("Next:");
            println!("  phonetpm daemon &");
            println!("  export SSH_AUTH_SOCK={}", config::agent_sock_path().display());
            Ok(())
        }
        Response::Denied => bail!("pairing denied on the phone"),
        other => bail!("unexpected response to Pair: {other:?}"),
    }
}

/// Removes a stale socket file, refusing if another daemon still answers on it.
fn reclaim_socket(path: &Path) -> Result<()> {
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => bail!("another phonetpm daemon is listening on {}", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => std::fs::remove_file(path).with_context(|| format!("removing {}", path.display())),
    }
}

fn bind_socket(path: &Path) -> Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    reclaim_socket(path)?;
    let listener = UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

struct Activated {
    agent: std::os::unix::net::UnixListener,
    control: std::os::unix::net::UnixListener,
}

/// Sockets passed by systemd socket activation (`sd_listen_fds_with_names`),
/// matched by `FileDescriptorName=agent` / `control` or else by socket file
/// name (`agent.sock` / `control.sock`). `Ok(None)` when the daemon was not
/// socket-activated. Call before starting the runtime: it edits the
/// environment.
fn activated_sockets() -> Result<Option<Activated>> {
    use std::os::fd::FromRawFd;
    const SD_LISTEN_FDS_START: i32 = 3;
    let Ok(pid) = std::env::var("LISTEN_PID") else {
        return Ok(None);
    };
    if pid.parse::<u32>().ok() != Some(std::process::id()) {
        return Ok(None);
    }
    let count: i32 = std::env::var("LISTEN_FDS")
        .context("LISTEN_PID set without LISTEN_FDS")?
        .parse()
        .context("parsing LISTEN_FDS")?;
    let names = std::env::var("LISTEN_FDNAMES").unwrap_or_default();
    let names: Vec<&str> = names.split(':').collect();
    // Not inherited by anything we might spawn.
    for var in ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"] {
        std::env::remove_var(var);
    }
    let (mut agent, mut control) = (None, None);
    for i in 0..count {
        let fd = SD_LISTEN_FDS_START + i;
        // SAFETY: fds 3..3+LISTEN_FDS are handed to this process by systemd and
        // owned by nobody else; each is wrapped exactly once.
        let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
        // SAFETY: fd is a valid open descriptor (see above).
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        // FileDescriptorName= names every fd of a socket unit alike, so with a
        // single unit fall back to the file name the socket is bound to.
        let path = listener.local_addr().ok().and_then(|a| a.as_pathname().map(Path::to_owned));
        let file = path.as_deref().and_then(Path::file_name).and_then(|f| f.to_str());
        let slot = match (names.get(i as usize).copied(), file) {
            (Some("agent"), _) => &mut agent,
            (Some("control"), _) => &mut control,
            (_, Some(config::AGENT_SOCK)) => &mut agent,
            (_, Some(config::CONTROL_SOCK)) => &mut control,
            (name, _) => bail!(
                "socket-activated fd {fd} ({name:?}, {path:?}) is neither \
                 FileDescriptorName=agent/control nor {}/{}",
                config::AGENT_SOCK,
                config::CONTROL_SOCK
            ),
        };
        listener.set_nonblocking(true)?;
        *slot = Some(listener);
    }
    match (agent, control) {
        (Some(agent), Some(control)) => Ok(Some(Activated { agent, control })),
        _ => bail!("socket activation needs both an agent and a control socket"),
    }
}

/// When socket-activated, exit after this long without a phone request;
/// systemd starts the daemon again on the next connection.
const IDLE_EXIT: Duration = Duration::from_secs(10 * 60);

async fn idle_exit(phone: &Phone) {
    loop {
        let idle = phone.idle_for();
        if idle >= IDLE_EXIT {
            return;
        }
        tokio::time::sleep(IDLE_EXIT - idle).await;
    }
}

async fn daemon(activated: Option<Activated>) -> Result<()> {
    let socket_activated = activated.is_some();
    let cfg = config::load_config()?;
    let phone_id = cfg.phone_id()?;
    let secret = config::load_secret()?;
    let endpoint = transport::bind(secret).await?;
    info!(host = %endpoint.id(), phone = %phone_id, "endpoint bound");
    let phone = Arc::new(Phone::new(endpoint, phone_id).with_push(cfg.push_endpoint)?);

    // Socket files we created ourselves and must remove on exit; systemd owns
    // the activated ones.
    let mut owned_paths = Vec::new();
    let (agent_listener, control_listener) = match activated {
        Some(Activated { agent, control }) => {
            info!("using sockets from systemd socket activation");
            (UnixListener::from_std(agent)?, UnixListener::from_std(control)?)
        }
        None => {
            let dir = config::ensure_runtime_dir()?;
            let agent_path = dir.join(config::AGENT_SOCK);
            let control_path = dir.join(config::CONTROL_SOCK);
            let agent_listener = bind_socket(&agent_path)?;
            let control_listener = bind_socket(&control_path)?;
            info!(agent = %agent_path.display(), control = %control_path.display(), "listening");
            owned_paths = vec![agent_path, control_path];
            (agent_listener, control_listener)
        }
    };

    let agent = Arc::new(Agent::new(phone.clone()));
    let agent_task = tokio::spawn(sshagent::serve(agent_listener, agent));
    let control_task = tokio::spawn(control::serve(control_listener, phone.clone()));

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => info!("SIGINT received"),
        _ = sigterm.recv() => info!("SIGTERM received"),
        _ = idle_exit(&phone), if socket_activated => info!("idle; exiting until the next connection"),
        r = agent_task => error!("agent listener stopped: {r:?}"),
        r = control_task => error!("control listener stopped: {r:?}"),
    }
    for path in &owned_paths {
        let _ = std::fs::remove_file(path);
    }
    phone.endpoint().close().await;
    Ok(())
}

fn list_keys() -> Result<Vec<KeyInfo>> {
    match control::Client::connect()?.request(&Request::ListKeys)? {
        Response::Keys(keys) => Ok(keys),
        Response::Denied => bail!("phone denied the request; is this host paired?"),
        Response::Error(e) => bail!("daemon: {e}"),
        other => bail!("unexpected response to ListKeys: {other:?}"),
    }
}

fn keys() -> Result<()> {
    let keys = list_keys()?;
    if keys.is_empty() {
        println!("no keys on the phone");
    }
    for key in keys {
        match key.kind {
            KeyKind::Ssh => {
                let point = sshagent::spki_to_point(&key.public_key)?;
                let blob = BASE64_STANDARD.encode(sshagent::key_blob(&point));
                println!("{} {blob} {}", sshagent::KEY_TYPE, key.label);
            }
            KeyKind::Age => {
                let recipient = Recipient::from_spki(&key.public_key)?;
                println!("{}  {} ({})", recipient.encode(), key.label, key.id);
            }
        }
    }
    Ok(())
}

fn identity(wanted: &str) -> Result<()> {
    let keys = list_keys()?;
    let key = keys
        .iter()
        .find(|k| k.id == wanted)
        .or_else(|| keys.iter().find(|k| k.label == wanted))
        .ok_or_else(|| anyhow!("no key with id or label {wanted:?}; see `phonetpm keys`"))?;
    if key.kind != KeyKind::Age {
        bail!("key {wanted:?} is an SSH key, not an age key");
    }
    let recipient = Recipient::from_spki(&key.public_key)?;
    let identity = Identity::new(recipient.clone(), key.id.clone());
    println!("# phonetpm key: {} ({})", key.label, key.id);
    println!("# public key: {}", recipient.encode());
    println!("{}", identity.encode());
    Ok(())
}
