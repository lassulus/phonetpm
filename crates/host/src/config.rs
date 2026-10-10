//! On-disk configuration and well-known paths.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use iroh::{EndpointId, SecretKey};
use serde::{Deserialize, Serialize};

const SECRET_FILE: &str = "secret.key";
const CONFIG_FILE: &str = "config.toml";
pub const AGENT_SOCK: &str = "agent.sock";
pub const CONTROL_SOCK: &str = "control.sock";
/// Overrides the control socket path (used by the age plugin).
pub const SOCK_ENV: &str = "PHONETPM_SOCK";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Endpoint id of the paired phone (hex).
    pub phone: String,
    /// Display name sent to the phone when pairing.
    pub host_name: String,
    /// UnifiedPush endpoint reported by the phone; POSTed to wake it. Absent
    /// while the phone listens permanently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_endpoint: Option<String>,
}

impl Config {
    pub fn phone_id(&self) -> Result<EndpointId> {
        self.phone
            .parse()
            .map_err(|e| anyhow!("invalid phone endpoint id {:?}: {e}", self.phone))
    }
}

/// `$XDG_CONFIG_HOME/phonetpm`.
pub fn config_dir() -> Result<PathBuf> {
    let base = dirs::config_dir().ok_or_else(|| anyhow!("no config directory for this user"))?;
    Ok(base.join("phonetpm"))
}

pub fn load_config() -> Result<Config> {
    let path = config_dir()?.join(CONFIG_FILE);
    let text = fs::read_to_string(&path)
        .with_context(|| format!("reading {}; run `phonetpm pair` first", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

pub fn save_config(cfg: &Config) -> Result<()> {
    let dir = config_dir()?;
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join(CONFIG_FILE);
    fs::write(&path, toml::to_string(cfg)?).with_context(|| format!("writing {}", path.display()))
}

/// Loads the endpoint secret, generating and persisting one (mode 0600) if absent.
pub fn load_or_create_secret() -> Result<SecretKey> {
    let dir = config_dir()?;
    let path = dir.join(SECRET_FILE);
    match fs::read(&path) {
        Ok(bytes) => secret_from_bytes(&bytes).with_context(|| format!("reading {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
            let sk = SecretKey::generate();
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .with_context(|| format!("creating {}", path.display()))?;
            f.write_all(&sk.to_bytes())?;
            Ok(sk)
        }
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Loads the endpoint secret; errors if it does not exist yet.
pub fn load_secret() -> Result<SecretKey> {
    let path = config_dir()?.join(SECRET_FILE);
    let bytes = fs::read(&path)
        .with_context(|| format!("reading {}; run `phonetpm pair` first", path.display()))?;
    secret_from_bytes(&bytes)
}

fn secret_from_bytes(bytes: &[u8]) -> Result<SecretKey> {
    let arr: &[u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("secret key must be exactly 32 bytes, got {}", bytes.len()))?;
    Ok(SecretKey::from_bytes(arr))
}

/// `$XDG_RUNTIME_DIR/phonetpm`, or `/tmp/phonetpm-$UID`.
pub fn runtime_dir() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir).join("phonetpm"),
        // SAFETY: getuid has no preconditions and cannot fail.
        _ => PathBuf::from(format!("/tmp/phonetpm-{}", unsafe { libc::getuid() })),
    }
}

/// Creates the runtime dir with mode 0700 and returns it.
pub fn ensure_runtime_dir() -> Result<PathBuf> {
    let dir = runtime_dir();
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

pub fn agent_sock_path() -> PathBuf {
    runtime_dir().join(AGENT_SOCK)
}

/// Control socket path; `PHONETPM_SOCK` overrides.
pub fn control_sock_path() -> PathBuf {
    match std::env::var_os(SOCK_ENV) {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => runtime_dir().join(CONTROL_SOCK),
    }
}
