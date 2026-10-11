//! On-disk configuration and well-known paths.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
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
    let text = toml::to_string(cfg)?;
    // Write a private temp file next to the config and rename it over, so a
    // crash never leaves a truncated config and it is never world-readable.
    let tmp = dir.join(format!(".{CONFIG_FILE}.{:016x}.tmp", rand::random::<u64>()));
    let written = (|| {
        let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        fs::rename(&tmp, &path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written.with_context(|| format!("writing {}", path.display()))
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

/// Private per-user directory holding the sockets: on macOS the per-user temp
/// dir (`confstr(_CS_DARWIN_USER_TEMP_DIR)`), else `$XDG_RUNTIME_DIR`, else
/// `/tmp/phonetpm-$UID`.
pub fn runtime_dir() -> PathBuf {
    #[cfg(target_vendor = "apple")]
    if let Some(dir) = darwin_user_temp_dir() {
        return dir.join("phonetpm");
    }
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir).join("phonetpm"),
        // SAFETY: getuid has no preconditions and cannot fail.
        _ => PathBuf::from(format!("/tmp/phonetpm-{}", unsafe { libc::getuid() })),
    }
}

#[cfg(target_vendor = "apple")]
fn darwin_user_temp_dir() -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    // SAFETY: a null buffer of length 0 only queries the required size.
    let len = unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, std::ptr::null_mut(), 0) };
    if len == 0 {
        return None;
    }
    let mut buf = vec![0u8; len];
    // SAFETY: buf is valid for len bytes; confstr NUL-terminates within it.
    let n = unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, buf.as_mut_ptr().cast(), len) };
    if n == 0 || n > len {
        return None;
    }
    buf.truncate(n - 1);
    (!buf.is_empty()).then(|| PathBuf::from(std::ffi::OsString::from_vec(buf)))
}

/// Creates the runtime dir (mode 0700) if missing, verifies it and returns it.
pub fn ensure_runtime_dir() -> Result<PathBuf> {
    let dir = runtime_dir();
    create_private_dir(&dir)?;
    Ok(dir)
}

/// Creates `dir` (only the last component) with mode 0700 unless it exists,
/// then checks it with [`verify_private_dir`].
fn create_private_dir(dir: &Path) -> Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        // The umask may have stripped bits; we just created it, so fix them.
        Ok(()) => fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("setting permissions of {}", dir.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).with_context(|| format!("creating {}", dir.display())),
    }
    verify_private_dir(dir)
}

/// Refuses `dir` unless it is a real directory (not a symlink) owned by the
/// current user with mode exactly 0700: anything else could let another
/// local user plant or intercept the sockets.
pub fn verify_private_dir(dir: &Path) -> Result<()> {
    let md = fs::symlink_metadata(dir).with_context(|| format!("checking {}", dir.display()))?;
    if !md.file_type().is_dir() {
        bail!("{} is not a directory (symlink or other file); refusing to use it", dir.display());
    }
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    if md.uid() != uid {
        bail!("{} is owned by uid {}, not by you (uid {uid}); refusing to use it", dir.display(), md.uid());
    }
    let mode = md.mode() & 0o7777;
    if mode != 0o700 {
        bail!("{} has mode {mode:o}, expected 700; refusing to use it", dir.display());
    }
    Ok(())
}

/// The directory a socket path lives in, verified with [`verify_private_dir`].
pub fn verify_socket_parent(sock: &Path) -> Result<()> {
    let parent = match sock.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    verify_private_dir(parent)
}

pub fn agent_sock_path() -> PathBuf {
    runtime_dir().join(AGENT_SOCK)
}

/// Control socket path; `PHONETPM_SOCK` overrides. Errors unless the socket's
/// directory passes [`verify_private_dir`].
pub fn control_sock_path() -> Result<PathBuf> {
    let path = match std::env::var_os(SOCK_ENV) {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => runtime_dir().join(CONTROL_SOCK),
    };
    verify_socket_parent(&path)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh, not yet existing path in a private scratch dir.
    fn scratch(name: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!("phonetpm-test-{:016x}", rand::random::<u64>()));
        fs::create_dir(&base).unwrap();
        base.join(name)
    }

    #[test]
    fn fresh_runtime_dir_is_created_0700() {
        let dir = scratch("rt");
        create_private_dir(&dir).unwrap();
        let md = fs::symlink_metadata(&dir).unwrap();
        assert!(md.is_dir());
        assert_eq!(md.mode() & 0o7777, 0o700);
        // Existing and correct: accepted again.
        create_private_dir(&dir).unwrap();
        verify_socket_parent(&dir.join(CONTROL_SOCK)).unwrap();
        fs::remove_dir_all(dir.parent().unwrap()).unwrap();
    }

    #[test]
    fn symlinked_runtime_dir_is_rejected() {
        let target = scratch("target");
        create_private_dir(&target).unwrap();
        let link = target.with_file_name("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(create_private_dir(&link).is_err());
        assert!(verify_socket_parent(&link.join(CONTROL_SOCK)).is_err());
        fs::remove_dir_all(target.parent().unwrap()).unwrap();
    }

    #[test]
    fn runtime_dir_with_wrong_mode_is_rejected() {
        let dir = scratch("rt");
        fs::create_dir(&dir).unwrap();
        for mode in [0o755, 0o770, 0o701, 0o1700] {
            fs::set_permissions(&dir, fs::Permissions::from_mode(mode)).unwrap();
            assert!(create_private_dir(&dir).is_err(), "mode {mode:o} accepted");
        }
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        verify_private_dir(&dir).unwrap();
        fs::remove_dir_all(dir.parent().unwrap()).unwrap();
    }
}
