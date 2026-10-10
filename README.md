# phonetpm

Your Android phone as a YubiKey. P-256 keys live in the phone's StrongBox/TEE,
bound to your fingerprint. A small host daemon reaches the phone over
[iroh](https://iroh.computer) (p2p QUIC, works off-LAN via relays) and exposes
the keys as:

- an **ssh-agent** (`ecdsa-sha2-nistp256`), and
- an **age plugin** (`age-plugin-phone`, `piv-p256` stanzas — the same format
  as `age-plugin-yubikey` / `age-plugin-se`).

Every signature and every decryption asks for a fingerprint on the phone.

```
ssh / git ──ssh-agent──┐
                       ├─ phonetpm daemon ──iroh/QUIC──▶ Android app ──▶ Keystore (StrongBox)
age ──age-plugin-phone─┘   (control.sock)                 BiometricPrompt
```

## Layout

| path | what |
|---|---|
| `crates/proto` | wire protocol (postcard frames over one QUIC bi-stream per request) |
| `crates/host` | `phonetpm` (daemon, pair, keys, identity) and `age-plugin-phone` |
| `crates/mobile` | Rust core of the app: iroh endpoint + UniFFI surface (`libphonetpm_mobile.so`) |
| `android/` | Kotlin/Compose app: Keystore, BiometricPrompt, foreground service, pairing UI |
| `scripts/build-android-lib.sh` | cargo-ndk build + Kotlin binding generation |

## Build

Everything runs inside `nix develop` (Rust with Android targets, cargo-ndk,
JDK 17, Gradle, Android SDK/NDK).

```sh
nix develop
cargo build -p phonetpm --release           # host: target/release/{phonetpm,age-plugin-phone}
scripts/build-android-lib.sh                # native lib + bindings into android/
gradle -p android assembleDebug             # android/app/build/outputs/apk/debug/app-debug.apk
```

## Use

1. Install the APK, start the service, create keys (SSH and/or age) in the app.
2. On the host: `phonetpm pair <endpoint id shown in the app>` and approve on the phone.
3. `phonetpm daemon &` then `export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/phonetpm/agent.sock`.
4. `phonetpm keys` prints the SSH public key line and the age recipient.
   `phonetpm identity <label>` prints an age identity file.

```sh
ssh-add -L                                   # lists the phone key
ssh host                                     # fingerprint on the phone
age -r age1phone1... -o secret.age file      # encrypt (no phone needed)
age -d -i phone.txt secret.age               # fingerprint on the phone
```

`age-plugin-phone` must be on `PATH`; it talks to the daemon via
`$XDG_RUNTIME_DIR/phonetpm/control.sock` (override with `PHONETPM_SOCK`).

### systemd socket activation

Instead of starting the daemon by hand, let systemd own the sockets and start
`phonetpm daemon` on the first connection. A socket-activated daemon exits
after 10 minutes without a request; the next connection starts it again.

`~/.config/systemd/user/phonetpm.socket`:

```ini
[Unit]
Description=phonetpm ssh-agent and control sockets

[Socket]
ListenStream=%t/phonetpm/agent.sock
ListenStream=%t/phonetpm/control.sock
SocketMode=0600
DirectoryMode=0700

[Install]
WantedBy=sockets.target
```

`~/.config/systemd/user/phonetpm.service`:

```ini
[Unit]
Description=phonetpm daemon
Requires=phonetpm.socket

[Service]
ExecStart=/path/to/phonetpm daemon
```

```sh
systemctl --user daemon-reload
systemctl --user enable --now phonetpm.socket
```

The daemon tells the sockets apart by their file names (`agent.sock`,
`control.sock`). For other paths, name them with `FileDescriptorName=agent`
and `FileDescriptorName=control`. That setting applies to every socket in a
unit, so it needs two socket units (e.g. `phonetpm-agent.socket` and
`phonetpm-control.socket`, both with `Service=phonetpm.service`, listed in the
service's `Sockets=`).

## Security model

- Private keys never leave the Keystore. SSH keys are per-operation
  biometric-bound (`setUserAuthenticationParameters(0, BIOMETRIC_STRONG)` with a
  `BiometricPrompt.CryptoObject`). age keys use a 10 s post-auth window because
  Android has no `CryptoObject` for `KeyAgreement`.
- Transport identity is the iroh endpoint key (Ed25519, TLS 1.3). The phone
  keeps an allow-list of paired host endpoint ids; unknown peers get `Denied`
  without any UI.
- Relays only see ciphertext; connections upgrade to direct paths when possible.

## Smoke test without a phone

`crates/mobile/examples/fake_phone.rs` runs the real iroh node with software
keys and auto-approves pairing:

```sh
cargo run -p phonetpm-mobile --example fake_phone   # prints endpoint id
phonetpm pair <id> && phonetpm daemon
```
