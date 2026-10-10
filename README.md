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
| `android/` | Kotlin/Compose app: Keystore, BiometricPrompt, foreground service, UnifiedPush wake-up, pairing UI |
| `scripts/build-android-lib.sh` | cargo-ndk build + Kotlin binding generation |

## Build

The host binaries are a flake package for x86_64/aarch64 Linux and Darwin:

```sh
nix build github:lassulus/phonetpm         # result/bin/{phonetpm,age-plugin-phone}
nix run github:lassulus/phonetpm -- pair <endpoint id>
```

Development, including the Android app, runs inside `nix develop` on
x86_64-linux (Rust with Android targets, cargo-ndk, JDK 17, Gradle, Android SDK/NDK).

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

### Let the phone sleep (UnifiedPush)

Without extra setup the app keeps a foreground service running so hosts can
connect at any time. With a [UnifiedPush](https://unifiedpush.org)
distributor installed, the app only runs while hosts need it:

1. Install [ntfy](https://f-droid.org/packages/io.heckel.ntfy/) from F-Droid
   (any UnifiedPush distributor works; ntfy.sh or your own ntfy server).
2. Open phonetpm; it registers with the distributor (pick ntfy if asked).
   The Home tab then says "Asleep, woken by hosts via UnifiedPush".
3. Pair (or, for an existing pairing, let the daemon connect once while the
   app is open). The phone hands its push endpoint URL to the host, which
   stores it as `push_endpoint` in `~/.config/phonetpm/config.toml` and
   refreshes it on every connection.

When a request comes in and there is no live connection, the daemon POSTs
`wake` to that URL, the distributor wakes the app, and the app starts the
iroh endpoint for the request and stops again after a minute without
requests. The daemon keeps trying to connect for up to 30 s after the push.
The push carries no data, and the push server only learns that this host
wants to talk to the phone. If the distributor is uninstalled, the app falls
back to listening permanently.

Pairing changed the wire format (`Paired` now carries the push endpoint), so
the host and the app need to be updated together.

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
