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
The native library and the Kotlin bindings are generated, not checked in, so
run `scripts/build-android-lib.sh` before any Gradle build.

```sh
nix develop
cargo build -p phonetpm --release           # host: target/release/{phonetpm,age-plugin-phone}
scripts/build-android-lib.sh                # native lib + bindings into android/
gradle -p android assembleDebug             # android/app/build/outputs/apk/debug/app-debug.apk
```

Gradle verifies every dependency against `android/gradle/verification-metadata.xml`.
After changing dependencies, refresh it with
`gradle -p android --write-verification-metadata sha256 assembleDebug assembleRelease`
and review the diff.

Release APKs are built unsigned by CI, then signed in a separate job that runs
no repository code. Every release file has a build provenance attestation:

```sh
gh attestation verify phonetpm-v0.4.0.apk -R lassulus/phonetpm
```

Signing runs in the `release` environment, which only accepts `v*` tags, and a
tag ruleset lets only repository admins create, move or delete `v*` tags. The
`ANDROID_*` signing secrets are repository secrets, so anyone with write
access could reference them from a workflow on another branch; keep write
access limited to people you would trust with the signing key.

## Use

1. Install the APK, start the service, create keys (SSH and/or age) in the app.
2. In the app's Hosts tab, tap "Pair new host". This opens pairing for two
   minutes; outside that window pairing requests are refused without any UI.
3. On the host: `phonetpm pair <endpoint id shown in the app>`. The phone shows
   the host's id: approve only if it matches the `this host:` line, then confirm
   with your fingerprint or screen lock.
4. `phonetpm daemon &` then export the `SSH_AUTH_SOCK` printed by `phonetpm pair`.
   Sockets live in a private per-user directory: `$XDG_RUNTIME_DIR/phonetpm` on
   Linux (or `/tmp/phonetpm-$UID` without it), the per-user temp dir on macOS.
   The daemon and clients refuse the directory unless it is a real directory
   owned by you with mode 0700.
5. `phonetpm keys` prints the SSH public key line and the age recipient.
   `phonetpm identity <label>` prints an age identity file.

```sh
ssh-add -L                                   # lists the phone key
ssh host                                     # fingerprint on the phone
age -r age1phone1... -o secret.age file      # encrypt (no phone needed)
age -d -i phone.txt secret.age               # fingerprint on the phone
```

`age-plugin-phone` must be on `PATH`; it talks to the daemon via
`control.sock` next to the agent socket (override with `PHONETPM_SOCK`). The
control socket only forwards key listing and age decryption; signing goes
through the ssh-agent socket.

Every prompt names the key, the host (its name and the first 8 characters of
its id) and, where available, a description from the host. For SSH signatures
the daemon derives it from what is signed ("SSH login as alice", "git
commit/tag signing"). For `age`, set `PHONETPM_DESCRIPTION`:

```sh
PHONETPM_DESCRIPTION="deploy secrets for coaxmetal" age -d -i phone.txt secret.age
```

Descriptions and names are stripped of control and bidi characters and capped
(names 64, descriptions 200 characters) on both the host and the phone. The
app's History tab keeps the last 100 requests with host, key, description and
outcome. If you deny an unlock, the plugin makes no further requests for that
`age` run.

Sign and unlock requests carry the description, so the host and the app need
to be updated together.

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
the host and the app need to be updated together. The host only stores and
POSTs to `https` push URLs and does not follow redirects.

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
  `BiometricPrompt.CryptoObject`); the app checks that the authenticated
  `Signature` is the one created for the request being approved. Prompts require
  an explicit confirmation, so passive face unlock cannot approve.
- age keys use a 10 s post-auth window because `BiometricPrompt.CryptoObject`
  only accepts a `KeyAgreement` from Android 16 on (not in androidx.biometric
  or the compile SDK used here). The app still prompts for every request; the
  window is only a Keystore-level property. The phone checks that the host's
  ephemeral key is a valid P-256 point before the agreement.
- Transport identity is the iroh endpoint key (Ed25519, TLS 1.3). The phone
  keeps an allow-list of paired host endpoint ids; unknown peers get `Denied`
  without any UI, except `Pair` inside the pairing window. Approving a pairing
  requires your fingerprint or screen lock. Removing a host denies its pending
  requests immediately.
- The phone drops connections from unpaired peers right after the TLS
  handshake (except while the pairing window is open), so they cannot hold
  resources a paired host needs. It also limits load: 32 concurrent
  handshakes, 4 connections per host, 4 streams per connection, 8 concurrent
  requests, 10 s to send a request, and connections close after 15 s idle.
- Lock-screen notifications only say "phonetpm request"; details appear after
  unlocking or on the approval screen. App data, including the iroh identity
  and the paired hosts, is excluded from cloud backup and device transfer.
- Relays only see ciphertext; connections upgrade to direct paths when possible.
- The host never logs request or response payloads, writes `config.toml` with
  mode 0600, and zeroizes ECDH secrets and file keys after use.

## Smoke test without a phone

`crates/mobile/examples/fake_phone.rs` runs the real iroh node with software
keys and auto-approves everything, including pairing (no pairing window):

```sh
cargo run -p phonetpm-mobile --example fake_phone   # prints endpoint id
phonetpm pair <id> && phonetpm daemon
```
