//! age plugin: encrypts to `age1phone1…` recipients locally and decrypts
//! `AGE-PLUGIN-PHONE-1…` identities through the phonetpm daemon.

use std::collections::{HashMap, HashSet};
use std::io;

use age_core::format::{FileKey, Stanza};
use age_core::secrecy::ExposeSecret;
use age_plugin::{identity, recipient, run_state_machine, Callbacks, PluginHandler};
use clap::Parser;

use phonetpm::agekey::{Identity, ParsedStanza, Recipient, PLUGIN_NAME};
use phonetpm::control;
use phonetpm::proto::{self, Request, Response};
use phonetpm::transport::response_kind;
use zeroize::Zeroizing;

const DESCRIPTION_ENV: &str = "PHONETPM_DESCRIPTION";

#[derive(Parser)]
#[command(version, about = "age plugin backed by phonetpm")]
struct Opts {
    /// Run the given age plugin state machine (set by the age client).
    #[arg(long, value_name = "STATE-MACHINE")]
    age_plugin: Option<String>,
}

fn main() -> io::Result<()> {
    let opts = Opts::parse();
    match opts.age_plugin {
        Some(sm) => run_state_machine(&sm, Handler),
        None => {
            eprintln!(
                "age-plugin-phone is started by age/rage; it is not meant to be run directly.\n\
                 \n\
                 Create an identity file with the phonetpm daemon running:\n\
                 \n\
                 \x20   phonetpm keys\n\
                 \x20   phonetpm identity <key id or label> > phone.txt\n\
                 \x20   age -d -i phone.txt file.age"
            );
            std::process::exit(2);
        }
    }
}

struct Handler;

impl PluginHandler for Handler {
    type RecipientV1 = RecipientPlugin;
    type IdentityV1 = IdentityPlugin;

    fn recipient_v1(self) -> io::Result<Self::RecipientV1> {
        Ok(RecipientPlugin::default())
    }

    fn identity_v1(self) -> io::Result<Self::IdentityV1> {
        Ok(IdentityPlugin::default())
    }
}

#[derive(Default)]
struct RecipientPlugin {
    recipients: Vec<Recipient>,
}

impl recipient::RecipientPluginV1 for RecipientPlugin {
    fn add_recipient(&mut self, index: usize, plugin_name: &str, bytes: &[u8]) -> Result<(), recipient::Error> {
        if plugin_name != PLUGIN_NAME {
            return Err(recipient::Error::Recipient {
                index,
                message: format!("unknown recipient type age1{plugin_name}"),
            });
        }
        let r = Recipient::from_bytes(bytes)
            .map_err(|e| recipient::Error::Recipient { index, message: e.to_string() })?;
        self.recipients.push(r);
        Ok(())
    }

    fn add_identity(&mut self, index: usize, plugin_name: &str, bytes: &[u8]) -> Result<(), recipient::Error> {
        if plugin_name != PLUGIN_NAME {
            return Err(recipient::Error::Identity {
                index,
                message: format!("unknown identity type AGE-PLUGIN-{}-", plugin_name.to_uppercase()),
            });
        }
        let id = Identity::from_bytes(bytes)
            .map_err(|e| recipient::Error::Identity { index, message: e.to_string() })?;
        self.recipients.push(id.recipient().clone());
        Ok(())
    }

    fn labels(&mut self) -> HashSet<String> {
        HashSet::new()
    }

    fn wrap_file_keys(
        &mut self,
        file_keys: Vec<FileKey>,
        _callbacks: impl Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        Ok(Ok(file_keys
            .iter()
            .map(|fk| self.recipients.iter().map(|r| r.wrap(fk.expose_secret())).collect())
            .collect()))
    }
}

#[derive(Default)]
struct IdentityPlugin {
    identities: Vec<Identity>,
}

/// Why the plugin stops asking the phone for the rest of this invocation:
/// re-prompting for every file/stanza would wear the user down into approving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Halt {
    /// The phone refused a request.
    Denied,
    /// The user approved a request, but its stanza did not decrypt: the file
    /// was crafted to collect approvals.
    Malformed,
}

impl Halt {
    fn not_attempted(self) -> &'static str {
        match self {
            Halt::Denied => "not attempted: the phone denied an earlier request",
            Halt::Malformed => "not attempted: an earlier approved request did not decrypt (malformed file)",
        }
    }
}

/// Whether a stanza may cost a phone round trip.
#[derive(Debug, PartialEq, Eq)]
enum Attempt {
    New,
    /// This identity was already asked for the current file.
    AskedInFile,
    /// This identity was already asked about this ephemeral key.
    DuplicateEpk,
}

/// Phone round trips in this invocation: at most one per identity per file,
/// and never twice for the same identity and ephemeral key.
#[derive(Default)]
struct Attempts {
    epks: HashSet<(usize, Vec<u8>)>,
    file: HashSet<usize>,
}

impl Attempts {
    fn next_file(&mut self) {
        self.file.clear();
    }

    fn record(&mut self, ident_index: usize, epk: Vec<u8>) -> Attempt {
        if self.file.contains(&ident_index) {
            return Attempt::AskedInFile;
        }
        if !self.epks.insert((ident_index, epk)) {
            return Attempt::DuplicateEpk;
        }
        self.file.insert(ident_index);
        Attempt::New
    }
}

impl IdentityPlugin {
    /// Asks the phone for the ECDH result and unwraps the stanza. Sets `halt`
    /// when the phone refused or an approved result did not decrypt.
    fn unwrap(
        &self,
        daemon: &mut control::Client,
        halt: &mut Option<Halt>,
        callbacks: &mut impl Callbacks<identity::Error>,
        ident_index: usize,
        stanza: &ParsedStanza,
    ) -> Result<FileKey, identity::Error> {
        let ident = &self.identities[ident_index];
        let error = |message: String| identity::Error::Identity { index: ident_index, message };
        let _ = callbacks.message("Confirm on your phone to unlock the file key");
        let req = Request::Ecdh {
            key_id: ident.key_id().to_owned(),
            peer_public_key: stanza.ephemeral_spki(),
            description: description(),
        };
        let shared = match daemon.request(&req).map_err(|e| error(e.to_string()))? {
            Response::SharedSecret(x) => Zeroizing::new(x),
            Response::Denied => {
                *halt = Some(Halt::Denied);
                return Err(error("the phone denied the request (declined, or host not paired)".into()));
            }
            Response::UnknownKey => {
                return Err(error(format!("the phone has no key {:?}", ident.key_id())))
            }
            Response::Error(e) => return Err(error(format!("phonetpm daemon: {e}"))),
            other => return Err(error(format!("unexpected response {}", response_kind(&other)))),
        };
        ident.unwrap(stanza, &shared).map_err(|e| {
            *halt = Some(Halt::Malformed);
            error(format!("malformed file: approved request did not decrypt the stanza ({e}); no further requests will be sent"))
        })
    }
}

/// Why the file is being decrypted, shown on the phone; set by the caller of
/// `age`, which passes its environment to the plugin. Sanitized here too; the
/// phone does not trust it either.
fn description() -> Option<String> {
    let d = std::env::var(DESCRIPTION_ENV).ok()?;
    Some(proto::sanitize_text(&d, proto::MAX_DESCRIPTION_CHARS)).filter(|d| !d.is_empty())
}

impl identity::IdentityPluginV1 for IdentityPlugin {
    fn add_identity(&mut self, index: usize, plugin_name: &str, bytes: &[u8]) -> Result<(), identity::Error> {
        if plugin_name != PLUGIN_NAME {
            return Err(identity::Error::Identity {
                index,
                message: format!("unknown identity type AGE-PLUGIN-{}-", plugin_name.to_uppercase()),
            });
        }
        let id = Identity::from_bytes(bytes)
            .map_err(|e| identity::Error::Identity { index, message: e.to_string() })?;
        self.identities.push(id);
        Ok(())
    }

    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        mut callbacks: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        let mut daemon: Option<control::Client> = None;
        let mut halt: Option<Halt> = None;
        let mut attempts = Attempts::default();
        let mut out = HashMap::new();
        for (file_index, stanzas) in files.into_iter().enumerate() {
            attempts.next_file();
            let mut errors = Vec::new();
            let mut file_key = None;
            for (stanza_index, stanza) in stanzas.iter().enumerate() {
                let parsed = match ParsedStanza::parse(stanza) {
                    Ok(Some(p)) => p,
                    Ok(None) => continue,
                    Err(e) => {
                        errors.push(identity::Error::Stanza {
                            file_index,
                            stanza_index,
                            message: e.to_string(),
                        });
                        continue;
                    }
                };
                let Some(ident_index) = self.identities.iter().position(|i| i.matches(&parsed)) else {
                    continue;
                };
                if let Some(h) = halt {
                    errors.push(identity::Error::Identity {
                        index: ident_index,
                        message: h.not_attempted().into(),
                    });
                    break;
                }
                match attempts.record(ident_index, parsed.ephemeral_spki()) {
                    Attempt::New => {}
                    // The earlier attempt's error is already recorded.
                    Attempt::AskedInFile => continue,
                    Attempt::DuplicateEpk => {
                        errors.push(identity::Error::Stanza {
                            file_index,
                            stanza_index,
                            message: "not attempted: ephemeral key already used".into(),
                        });
                        continue;
                    }
                }
                let client = match &mut daemon {
                    Some(c) => c,
                    None => match control::Client::connect() {
                        Ok(c) => daemon.insert(c),
                        Err(e) => {
                            errors.push(identity::Error::Internal { message: e.to_string() });
                            break;
                        }
                    },
                };
                match self.unwrap(client, &mut halt, &mut callbacks, ident_index, &parsed) {
                    Ok(fk) => {
                        file_key = Some(fk);
                        break;
                    }
                    Err(e) => errors.push(e),
                }
            }
            match file_key {
                Some(fk) => {
                    out.insert(file_index, Ok(fk));
                }
                None if !errors.is_empty() => {
                    out.insert(file_index, Err(errors));
                }
                None => {}
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempts_one_per_identity_per_file_and_unique_epks() {
        let mut a = Attempts::default();
        assert_eq!(a.record(0, vec![1]), Attempt::New);
        assert_eq!(a.record(0, vec![2]), Attempt::AskedInFile);
        assert_eq!(a.record(1, vec![1]), Attempt::New, "other identity");
        a.next_file();
        assert_eq!(a.record(0, vec![1]), Attempt::DuplicateEpk);
        assert_eq!(a.record(0, vec![3]), Attempt::New);
    }
}
