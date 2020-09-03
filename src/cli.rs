use crate::error::*;
use crate::*;

use structopt::clap::{AppSettings, Shell};
use structopt::StructOpt;

use ctap::{FidoCredential, FidoErrorKind};
use failure::_core::fmt::{Display, Error, Formatter};
use failure::_core::str::FromStr;
use failure::_core::time::Duration;
use std::io::{Read, Write};
use std::process::exit;
use std::thread;

use crate::luks::{Fido2LuksToken, LuksDevice};
use crate::util::sha256;
use std::borrow::Cow;
use std::collections::HashSet;
use std::fs::File;
use std::time::SystemTime;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct HexEncoded(pub Vec<u8>);

impl Display for HexEncoded {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.write_str(&hex::encode(&self.0))
    }
}

impl AsRef<[u8]> for HexEncoded {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl FromStr for HexEncoded {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(HexEncoded(hex::decode(s)?))
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct CommaSeparated<T: FromStr + Display>(pub Vec<T>);

impl<T: Display + FromStr> Display for CommaSeparated<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        for i in &self.0 {
            f.write_str(&i.to_string())?;
            f.write_str(",")?;
        }
        Ok(())
    }
}

impl<T: Display + FromStr> FromStr for CommaSeparated<T> {
    type Err = <T as FromStr>::Err;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(CommaSeparated(
            s.split(',')
                .map(|part| <T as FromStr>::from_str(part))
                .collect::<Result<Vec<_>, _>>()?,
        ))
    }
}

#[derive(Debug, StructOpt)]
pub struct Credentials {
    /// FIDO credential ids, separated by ',' generate using fido2luks credential
    #[structopt(name = "credential-id", env = "FIDO2LUKS_CREDENTIAL_ID")]
    pub ids: CommaSeparated<HexEncoded>,
}

#[derive(Debug, StructOpt)]
pub struct AuthenticatorParameters {
    /// Request a PIN to unlock the authenticator
    #[structopt(short = "P", long = "pin")]
    pub pin: bool,

    /// Location to read PIN from
    #[structopt(long = "pin-source", env = "FIDO2LUKS_PIN_SOURCE")]
    pub pin_source: Option<PathBuf>,

    /// Await for an authenticator to be connected, timeout after n seconds
    #[structopt(
        long = "await-dev",
        name = "await-dev",
        env = "FIDO2LUKS_DEVICE_AWAIT",
        default_value = "15"
    )]
    pub await_time: u64,
}

impl AuthenticatorParameters {
    fn read_pin(&self) -> Fido2LuksResult<String> {
        if let Some(src) = self.pin_source.as_ref() {
            let mut pin = String::new();
            File::open(src)?.read_to_string(&mut pin)?;
            Ok(pin)
        } else {
            util::read_password("Authenticator PIN", false)
        }
    }
}

#[derive(Debug, StructOpt)]
pub struct LuksParameters {
    #[structopt(env = "FIDO2LUKS_DEVICE")]
    device: PathBuf,

    /// Try to unlock the device using a specifc keyslot, ignore all other slots
    #[structopt(long = "slot", env = "FIDO2LUKS_DEVICE_SLOT")]
    slot: Option<u32>,
}

#[derive(Debug, StructOpt, Clone)]
pub struct LuksModParameters {
    /// Number of milliseconds required to derive the volume decryption key
    /// Defaults to 10ms when using an authenticator or the default by cryptsetup when using a password
    #[structopt(long = "kdf-time", name = "kdf-time")]
    kdf_time: Option<u64>,
}

#[derive(Debug, StructOpt)]
pub struct SecretParameters {
    /// Salt for secret generation, defaults to 'ask'
    ///
    /// Options:{n}
    ///  - ask              : Prompt user using password helper{n}
    ///  - file:<PATH>      : Will read <FILE>{n}
    ///  - string:<STRING>  : Will use <STRING>, which will be handled like a password provided to the 'ask' option{n}
    #[structopt(
        name = "salt",
        long = "salt",
        env = "FIDO2LUKS_SALT",
        default_value = "ask"
    )]
    pub salt: InputSalt,
    /// Script used to obtain passwords, overridden by --interactive flag
    #[structopt(
        name = "password-helper",
        env = "FIDO2LUKS_PASSWORD_HELPER",
        default_value = "/usr/bin/env systemd-ask-password 'Please enter second factor for LUKS disk encryption!'"
    )]
    pub password_helper: PasswordHelper,
}

fn derive_secret(
    credentials: &[HexEncoded],
    salt: &[u8; 32],
    timeout: u64,
    pin: Option<&str>,
) -> Fido2LuksResult<([u8; 32], FidoCredential)> {
    let timeout = Duration::from_secs(timeout);
    let start = SystemTime::now();

    while let Ok(el) = start.elapsed() {
        if el > timeout {
            return Err(error::Fido2LuksError::NoAuthenticatorError);
        }
        if get_devices()
            .map(|devices| !devices.is_empty())
            .unwrap_or(false)
        {
            break;
        }
        thread::sleep(Duration::from_millis(500));
    }

    let credentials = credentials
        .iter()
        .map(|hex| FidoCredential {
            id: hex.0.clone(),
            public_key: None,
        })
        .collect::<Vec<_>>();
    let credentials = credentials.iter().collect::<Vec<_>>();
    let (unsalted, cred) =
        perform_challenge(&credentials, salt, timeout - start.elapsed().unwrap(), pin)?;

    Ok((sha256(&[salt, &unsalted[..]]), cred.clone()))
}

#[derive(Debug, StructOpt)]
pub struct Args {
    /// Request passwords via Stdin instead of using the password helper
    #[structopt(short = "i", long = "interactive")]
    pub interactive: bool,
    #[structopt(subcommand)]
    pub command: Command,
}

#[derive(Debug, StructOpt, Clone)]
pub struct OtherSecret {
    /// Use a keyfile instead of a password
    #[structopt(short = "d", long = "keyfile", conflicts_with = "fido_device")]
    keyfile: Option<PathBuf>,
    /// Use another fido device instead of a password
    /// Note: this requires for the credential fot the other device to be passed as argument as well
    #[structopt(short = "f", long = "fido-device", conflicts_with = "keyfile")]
    fido_device: bool,
}

#[derive(Debug, StructOpt)]
pub enum Command {
    #[structopt(name = "print-secret")]
    PrintSecret {
        /// Prints the secret as binary instead of hex encoded
        #[structopt(short = "b", long = "bin")]
        binary: bool,
        #[structopt(flatten)]
        credentials: Credentials,
        #[structopt(flatten)]
        authenticator: AuthenticatorParameters,
        #[structopt(flatten)]
        secret: SecretParameters,
    },
    /// Adds a generated key to the specified LUKS device
    #[structopt(name = "add-key")]
    AddKey {
        #[structopt(flatten)]
        luks: LuksParameters,
        #[structopt(flatten)]
        credentials: Credentials,
        #[structopt(flatten)]
        authenticator: AuthenticatorParameters,
        #[structopt(flatten)]
        secret: SecretParameters,
        /// Will wipe all other keys
        #[structopt(short = "e", long = "exclusive")]
        exclusive: bool,
        /// Will add an token to your LUKS 2 header, including the credential id
        #[structopt(short = "t", long = "token")]
        token: bool,
        #[structopt(flatten)]
        existing_secret: OtherSecret,
        #[structopt(flatten)]
        luks_mod: LuksModParameters,
    },
    /// Replace a previously added key with a password
    #[structopt(name = "replace-key")]
    ReplaceKey {
        #[structopt(flatten)]
        luks: LuksParameters,
        #[structopt(flatten)]
        credentials: Credentials,
        #[structopt(flatten)]
        authenticator: AuthenticatorParameters,
        #[structopt(flatten)]
        secret: SecretParameters,
        /// Add the password and keep the key
        #[structopt(short = "a", long = "add-password")]
        add_password: bool,
        /// Will add an token to your LUKS 2 header, including the credential id
        #[structopt(short = "t", long = "token")]
        token: bool,
        #[structopt(flatten)]
        replacement: OtherSecret,
        #[structopt(flatten)]
        luks_mod: LuksModParameters,
    },
    /// Open the LUKS device
    #[structopt(name = "open")]
    Open {
        #[structopt(flatten)]
        luks: LuksParameters,
        #[structopt(env = "FIDO2LUKS_MAPPER_NAME")]
        name: String,
        #[structopt(flatten)]
        credentials: Credentials,
        #[structopt(flatten)]
        authenticator: AuthenticatorParameters,
        #[structopt(flatten)]
        secret: SecretParameters,
        #[structopt(short = "r", long = "max-retries", default_value = "0")]
        retries: i32,
    },
    /// Open the LUKS device using credentials embedded in the LUKS 2 header
    #[structopt(name = "open-token")]
    OpenToken {
        #[structopt(flatten)]
        luks: LuksParameters,
        #[structopt(env = "FIDO2LUKS_MAPPER_NAME")]
        name: String,
        #[structopt(flatten)]
        authenticator: AuthenticatorParameters,
        #[structopt(flatten)]
        secret: SecretParameters,
        #[structopt(short = "r", long = "max-retries", default_value = "0")]
        retries: i32,
    },
    /// Generate a new FIDO credential
    #[structopt(name = "credential")]
    Credential {
        #[structopt(flatten)]
        authenticator: AuthenticatorParameters,
        /// Name to be displayed on the authenticator if it has a display
        #[structopt(env = "FIDO2LUKS_CREDENTIAL_NAME")]
        name: Option<String>,
    },
    /// Check if an authenticator is connected
    #[structopt(name = "connected")]
    Connected,
    Token(TokenCommand),
    /// Generate bash completion scripts
    #[structopt(name = "completions", setting = AppSettings::Hidden)]
    GenerateCompletions {
        /// Shell to generate completions for: bash, fish
        #[structopt(possible_values = &["bash", "fish"])]
        shell: String,
        out_dir: PathBuf,
    },
}

///LUKS2 token related operations
#[derive(Debug, StructOpt)]
pub enum TokenCommand {
    /// List all tokens associated with the specified device
    List {
        #[structopt(env = "FIDO2LUKS_DEVICE")]
        device: PathBuf,
        /// Dump all credentials as CSV
        #[structopt(long = "csv")]
        csv: bool,
    },
    /// Add credential to a keyslot
    Add {
        #[structopt(env = "FIDO2LUKS_DEVICE")]
        device: PathBuf,
        #[structopt(flatten)]
        credentials: Credentials,
        /// Slot to which the credentials will be added
        #[structopt(long = "slot", env = "FIDO2LUKS_DEVICE_SLOT")]
        slot: u32,
    },
    /// Remove credentials from token(s)
    Remove {
        #[structopt(env = "FIDO2LUKS_DEVICE")]
        device: PathBuf,
        #[structopt(flatten)]
        credentials: Credentials,
        /// Token from which the credentials will be removed
        #[structopt(long = "token")]
        token_id: Option<u32>,
    },
    /// Remove all unassigned tokens
    GC {
        #[structopt(env = "FIDO2LUKS_DEVICE")]
        device: PathBuf,
    },
}

pub fn parse_cmdline() -> Args {
    Args::from_args()
}

pub fn run_cli() -> Fido2LuksResult<()> {
    let mut stdout = io::stdout();
    let args = parse_cmdline();
    let interactive = args.interactive;
    match &args.command {
        Command::Credential {
            authenticator,
            name,
        } => {
            let pin_string;
            let pin = if authenticator.pin {
                pin_string = authenticator.read_pin()?;
                Some(pin_string.as_ref())
            } else {
                None
            };
            let cred = make_credential_id(name.as_ref().map(|n| n.as_ref()), pin)?;
            println!("{}", hex::encode(&cred.id));
            Ok(())
        }
        Command::PrintSecret {
            binary,
            authenticator,
            credentials,
            secret,
        } => {
            let pin_string;
            let pin = if authenticator.pin {
                pin_string = authenticator.read_pin()?;
                Some(pin_string.as_ref())
            } else {
                None
            };
            let salt = if interactive || secret.password_helper == PasswordHelper::Stdin {
                util::read_password_hashed("Password", false)
            } else {
                secret.salt.obtain(&secret.password_helper)
            }?;
            let (secret, _cred) = derive_secret(
                credentials.ids.0.as_slice(),
                &salt,
                authenticator.await_time,
                pin,
            )?;
            if *binary {
                stdout.write_all(&secret[..])?;
            } else {
                stdout.write_all(hex::encode(&secret[..]).as_bytes())?;
            }
            Ok(stdout.flush()?)
        }
        Command::AddKey {
            luks,
            authenticator,
            credentials,
            secret,
            luks_mod,
            existing_secret: other_secret,
            token,
            ..
        }
        | Command::ReplaceKey {
            luks,
            authenticator,
            credentials,
            secret,
            luks_mod,
            replacement: other_secret,
            token,
            ..
        } => {
            let pin = if authenticator.pin {
                Some(authenticator.read_pin()?)
            } else {
                None
            };
            let salt = |q: &str, verify: bool| -> Fido2LuksResult<[u8; 32]> {
                if interactive || secret.password_helper == PasswordHelper::Stdin {
                    util::read_password_hashed(q, verify)
                } else {
                    secret.salt.obtain(&secret.password_helper)
                }
            };
            let other_secret = |salt_q: &str,
                                verify: bool|
             -> Fido2LuksResult<(Vec<u8>, Option<FidoCredential>)> {
                match other_secret {
                    OtherSecret {
                        keyfile: Some(file),
                        ..
                    } => Ok((util::read_keyfile(file)?, None)),
                    OtherSecret {
                        fido_device: true, ..
                    } => Ok(derive_secret(
                        &credentials.ids.0,
                        &salt(salt_q, verify)?,
                        authenticator.await_time,
                        pin.as_deref(),
                    )
                    .map(|(secret, cred)| (secret[..].to_vec(), Some(cred)))?),
                    _ => Ok((
                        util::read_password(salt_q, verify)?.as_bytes().to_vec(),
                        None,
                    )),
                }
            };
            let secret = |verify: bool| -> Fido2LuksResult<([u8; 32], FidoCredential)> {
                derive_secret(
                    &credentials.ids.0,
                    &salt("Password", verify)?,
                    authenticator.await_time,
                    pin.as_deref(),
                )
            };
            let mut luks_dev = LuksDevice::load(&luks.device)?;
            // Non overlap
            match &args.command {
                Command::AddKey { exclusive, .. } => {
                    let (existing_secret, _) = other_secret("Current password", false)?;
                    let (new_secret, cred) = secret(true)?;
                    let added_slot = luks_dev.add_key(
                        &new_secret,
                        &existing_secret[..],
                        luks_mod.kdf_time.or(Some(10)),
                        Some(&cred.id[..]).filter(|_| *token),
                    )?;
                    if *exclusive {
                        let destroyed = luks_dev.remove_keyslots(&[added_slot])?;
                        println!(
                            "Added to key to device {}, slot: {}\nRemoved {} old keys",
                            luks.device.display(),
                            added_slot,
                            destroyed
                        );
                    } else {
                        println!(
                            "Added to key to device {}, slot: {}",
                            luks.device.display(),
                            added_slot
                        );
                    }
                    Ok(())
                }
                Command::ReplaceKey { add_password, .. } => {
                    let (existing_secret, _) = secret(false)?;
                    let (replacement_secret, cred) = other_secret("Replacement password", true)?;
                    let slot = if *add_password {
                        luks_dev.add_key(
                            &replacement_secret[..],
                            &existing_secret,
                            luks_mod.kdf_time,
                            cred.as_ref().filter(|_| *token).map(|cred| &cred.id[..]),
                        )
                    } else {
                        luks_dev.replace_key(
                            &replacement_secret[..],
                            &existing_secret,
                            luks_mod.kdf_time,
                            cred.as_ref().filter(|_| *token).map(|cred| &cred.id[..]),
                        )
                    }?;
                    println!(
                        "Added to password to device {}, slot: {}",
                        luks.device.display(),
                        slot
                    );
                    Ok(())
                }
                _ => unreachable!(),
            }
        }
        Command::Open {
            luks,
            authenticator,
            secret,
            name,
            retries,
            ..
        }
        | Command::OpenToken {
            luks,
            authenticator,
            secret,
            name,
            retries,
        } => {
            let pin_string;
            let pin = if authenticator.pin {
                pin_string = authenticator.read_pin()?;
                Some(pin_string.as_ref())
            } else {
                None
            };
            let salt = |q: &str, verify: bool| -> Fido2LuksResult<[u8; 32]> {
                if interactive || secret.password_helper == PasswordHelper::Stdin {
                    util::read_password_hashed(q, verify)
                } else {
                    secret.salt.obtain(&secret.password_helper)
                }
            };

            // Cow shouldn't be necessary
            let secret = |credentials: Cow<'_, Vec<HexEncoded>>| {
                derive_secret(
                    credentials.as_ref(),
                    &salt("Password", false)?,
                    authenticator.await_time,
                    pin,
                )
            };

            let mut retries = *retries;
            let mut luks_dev = LuksDevice::load(&luks.device)?;
            loop {
                let secret = match &args.command {
                    Command::Open { credentials, .. } => secret(Cow::Borrowed(&credentials.ids.0))
                        .and_then(|(secret, _cred)| luks_dev.activate(&name, &secret, luks.slot)),
                    Command::OpenToken { .. } => luks_dev.activate_token(
                        &name,
                        Box::new(|credentials: Vec<String>| {
                            let creds = credentials
                                .into_iter()
                                .flat_map(|cred| HexEncoded::from_str(cred.as_ref()).ok())
                                .collect::<Vec<_>>();
                            secret(Cow::Owned(creds))
                                .map(|(secret, cred)| (secret, hex::encode(&cred.id)))
                        }),
                        luks.slot,
                    ),
                    _ => unreachable!(),
                };
                match secret {
                    Err(e) => {
                        match e {
                            Fido2LuksError::WrongSecret if retries > 0 => {}
                            Fido2LuksError::AuthenticatorError { ref cause }
                                if cause.kind() == FidoErrorKind::Timeout && retries > 0 => {}

                            e => return Err(e),
                        }
                        retries -= 1;
                        eprintln!("{}", e);
                    }
                    res => break res.map(|_| ()),
                }
            }
        }
        Command::Connected => match get_devices() {
            Ok(ref devs) if !devs.is_empty() => {
                println!("Found {} devices", devs.len());
                Ok(())
            }
            _ => exit(1),
        },
        Command::Token(cmd) => match cmd {
            TokenCommand::List {
                device,
                csv: dump_credentials,
            } => {
                let mut dev = LuksDevice::load(device)?;
                let mut creds = Vec::new();
                for token in dev.tokens()? {
                    let (id, token) = token?;
                    for cred in token.credential.iter() {
                        if !creds.contains(cred) {
                            creds.push(cred.clone());
                            if *dump_credentials {
                                print!("{}{}", if creds.len() == 1 { "" } else { "," }, cred);
                            }
                        }
                    }
                    if *dump_credentials {
                        continue;
                    }
                    println!(
                        "{}:\n\tSlots: {}\n\tCredentials: {}",
                        id,
                        if token.keyslots.is_empty() {
                            "None".into()
                        } else {
                            token.keyslots.iter().cloned().collect::<Vec<_>>().join(",")
                        },
                        token
                            .credential
                            .iter()
                            .map(|cred| format!(
                                "{} ({})",
                                cred,
                                creds.iter().position(|c| c == cred).unwrap().to_string()
                            ))
                            .collect::<Vec<_>>()
                            .join(",")
                    );
                }
                if *dump_credentials {
                    println!();
                }
                Ok(())
            }
            TokenCommand::Add {
                device,
                credentials,
                slot,
            } => {
                let mut dev = LuksDevice::load(device)?;
                let mut tokens = Vec::new();
                for token in dev.tokens()? {
                    let (id, token) = token?;
                    if token.keyslots.contains(&slot.to_string()) {
                        tokens.push((id, token));
                    }
                }
                let count = if tokens.is_empty() {
                    dev.add_token(&Fido2LuksToken::with_credentials(&credentials.ids.0, *slot))?;
                    1
                } else {
                    tokens.len()
                };
                for (id, mut token) in tokens {
                    token
                        .credential
                        .extend(credentials.ids.0.iter().map(|h| h.to_string()));
                    dev.update_token(id, &token)?;
                }
                println!("Updated {} tokens", count);
                Ok(())
            }
            TokenCommand::Remove {
                device,
                credentials,
                token_id,
            } => {
                let mut dev = LuksDevice::load(device)?;
                let mut tokens = Vec::new();
                for token in dev.tokens()? {
                    let (id, token) = token?;
                    if let Some(token_id) = token_id {
                        if id == *token_id {
                            tokens.push((id, token));
                        }
                    } else {
                        tokens.push((id, token));
                    }
                }
                let count = tokens.len();
                for (id, mut token) in tokens {
                    token.credential = token
                        .credential
                        .into_iter()
                        .filter(|cred| !credentials.ids.0.iter().any(|h| &h.to_string() == cred))
                        .collect();
                    dev.update_token(id, &token)?;
                }
                println!("Updated {} tokens", count);
                Ok(())
            }
            TokenCommand::GC { device } => {
                let mut dev = LuksDevice::load(device)?;
                let mut creds: HashSet<String> = HashSet::new();
                let mut remove = Vec::new();
                for token in dev.tokens()? {
                    let (id, token) = token?;
                    if token.keyslots.is_empty() || token.credential.is_empty() {
                        creds.extend(token.credential);
                        remove.push(id);
                    }
                }
                for id in remove.iter().rev() {
                    dev.remove_token(*id)?;
                }
                println!(
                    "Removed {} tokens, affected credentials: {}",
                    remove.len(),
                    creds.into_iter().collect::<Vec<_>>().join(",")
                );
                Ok(())
            }
        },
        Command::GenerateCompletions { shell, out_dir } => {
            Args::clap().gen_completions(
                env!("CARGO_PKG_NAME"),
                match shell.as_ref() {
                    "bash" => Shell::Bash,
                    "fish" => Shell::Fish,
                    _ => unreachable!("structopt shouldn't allow us to reach this point"),
                },
                &out_dir,
            );
            Ok(())
        }
    }
}
