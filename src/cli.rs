use crate::error::*;
use crate::luks;
use crate::*;

use structopt::StructOpt;

use ctap::{FidoCredential, FidoErrorKind};
use failure::_core::fmt::{Display, Error, Formatter};
use failure::_core::str::FromStr;
use failure::_core::time::Duration;
use std::io::Write;
use std::process::exit;
use std::thread;

use crate::util::sha256;
use std::time::SystemTime;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct HexEncoded(pub Vec<u8>);

impl Display for HexEncoded {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.write_str(&hex::encode(&self.0))
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
pub struct AuthenticatorParameters {
    /// FIDO credential ids, seperated by ',' generate using fido2luks credential
    #[structopt(name = "credential-id", env = "FIDO2LUKS_CREDENTIAL_ID")]
    pub credential_ids: CommaSeparated<HexEncoded>,

    /// Await for an authenticator to be connected, timeout after n seconds
    #[structopt(
        long = "await-dev",
        name = "await-dev",
        env = "FIDO2LUKS_DEVICE_AWAIT",
        default_value = "15"
    )]
    pub await_time: u64,
}

#[derive(Debug, StructOpt)]
pub struct LuksParameters {
    #[structopt(env = "FIDO2LUKS_DEVICE")]
    device: PathBuf,

    #[structopt(long = "slot", env = "FIDO2LUKS_DEVICE_SLOT")]
    slot_hint: Option<u32>,
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
) -> Fido2LuksResult<[u8; 32]> {
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

    Ok(sha256(&[
        &perform_challenge(
            &credentials
                .iter()
                .map(|hex| FidoCredential {
                    id: hex.0.clone(),
                    public_key: None,
                })
                .collect::<Vec<_>>()
                .iter()
                .collect::<Vec<_>>()[..],
            salt,
            timeout - start.elapsed().unwrap(),
        )?[..],
        salt,
    ]))
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
pub struct SecretGeneration {
    /// FIDO credential ids, seperated by ',' generate using fido2luks credential
    #[structopt(name = "credential-id", env = "FIDO2LUKS_CREDENTIAL_ID")]
    pub credential_ids: CommaSeparated<HexEncoded>,
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

    /// Await for an authenticator to be connected, timeout after n seconds
    #[structopt(
        long = "await-dev",
        name = "await-dev",
        env = "FIDO2LUKS_DEVICE_AWAIT",
        default_value = "15"
    )]
    pub await_authenticator: u64,

    /// Request the password twice to ensure it being correct
    #[structopt(
        long = "verify-password",
        env = "FIDO2LUKS_VERIFY_PASSWORD",
        hidden = true
    )]
    pub verify_password: Option<bool>,
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
        authenticator: AuthenticatorParameters,
        #[structopt(flatten)]
        secret: SecretParameters,
        /// Will wipe all other keys
        #[structopt(short = "e", long = "exclusive")]
        exclusive: bool,
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
        authenticator: AuthenticatorParameters,
        #[structopt(flatten)]
        secret: SecretParameters,
        /// Add the password and keep the key
        #[structopt(short = "a", long = "add-password")]
        add_password: bool,
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
        #[structopt(flatten)]
        authenticator: AuthenticatorParameters,
        #[structopt(flatten)]
        secret: SecretParameters,
        #[structopt(env = "FIDO2LUKS_MAPPER_NAME")]
        name: String,
        #[structopt(short = "r", long = "max-retries", default_value = "0")]
        retries: i32,
    },
    /// Generate a new FIDO credential
    #[structopt(name = "credential")]
    Credential {
        /// Name to be displayed on the authenticator if it has a display
        #[structopt(env = "FIDO2LUKS_CREDENTIAL_NAME")]
        name: Option<String>,
    },
    /// Check if an authenticator is connected
    #[structopt(name = "connected")]
    Connected,
}

pub fn parse_cmdline() -> Args {
    Args::from_args()
}

pub fn run_cli() -> Fido2LuksResult<()> {
    let mut stdout = io::stdout();
    let args = parse_cmdline();
    let interactive = args.interactive;
    match &args.command {
        Command::Credential { name } => {
            let cred = make_credential_id(name.as_ref().map(|n| n.as_ref()))?;
            println!("{}", hex::encode(&cred.id));
            Ok(())
        }
        Command::PrintSecret {
            binary,
            authenticator,
            secret,
        } => {
            let salt = if interactive || secret.password_helper == PasswordHelper::Stdin {
                util::read_password_hashed("Password", false)
            } else {
                secret.salt.obtain(&secret.password_helper)
            }?;
            let secret = derive_secret(
                authenticator.credential_ids.0.as_slice(),
                &salt,
                authenticator.await_time,
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
            secret,
            exclusive,
            existing_secret,
            luks_mod,
        } => {
            let salt = |q: &str, verify: bool| -> Fido2LuksResult<[u8; 32]> {
                if interactive || secret.password_helper == PasswordHelper::Stdin {
                    util::read_password_hashed(q, verify)
                } else {
                    secret.salt.obtain(&secret.password_helper)
                }
            };
            let old_secret = match existing_secret {
                OtherSecret {
                    keyfile: Some(file),
                    ..
                } => util::read_keyfile(file)?,
                OtherSecret {
                    fido_device: true, ..
                } => derive_secret(
                    &authenticator.credential_ids.0,
                    &salt("Existing password", false)?,
                    authenticator.await_time,
                )?[..]
                    .to_vec(),
                _ => util::read_password("Existing password", false)?
                    .as_bytes()
                    .to_vec(),
            };
            let secret = derive_secret(
                &authenticator.credential_ids.0,
                &salt("Password", false)?,
                authenticator.await_time,
            )?;
            let added_slot = luks::add_key(
                &luks.device,
                &secret,
                &old_secret[..],
                luks_mod.kdf_time.or(Some(10)),
            )?;
            if *exclusive {
                let destroyed = luks::remove_keyslots(&luks.device, &[added_slot])?;
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
        Command::ReplaceKey {
            luks,
            authenticator,
            secret,
            add_password,
            replacement,
            luks_mod,
        } => {
            let salt = |q: &str, verify: bool| -> Fido2LuksResult<[u8; 32]> {
                if interactive || secret.password_helper == PasswordHelper::Stdin {
                    util::read_password_hashed(q, verify)
                } else {
                    secret.salt.obtain(&secret.password_helper)
                }
            };
            let replacement_secret = match replacement {
                OtherSecret {
                    keyfile: Some(file),
                    ..
                } => util::read_keyfile(file)?,
                OtherSecret {
                    fido_device: true, ..
                } => derive_secret(
                    &authenticator.credential_ids.0,
                    &salt("Replacement password", true)?,
                    authenticator.await_time,
                )?[..]
                    .to_vec(),
                _ => util::read_password("Replacement password", true)?
                    .as_bytes()
                    .to_vec(),
            };
            let existing_secret = derive_secret(
                &authenticator.credential_ids.0,
                &salt("Password", false)?,
                authenticator.await_time,
            )?;
            let slot = if *add_password {
                luks::add_key(
                    &luks.device,
                    &replacement_secret[..],
                    &existing_secret,
                    luks_mod.kdf_time,
                )
            } else {
                luks::replace_key(
                    &luks.device,
                    &replacement_secret[..],
                    &existing_secret,
                    luks_mod.kdf_time,
                )
            }?;
            println!(
                "Added to password to device {}, slot: {}",
                luks.device.display(),
                slot
            );
            Ok(())
        }
        Command::Open {
            luks,
            authenticator,
            secret,
            name,
            retries,
        } => {
            let salt = |q: &str, verify: bool| -> Fido2LuksResult<[u8; 32]> {
                if interactive || secret.password_helper == PasswordHelper::Stdin {
                    util::read_password_hashed(q, verify)
                } else {
                    secret.salt.obtain(&secret.password_helper)
                }
            };
            let mut retries = *retries;
            loop {
                match derive_secret(
                    &authenticator.credential_ids.0,
                    &salt("Password", false)?,
                    authenticator.await_time,
                )
                .and_then(|secret| luks::open_container(&luks.device, &name, &secret, luks.slot_hint))
                {
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
                    res => break res,
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
    }
}
