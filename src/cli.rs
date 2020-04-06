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

use crate::util::read_password;
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

impl SecretGeneration {
    pub fn patch(&self, args: &Args, verify_password: Option<bool>) -> Self {
        let mut me = self.clone();
        if args.interactive {
            me.password_helper = PasswordHelper::Stdin;
        }
        me.verify_password = me.verify_password.or(verify_password);
        me
    }

    pub fn obtain_secret(&self, password_query: &str) -> Fido2LuksResult<[u8; 32]> {
        let mut salt = [0u8; 32];
        match self.password_helper {
            PasswordHelper::Stdin if !self.verify_password.unwrap_or(true) => {
                salt.copy_from_slice(&util::sha256(&[&read_password(
                    password_query,
                    self.verify_password.unwrap_or(true),
                )?
                .as_bytes()[..]]));
            }
            _ => {
                salt = self.salt.obtain(&self.password_helper)?;
            }
        }
        let timeout = Duration::from_secs(self.await_authenticator);
        let start = SystemTime::now();

        while let Ok(el) = start.elapsed() {
            if el > timeout {
                Err(error::Fido2LuksError::NoAuthenticatorError)?;
            }
            if get_devices()
                .map(|devices| !devices.is_empty())
                .unwrap_or(false)
            {
                break;
            }
            thread::sleep(Duration::from_millis(500));
        }
        let credentials = &self
            .credential_ids
            .0
            .iter()
            .map(|HexEncoded(id)| FidoCredential {
                id: id.to_vec(),
                public_key: None,
            })
            .collect::<Vec<_>>();
        let credentials = credentials.iter().collect::<Vec<_>>();
        Ok(assemble_secret(
            &perform_challenge(&credentials[..], &salt, timeout - start.elapsed().unwrap())?,
            &salt,
        ))
    }
}

#[derive(Debug, StructOpt, Clone)]
pub struct LuksSettings {
    /// Number of milliseconds required to derive the volume decryption key
    /// Defaults to 10ms when using an authenticator or the default by cryptsetup when using a password
    #[structopt(long = "kdf-time", name = "kdf-time")]
    kdf_time: Option<u64>,
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

impl OtherSecret {
    pub fn obtain(
        &self,
        secret_gen: &SecretGeneration,
        verify_password: bool,
        password_question: &str,
    ) -> Fido2LuksResult<Vec<u8>> {
        match &self.keyfile {
            Some(keyfile) => util::read_keyfile(keyfile.clone()),
            None if self.fido_device => {
                Ok(Vec::from(&secret_gen.obtain_secret(password_question)?[..]))
            }
            None => util::read_password(password_question, verify_password)
                .map(|p| p.as_bytes().to_vec()),
        }
    }
}

#[derive(Debug, StructOpt)]
pub enum Command {
    #[structopt(name = "print-secret")]
    PrintSecret {
        /// Prints the secret as binary instead of hex encoded
        #[structopt(short = "b", long = "bin")]
        binary: bool,
        #[structopt(flatten)]
        secret_gen: SecretGeneration,
    },
    /// Adds a generated key to the specified LUKS device
    #[structopt(name = "add-key")]
    AddKey {
        #[structopt(env = "FIDO2LUKS_DEVICE")]
        device: PathBuf,
        /// Will wipe all other keys
        #[structopt(short = "e", long = "exclusive")]
        exclusive: bool,
        #[structopt(flatten)]
        existing_secret: OtherSecret,
        #[structopt(flatten)]
        secret_gen: SecretGeneration,
        #[structopt(flatten)]
        luks_settings: LuksSettings,
    },
    /// Replace a previously added key with a password
    #[structopt(name = "replace-key")]
    ReplaceKey {
        #[structopt(env = "FIDO2LUKS_DEVICE")]
        device: PathBuf,
        /// Add the password and keep the key
        #[structopt(short = "a", long = "add-password")]
        add_password: bool,
        #[structopt(flatten)]
        replacement: OtherSecret,
        #[structopt(flatten)]
        secret_gen: SecretGeneration,
        #[structopt(flatten)]
        luks_settings: LuksSettings,
    },
    /// Open the LUKS device
    #[structopt(name = "open")]
    Open {
        #[structopt(env = "FIDO2LUKS_DEVICE")]
        device: PathBuf,
        #[structopt(env = "FIDO2LUKS_MAPPER_NAME")]
        name: String,
        #[structopt(short = "r", long = "max-retries", default_value = "0")]
        retries: i32,
        #[structopt(flatten)]
        secret_gen: SecretGeneration,
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
    match &args.command {
        Command::Credential { name } => {
            let cred = make_credential_id(name.as_ref().map(|n| n.as_ref()))?;
            println!("{}", hex::encode(&cred.id));
            Ok(())
        }
        Command::PrintSecret {
            binary,
            ref secret_gen,
        } => {
            let secret = secret_gen
                .patch(&args, Some(false))
                .obtain_secret("Password")?;
            if *binary {
                stdout.write(&secret[..])?;
            } else {
                stdout.write(hex::encode(&secret[..]).as_bytes())?;
            }
            Ok(stdout.flush()?)
        }
        Command::AddKey {
            device,
            exclusive,
            existing_secret,
            ref secret_gen,
            luks_settings,
        } => {
            let old_secret = existing_secret.obtain(&secret_gen, false, "Existing password")?;
            let secret_gen = secret_gen.patch(&args, None);
            let secret = secret_gen.obtain_secret("Password")?;
            let added_slot = luks::add_key(
                device.clone(),
                &secret,
                &old_secret[..],
                luks_settings.kdf_time.or(Some(10)),
            )?;
            if *exclusive {
                let destroyed = luks::remove_keyslots(&device, &[added_slot])?;
                println!(
                    "Added to key to device {}, slot: {}\nRemoved {} old keys",
                    device.display(),
                    added_slot,
                    destroyed
                );
            } else {
                println!(
                    "Added to key to device {}, slot: {}",
                    device.display(),
                    added_slot
                );
            }
            Ok(())
        }
        Command::ReplaceKey {
            device,
            add_password,
            replacement,
            ref secret_gen,
            luks_settings,
        } => {
            let secret_gen = secret_gen.patch(&args, Some(false));
            let secret = secret_gen.obtain_secret("Password")?;
            let new_secret = replacement.obtain(&secret_gen, true, "Replacement password")?;
            let slot = if *add_password {
                luks::add_key(device, &new_secret[..], &secret, luks_settings.kdf_time)
            } else {
                luks::replace_key(device, &new_secret[..], &secret, luks_settings.kdf_time)
            }?;
            println!(
                "Added to password to device {}, slot: {}",
                device.display(),
                slot
            );
            Ok(())
        }
        Command::Open {
            device,
            name,
            retries,
            ref secret_gen,
        } => {
            let mut retries = *retries;
            loop {
                match secret_gen
                    .patch(&args, Some(false))
                    .obtain_secret("Password")
                    .and_then(|secret| luks::open_container(&device, &name, &secret))
                {
                    Err(e) => {
                        match e {
                            Fido2LuksError::WrongSecret if retries > 0 => (),
                            Fido2LuksError::AuthenticatorError { ref cause }
                                if cause.kind() == FidoErrorKind::Timeout && retries > 0 =>
                            {
                                ()
                            }

                            e => break Err(e)?,
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
