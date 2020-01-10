use crate::error::*;
use crate::*;

use cryptsetup_rs as luks;
use cryptsetup_rs::api::{CryptDeviceHandle, CryptDeviceOpenBuilder, Luks1Params};
use cryptsetup_rs::{CryptDevice, Luks1CryptDevice};

use libcryptsetup_sys::crypt_keyslot_info;
use structopt::StructOpt;

use std::io::Write;
use std::process::exit;

pub fn add_key_to_luks(
    device: PathBuf,
    secret: &[u8; 32],
    old_secret: Box<dyn Fn() -> Fido2LuksResult<Vec<u8>>>,
    exclusive: bool,
) -> Fido2LuksResult<u8> {
    fn offer_format(
        _dev: CryptDeviceOpenBuilder,
    ) -> Fido2LuksResult<CryptDeviceHandle<Luks1Params>> {
        unimplemented!()
    }
    let dev =
        || -> luks::device::Result<CryptDeviceOpenBuilder> { luks::open(&device.canonicalize()?) };

    let prev_key = old_secret()?;

    let mut handle = match dev()?.luks1() {
        Ok(handle) => handle,
        Err(luks::device::Error::BlkidError(_)) => offer_format(dev()?)?,
        Err(luks::device::Error::CryptsetupError(errno)) => {
            //if i32::from(errno) == 555
            dbg!(errno);
            offer_format(dev()?)?
        } //TODO: find correct errorno and offer to format as luks
        err => err?,
    };
    handle.set_iteration_time(50);
    let slot = handle.add_keyslot(secret, Some(prev_key.as_slice()), None)?;
    if exclusive {
        for old_slot in 0..8u8 {
            if old_slot != slot
                && (handle.keyslot_status(old_slot.into()) == crypt_keyslot_info::CRYPT_SLOT_ACTIVE
                    || handle.keyslot_status(old_slot.into())
                        == crypt_keyslot_info::CRYPT_SLOT_ACTIVE_LAST)
            {
                handle.destroy_keyslot(old_slot)?;
            }
        }
    }
    Ok(slot)
}

pub fn add_password_to_luks(
    device: PathBuf,
    secret: &[u8; 32],
    new_secret: Box<dyn Fn() -> Fido2LuksResult<Vec<u8>>>,
    add_password: bool,
) -> Fido2LuksResult<u8> {
    let dev = luks::open(&device.canonicalize()?)?;
    let mut handle = dev.luks1()?;
    let prev_slot = if add_password {
        Some(handle.add_keyslot(&secret[..], Some(&secret[..]), None)?)
    } else {
        None
    };
    let slot = handle.update_keyslot(&new_secret()?[..], &secret[..], prev_slot)?;
    Ok(slot)
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
    /// FIDO credential id, generate using fido2luks credential
    #[structopt(name = "credential-id", env = "FIDO2LUKS_CREDENTIAL_ID")]
    pub credential_id: String,
    /// Salt for secret generation, defaults to 'ask'
    ///
    /// Options:{n}
    ///  - ask              : Promt user using password helper{n}
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

impl SecretGeneration {
    pub fn patch(&self, args: &Args) -> Self {
        let mut me = self.clone();
        if args.interactive {
            me.password_helper = PasswordHelper::Stdin;
        }
        me
    }

    pub fn obtain_secret(&self) -> Fido2LuksResult<[u8; 32]> {
        let salt = self.salt.obtain(&self.password_helper)?;
        Ok(assemble_secret(
            &perform_challenge(&self.credential_id, &salt)?,
            &salt,
        ))
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
        /// Use a keyfile instead of a password
        #[structopt(short = "d", long = "keyfile")]
        keyfile: Option<PathBuf>,
        #[structopt(flatten)]
        secret_gen: SecretGeneration,
    },

    /// Replace a previously added key with a password
    #[structopt(name = "replace-key")]
    ReplaceKey {
        #[structopt(env = "FIDO2LUKS_DEVICE")]
        device: PathBuf,
        /// Add the password and keep the key
        #[structopt(short = "a", long = "add-password")]
        add_password: bool,
        /// Use a keyfile instead of a password
        #[structopt(short = "d", long = "keyfile")]
        keyfile: Option<PathBuf>,
        #[structopt(flatten)]
        secret_gen: SecretGeneration,
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
            let secret = secret_gen.patch(&args).obtain_secret()?;
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
            keyfile,
            ref secret_gen,
        } => {
            let secret = secret_gen.patch(&args).obtain_secret()?;
            let slot = add_key_to_luks(
                device.clone(),
                &secret,
                if let Some(keyfile) = keyfile.clone() {
                    Box::new(move || util::read_keyfile(keyfile.clone()))
                } else {
                    Box::new(|| {
                        util::read_password("Old password", true).map(|p| p.as_bytes().to_vec())
                    })
                },
                *exclusive,
            )?;
            println!(
                "Added to key to device {}, slot: {}",
                device.display(),
                slot
            );
            Ok(())
        }
        Command::ReplaceKey {
            device,
            add_password,
            keyfile,
            ref secret_gen,
        } => {
            let secret = secret_gen.patch(&args).obtain_secret()?;
            let slot = add_password_to_luks(
                device.clone(),
                &secret,
                if let Some(keyfile) = keyfile.clone() {
                    Box::new(move || util::read_keyfile(keyfile.clone()))
                } else {
                    Box::new(|| {
                        util::read_password("Password to add", true).map(|p| p.as_bytes().to_vec())
                    })
                },
                *add_password,
            )?;
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
                let secret = secret_gen.patch(&args).obtain_secret()?;
                match open_container(&device, &name, &secret) {
                    Err(e) => match e {
                        Fido2LuksError::WrongSecret if retries > 0 => {
                            retries -= 1;
                            eprintln!("{}", e);
                            continue;
                        }
                        e => Err(e)?,
                    },
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
