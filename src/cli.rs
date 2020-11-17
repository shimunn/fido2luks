use crate::error::*;
use crate::luks::{Fido2LuksToken, LuksDevice};
use crate::util::sha256;
use crate::*;
use cli_args::*;

use structopt::clap::Shell;
use structopt::StructOpt;

use ctap::{FidoCredential, FidoErrorKind};

use std::io::{Read, Write};
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use std::borrow::Cow;
use std::collections::HashSet;
use std::fs::File;
use std::time::SystemTime;

pub use cli_args::Args;

fn read_pin(ap: &AuthenticatorParameters) -> Fido2LuksResult<String> {
    if let Some(src) = ap.pin_source.as_ref() {
        let mut pin = String::new();
        File::open(src)?.read_to_string(&mut pin)?;
        Ok(pin)
    } else {
        util::read_password("Authenticator PIN", false)
    }
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
                pin_string = read_pin(authenticator)?;
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
                pin_string = read_pin(authenticator)?;
                Some(pin_string.as_ref())
            } else {
                None
            };
            let salt = if interactive || secret.password_helper == PasswordHelper::Stdin {
                util::read_password_hashed("Password", false)
            } else {
                secret.salt.obtain_sha256(&secret.password_helper)
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
                Some(read_pin(authenticator)?)
            } else {
                None
            };
            let salt = |q: &str, verify: bool| -> Fido2LuksResult<[u8; 32]> {
                if interactive || secret.password_helper == PasswordHelper::Stdin {
                    util::read_password_hashed(q, verify)
                } else {
                    secret.salt.obtain_sha256(&secret.password_helper)
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
                pin_string = read_pin(authenticator)?;
                Some(pin_string.as_ref())
            } else {
                None
            };
            let salt = |q: &str, verify: bool| -> Fido2LuksResult<[u8; 32]> {
                if interactive || secret.password_helper == PasswordHelper::Stdin {
                    util::read_password_hashed(q, verify)
                } else {
                    secret.salt.obtain_sha256(&secret.password_helper)
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
