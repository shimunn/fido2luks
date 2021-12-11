use crate::error::*;
use crate::luks::{Fido2LuksToken, LuksDevice};
use crate::util::sha256;
use crate::*;
pub use cli_args::Args;
use cli_args::*;
use ctap::{FidoCredential, FidoErrorKind};
use std::borrow::Cow;
use std::collections::HashSet;
use std::io::Write;
use std::iter::FromIterator;
use std::path::Path;
use std::str::FromStr;
use std::thread;
use std::time::Duration;
use std::time::SystemTime;
use structopt::clap::Shell;
use structopt::StructOpt;

fn read_pin() -> Fido2LuksResult<String> {
    util::read_password_tty("Authenticator PIN", false)
}

fn derive_secret(
    credentials: &[HexEncoded],
    salt: &[u8; 32],
    timeout: u64,
    pin: Option<&str>,
) -> Fido2LuksResult<([u8; 32], FidoCredential)> {
    if credentials.is_empty() {
        return Err(Fido2LuksError::InsufficientCredentials);
    }
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

    let binary = sha256(&[salt, &unsalted[..]]);
    Ok((binary, cred.clone()))
}

pub fn extend_creds_device(
    creds: &[HexEncoded],
    luks_dev: &mut LuksDevice,
) -> Fido2LuksResult<Vec<HexEncoded>> {
    let mut additional = HashSet::new();
    additional.extend(creds.iter().cloned());
    for token in luks_dev.tokens()? {
        for cred in token?.1.credential {
            let parsed = HexEncoded::from_str(cred.as_str()).map_err(|_e| {
                Fido2LuksError::HexEncodingError {
                    string: cred.clone(),
                }
            })?;
            additional.insert(parsed);
        }
    }
    Ok(Vec::from_iter(additional.into_iter()))
}

pub fn get_input(
    secret: &SecretParameters,
    authenticator: &AuthenticatorParameters,
    interactive: bool,
    q: &str,
    verify: bool,
) -> Fido2LuksResult<(Option<String>, [u8; 32])> {
    let password_helper = secret
        .password_helper
        .as_ref()
        .map(|helper| move || helper.obtain());
    let salt = &secret.salt;
    Ok(if interactive {
        (
            if authenticator.pin && may_require_pin()? {
                Some(read_pin()?)
            } else {
                None
            },
            salt.obtain_sha256(Some(|| util::read_password_tty(q, verify)))?,
        )
    } else {
        match (
            authenticator.pin && may_require_pin()?,
            authenticator.pin_prefixed,
        ) {
            (true, false) => (Some(read_pin()?), salt.obtain_sha256(password_helper)?),
            (true, true) => read_password_pin_prefixed(|| {
                salt.obtain(password_helper).and_then(|secret| {
                    String::from_utf8(secret).map_err(|e| Fido2LuksError::from(e))
                })
            })?,
            (false, _) => (None, salt.obtain_sha256(password_helper)?),
        }
    })
}

pub fn read_password_pin_prefixed(
    prefixed: impl Fn() -> Fido2LuksResult<String>,
) -> Fido2LuksResult<(Option<String>, [u8; 32])> {
    let read = prefixed()?;
    let separator = ':';
    let mut parts = read.split(separator);
    let pin = parts.next().filter(|p| p.len() > 0).map(|p| p.to_string());
    let password = match pin {
        Some(ref pin) if read.len() > pin.len() => {
            read.chars().skip(pin.len() + 1).collect::<String>()
        }
        Some(_) => String::new(),
        _ => read
            .chars()
            .skip(read.chars().next().map(|c| c == separator).unwrap_or(false) as usize)
            .collect::<String>(),
    };
    Ok((pin, util::sha256(&[password.as_bytes()])))
}

/// generate an more readable name from common paths
pub fn derive_credential_name(path: &Path) -> String {
    match path.file_name() {
        Some(name)
            if path
                .iter()
                .any(|p| p == "by-label" || p == "by-partlabel" || p == "by-uuid") =>
        {
            name.to_string_lossy().as_ref().to_string()
        }
        _ => path.display().to_string(),
    }
}

pub fn parse_cmdline() -> Args {
    Args::from_args()
}

pub fn prompt_interaction(interactive: bool) {
    if interactive {
        println!("Authorize using your FIDO device");
    }
}

pub fn run_cli() -> Fido2LuksResult<()> {
    let mut stdout = io::stdout();
    let args = parse_cmdline();
    let log = |message: &dyn Fn() -> String| {
        if args.verbose {
            eprintln!("{}", &*message());
        }
    };
    let interactive = args.interactive;
    match &args.command {
        Command::Credential {
            authenticator,
            name,
        } => {
            let pin_string;
            let pin = if authenticator.pin && may_require_pin()? {
                pin_string = read_pin()?;
                Some(pin_string.as_ref())
            } else {
                None
            };
            let cred = make_credential_id(Some(name.as_ref()), pin)?;
            println!("{}", hex::encode(&cred.id));
            Ok(())
        }
        Command::PrintSecret {
            binary,
            authenticator,
            credentials,
            secret,
            device,
        } => {
            let (pin, salt) =
                get_input(&secret, &authenticator, args.interactive, "Password", false)?;
            let credentials = if let Some(path) = device {
                let mut dev = LuksDevice::load(path)?;
                let luks2 = dev.is_luks2()?;
                log(&|| format!("luks2 supported: {}", luks2));
                extend_creds_device(
                    credentials
                        .ids
                        .clone()
                        .map(|cs| cs.0)
                        .unwrap_or_default()
                        .as_slice(),
                    &mut dev,
                )?
            } else {
                credentials.ids.clone().map(|cs| cs.0).unwrap_or_default()
            };
            log(&|| {
                format!(
                    "credentials: {}",
                    credentials
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            });
            prompt_interaction(interactive);
            let (secret, cred) = derive_secret(
                &credentials,
                &salt,
                authenticator.await_time,
                pin.as_deref(),
            )?;
            log(&|| format!("credential used: {}", hex::encode(&cred.id)));
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
            ..
        }
        | Command::ReplaceKey {
            luks,
            authenticator,
            credentials,
            secret,
            luks_mod,
            replacement: other_secret,
            ..
        } => {
            let mut luks_dev = LuksDevice::load(&luks.device)?;

            let luks2 = luks_dev.is_luks2()?;

            log(&|| format!("luks2 supported: {}", luks2));

            let credentials = if !luks.disable_token && luks2 {
                extend_creds_device(
                    credentials
                        .ids
                        .clone()
                        .map(|cs| cs.0)
                        .unwrap_or_default()
                        .as_slice(),
                    &mut luks_dev,
                )?
            } else {
                credentials.ids.clone().map(|cs| cs.0).unwrap_or_default()
            };
            log(&|| {
                format!(
                    "credentials: {}",
                    credentials
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            });
            let inputs = |q: &str, verify: bool| -> Fido2LuksResult<(Option<String>, [u8; 32])> {
                get_input(&secret, &authenticator, args.interactive, q, verify)
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
                    } => {
                        let (pin, salt) = inputs(salt_q, verify)?;
                        prompt_interaction(interactive);
                        Ok(derive_secret(
                            &credentials,
                            &salt,
                            authenticator.await_time,
                            pin.as_deref(),
                        )
                        .map(|(secret, cred)| (secret[..].to_vec(), Some(cred)))?)
                    }
                    _ => Ok((
                        util::read_password_tty(salt_q, verify)?.as_bytes().to_vec(),
                        None,
                    )),
                }
            };
            let secret = |q: &str,
                          verify: bool,
                          credentials: &[HexEncoded]|
             -> Fido2LuksResult<([u8; 32], FidoCredential)> {
                let (pin, salt) = inputs(q, verify)?;
                prompt_interaction(interactive);
                derive_secret(credentials, &salt, authenticator.await_time, pin.as_deref())
            };
            // Non overlap
            match &args.command {
                Command::AddKey {
                    exclusive,
                    generate_credential,
                    ..
                } => {
                    let (existing_secret, _) = other_secret("Current password", false)?;
                    let (new_secret, cred) = if *generate_credential && luks2 {
                        let cred = make_credential_id(
                            Some(derive_credential_name(luks.device.as_path()).as_str()),
                            (if authenticator.pin && may_require_pin()? {
                                //TODO: not ideal since it ignores pin-prefixed
                                Some(read_pin()?)
                            } else {
                                None
                            })
                            .as_deref(),
                        )?;
                        log(&|| {
                            format!(
                                "generated credential: {}\ncredential username: {:?}",
                                hex::encode(&cred.id),
                                derive_credential_name(luks.device.as_path())
                            )
                        });
                        let creds = vec![HexEncoded(cred.id)];
                        secret("Password to be added", true, &creds)
                    } else {
                        secret("Password to be added", true, &credentials)
                    }?;
                    log(&|| format!("credential used: {}", hex::encode(&cred.id)));
                    let added_slot = luks_dev.add_key(
                        &new_secret,
                        &existing_secret[..],
                        luks_mod.kdf_time.or(Some(10)),
                        Some(&cred.id[..])
                            .filter(|_| !luks.disable_token || *generate_credential)
                            .filter(|_| luks2),
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
                Command::ReplaceKey {
                    add_password,
                    remove_cred,
                    ..
                } => {
                    let (existing_secret, _prev_cred) =
                        secret("Current password", false, &credentials)?;
                    let (replacement_secret, cred) = other_secret("Replacement password", true)?;
                    let slot = if *add_password {
                        luks_dev.add_key(
                            &replacement_secret[..],
                            &existing_secret,
                            luks_mod.kdf_time,
                            cred.as_ref()
                                .filter(|_| !luks.disable_token)
                                .filter(|_| luks2)
                                .map(|cred| &cred.id[..]),
                        )
                    } else {
                        let slot = luks_dev.replace_key(
                            &replacement_secret[..],
                            &existing_secret,
                            luks_mod.kdf_time,
                            cred.as_ref()
                                .filter(|_| !luks.disable_token)
                                .filter(|_| luks2)
                                .map(|cred| &cred.id[..]),
                        )?;
                        if *remove_cred && cred.is_none() {
                            luks_dev.remove_token_slot(slot)?;
                        }
                        Ok(slot)
                    }?;
                    if let Some(cred) = cred {
                        log(&|| format!("credential used: {}", hex::encode(&cred.id)));
                    }
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
            credentials,
            retries,
            dry_run,
        } => {
            let inputs = |q: &str, verify: bool| -> Fido2LuksResult<(Option<String>, [u8; 32])> {
                get_input(&secret, &authenticator, args.interactive, q, verify)
            };

            // Cow shouldn't be necessary
            let secret = |credentials: Cow<'_, Vec<HexEncoded>>| {
                let (pin, salt) = inputs("Password", false)?;
                prompt_interaction(interactive);
                derive_secret(
                    credentials.as_ref(),
                    &salt,
                    authenticator.await_time,
                    pin.as_deref(),
                )
            };

            let mut retries = *retries;
            let mut luks_dev = LuksDevice::load(&luks.device)?;
            let luks2 = luks_dev.is_luks2()?;
            log(&|| format!("luks2 supported: {}", luks2));
            loop {
                let slot = if let Some(ref credentials) = credentials.ids {
                    log(&|| {
                        format!(
                            "credentials: {}",
                            credentials
                                .0
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    });
                    secret(Cow::Borrowed(&credentials.0)).and_then(|(secret, cred)| {
                        log(&|| format!("credential used: {}", hex::encode(&cred.id)));
                        luks_dev.activate(&name, &secret, luks.slot, *dry_run)
                    })
                } else if luks2 && !luks.disable_token {
                    luks_dev.activate_token(
                        &name,
                        Box::new(|credentials: Vec<String>| {
                            log(&|| format!("credentials: {}", credentials.join(", ")));
                            let creds = credentials
                                .into_iter()
                                .flat_map(|cred| HexEncoded::from_str(cred.as_ref()).ok())
                                .collect::<Vec<_>>();
                            secret(Cow::Owned(creds)).map(|(secret, cred)| {
                                log(&|| format!("credential used: {}", hex::encode(&cred.id)));
                                (secret, hex::encode(&cred.id))
                            })
                        }),
                        luks.slot,
                        *dry_run,
                    )
                } else if luks_dev.is_luks2()? && luks.disable_token {
                    // disable-token is mostly cosmetic in this instance
                    return Err(Fido2LuksError::InsufficientCredentials);
                } else {
                    return Err(Fido2LuksError::WrongSecret);
                };
                match slot {
                    Err(e) => {
                        match e {
                            Fido2LuksError::WrongSecret if retries > 0 => {}
                            Fido2LuksError::AuthenticatorError { ref cause }
                                if cause.kind() == FidoErrorKind::Timeout && retries > 0 => {}

                            e => return Err(e),
                        };
                        retries -= 1;
                        eprintln!("{}", e);
                    }
                    Ok(slot) => {
                        log(&|| format!("keyslot: {}", slot));
                        break Ok(());
                    }
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
                    dev.add_token(&Fido2LuksToken::with_credentials(&credentials.0, *slot))?;
                    1
                } else {
                    tokens.len()
                };
                for (id, mut token) in tokens {
                    token
                        .credential
                        .extend(credentials.0.iter().map(|h| h.to_string()));
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
                        .filter(|cred| !credentials.0.iter().any(|h| &h.to_string() == cred))
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
            // zsh won't work atm https://github.com/clap-rs/clap/issues/1822
            if let Some(s) = shell {
                if s.as_str() == "zsh" {
                    unimplemented!("zsh completions are broken atm: see https://github.com/clap-rs/clap/issues/1822")
                }
            }
            for variant in Shell::variants().iter().filter(|v| *v != &"zsh") {
                if let Some(s) = shell {
                    if *variant != s.as_str() {
                        break;
                    }
                }
                Args::clap().gen_completions(
                    env!("CARGO_PKG_NAME"),
                    Shell::from_str(variant)
                        .expect("structopt shouldn't allow us to reach this point"),
                    &out_dir,
                );
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_read_password_pin_prefixed() {
        // 1234:test -> PIN: 1234, password: test
        assert_eq!(
            read_password_pin_prefixed(|| Ok("1234:test".into())).unwrap(),
            (Some("1234".to_string()), util::sha256(&["test".as_bytes()]))
        );
        // :test -> PIN: None, password: test
        assert_eq!(
            read_password_pin_prefixed(|| Ok(":test".into())).unwrap(),
            (None, util::sha256(&["test".as_bytes()]))
        );
        // 1234::test -> PIN: 1234, password: :test
        assert_eq!(
            read_password_pin_prefixed(|| Ok("1234::test".into())).unwrap(),
            (
                Some("1234".to_string()),
                util::sha256(&[":test".as_bytes()])
            )
        );
        // 1234 -> PIN: 1234, password: empty
        assert_eq!(
            read_password_pin_prefixed(|| Ok("1234".into())).unwrap(),
            (Some("1234".to_string()), util::sha256(&["".as_bytes()]))
        );
        // 1234:test -> PIN: None, password: test
        assert_eq!(
            read_password_pin_prefixed(|| Ok(":test".into())).unwrap(),
            (None, util::sha256(&["test".as_bytes()]))
        );
    }
}
