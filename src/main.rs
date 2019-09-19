#[macro_use]
extern crate failure;
extern crate serde_derive;
use crate::cli::*;
use crate::config::*;
use crate::device::*;
use crate::error::*;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use cryptsetup_rs as luks;

use cryptsetup_rs::Luks1CryptDevice;
use ctap;

use luks::device::Error::CryptsetupError;

use std::collections::HashMap;
use std::env;

use std::convert::TryInto;
use std::io::{self, stdout, Write};
use std::path::PathBuf;
use std::process::exit;

mod cli;
mod config;
mod device;
mod error;

fn open_container(device: &PathBuf, name: &str, secret: &[u8; 32]) -> Fido2LuksResult<()> {
    let mut handle = luks::open(device.canonicalize()?)?.luks1()?;
    let _slot = handle.activate(name, &secret[..])?;
    Ok(())
}

fn assemble_secret(hmac_result: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.input(salt);
    digest.input(hmac_result);
    let mut secret = [0u8; 32];
    digest.result(&mut secret);
    secret
}
fn ask_str(q: &str) -> Fido2LuksResult<String> {
    let stdin = io::stdin();
    let mut s = String::new();
    print!("{}", q);
    io::stdout().flush()?;
    stdin.read_line(&mut s)?;
    Ok(s.trim().to_owned())
}

fn open(conf: &Config, secret: &[u8; 32]) -> Fido2LuksResult<()> {
    dbg!(hex::encode(&secret));
    match open_container(&conf.device, &conf.mapper_name, &secret) {
        Err(Fido2LuksError::LuksError {
            cause: CryptsetupError(errno),
        }) if errno.0 == 1 => Err(Fido2LuksError::WrongSecret)?,
        e => e?,
    };
    Ok(())
}

/*fn package_self() -> Fido2LuksResult<()> {
    let conf = Config::load_default_location()?;
    let binary_path: PathBuf = env::args().next().unwrap().into();
    let mut me = File::open(binary_path)?;

    me.seek(io::SeekFrom::End(("config".as_bytes().len() * -1) as i64 - 4))?;

    let conf_len = me.read_u32()?;

    let mut buf = vec![0u8; 512];

    me.read(&mut buf[0..6])?;

    if String::from_utf8((&buf[0..6]).iter().collect()).map(|s| &s == "config").unwrap_or(false) {

    }

    Ok(())
}*/

fn main() -> Fido2LuksResult<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    fn config_env() -> Fido2LuksResult<EnvConfig> {
        Ok(envy::prefixed("FIDO2LUKS_").from_env::<EnvConfig>()?)
    }
    fn secret_from_env_config(conf: &EnvConfig) -> Fido2LuksResult<[u8; 32]> {
        let conf = config_env()?;
        let salt =
            InputSalt::from(conf.salt.as_str()).obtain(&conf.password_helper.as_str().into())?;
        Ok(assemble_secret(
            &perform_challenge(&conf.credential_id, &salt)?,
            &salt,
        ))
    }
    match &args.iter().map(|s| s.as_str()).collect::<Vec<_>>()[..] {
        ["print-secret"] => {
            let conf = config_env()?;
            io::stdout().write(hex::encode(&secret_from_env_config(&conf)?[..]).as_bytes())?;
            Ok(io::stdout().flush()?)
        }
        ["open"] => {
            let mut conf = config_env()?;
            open_container(
                &conf
                    .device
                    .as_ref()
                    .expect("please specify FIDO2LUKS_DEVICE")
                    .into(),
                &conf
                    .mapper_name
                    .as_ref()
                    .expect("please specify FIDO2LUKS_MAPPER_NAME"),
                &secret_from_env_config(&conf)?,
            )
        }
        ["open", device, mapper_name] => {
            let mut conf = config_env()?;
            conf.mapper_name = Some(mapper_name.to_string());
            conf.device = Some(device.to_string());
            open_container(
                &conf
                    .device
                    .as_ref()
                    .expect("please specify FIDO2LUKS_DEVICE")
                    .into(),
                &conf
                    .mapper_name
                    .as_ref()
                    .expect("please specify FIDO2LUKS_MAPPER_NAME"),
                &secret_from_env_config(&conf)?,
            )
        }
        ["credential"] => {
            let cred = make_credential_id()?;
            println!("{}", hex::encode(&cred.id));
            Ok(())
        }
        ["addkey", device] => {
            let mut conf = config_env()?;
            conf.device = conf.device.or(Some(device.to_string()));
            let slot = add_key_to_luks(
                conf.device.as_ref().unwrap().into(),
                &secret_from_env_config(&conf)?,
            )?;
            println!("Added to key to device {}, slot: {}", device, slot);
            Ok(())
        }
        _ => {
            println!(
                "Usage:\n
            fido2luks open <device> [name]\n
            fido2luks addkey <device>\n\n
            Environment variables:\n
            <FIDO2LUKS_CREDENTIAL_ID>\n
            <FIDO2LUKS_SALT>\n
            "
            );
            Ok(())
        }
    }
}

fn main_old() -> Fido2LuksResult<()> {
    let args: Vec<_> = env::args().skip(1).collect(); //Ignore program name -> Vec
    let env = env::vars().collect::<HashMap<_, _>>();
    let secret = |conf: &Config| -> Fido2LuksResult<[u8; 32]> {
        let salt = conf.input_salt.obtain(&conf.password_helper)?;

        Ok(assemble_secret(
            &perform_challenge(&conf.credential_id, &salt)?,
            &salt,
        ))
    };
    if args.is_empty() {
        let conf = Config::load_default_location()?;
        if env.contains_key("CRYPTTAB_NAME") {
            //Indicates that this script is being run as keyscript
            let mut out = stdout();
            out.write(&secret(&conf)?)?;
            Ok(out.flush()?)
        } else {
            io::stdout().write(&secret(&conf)?)?;
            Ok(io::stdout().flush()?)
        }
    } else {
        match args.first().map(|s| s.as_ref()).unwrap() {
            //"addkey" => add_key_to_luks(&Config::load_default_location()?).map(|_| ()),
            "setup" => setup(),
            "open" if args.get(1).map(|a| &*a == "-e").unwrap_or(false) => {
                let conf = envy::prefixed("FIDO2LUKS_")
                    .from_env::<EnvConfig>()
                    .expect("Missing env config values")
                    .try_into()?;
                open(&conf, &secret(&conf)?)
            }
            "open" => open(
                &Config::load_default_location()?,
                &secret(&Config::load_default_location()?)?,
            ),
            "connected" => match authenticator_connected()? {
                false => {
                    println!("no");
                    exit(1)
                }
                _ => {
                    println!("yes");
                    exit(0)
                }
            },
            _ => {
                eprintln!("Usage: setup | addkey | connected");
                Ok(())
            } //"selfcontain" => package_self()
        }
    }
}
