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

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::exit;

mod cli;
mod config;
mod device;
mod error;
mod keystore;

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
    let args: Vec<_> = env::args().skip(1).collect(); //Ignore program name -> Vec
    let env = env::vars().collect::<HashMap<_, _>>();
    if args.is_empty() {
        let conf = Config::load_default_location()?;
        let salt = conf.input_salt.obtain(&conf.password_helper)?;
        dbg!(hex::encode(&salt));
        let secret = {
            let salt = conf.input_salt.obtain(&conf.password_helper)?;

            assemble_secret(&perform_challenge(&conf.credential_id, &salt)?, &salt)
        };
        if env.contains_key("CRYPTTAB_NAME") {
            //Indicates that this script is being run as keyscript
            open(&conf, &secret)
        } else {
            io::stdout().write(&secret)?;
            Ok(io::stdout().flush()?)
        }
    } else {
        match args.first().map(|s| s.as_ref()).unwrap() {
            "addkey" => add_key_to_luks(&Config::load_default_location()?).map(|_| ()),
            "setup" => setup(),
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
