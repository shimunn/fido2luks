#[macro_use] extern crate failure;
#[macro_use] extern crate serde_derive;
use crate::error::*;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{PathBuf, Path};
use ctap::extensions::hmac::{HmacExtension, FidoHmacCredential};
use ctap;
use ctap::FidoDevice;
use cryptsetup_rs as luks;
use cryptsetup_rs::Luks1CryptDevice;
use serde_derive::{Serialize, Deserialize};
use std::process::Command;
mod error;

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub credential_id: String,
    pub input_salt: InputSalt,
    pub device: PathBuf,
    pub mapper_name: String,
    pub password_helper: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
       Config {
           credential_id: "generate using solo key make-credential".into(),
           input_salt: Default::default(),
           device: "/dev/some-vg/my-volume".into(),
           mapper_name: "2fa-secured-luks".into(),
           password_helper: "/lib/cryptsetup/askpass".into()
       }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub enum InputSalt {
    AskPassword,
    File { path: PathBuf },
    Both { path: PathBuf },
}

impl Default for InputSalt {
    fn default() -> Self {
       InputSalt::AskPassword
    }
}

impl InputSalt {
    fn obtain(&self, password_helper: &PathBuf) -> Fido2LuksResult<[u8; 32]> {
        let mut digest = Sha256::new();
        match self {
            InputSalt::File { path } => {
                let mut do_io = || {
                    let mut reader = File::open(path)?;
                    let mut buf = [0u8; 512];
                    loop {
                        let red = reader.read(&mut buf)?;
                        digest.input(&buf[0..red]);
                        if red == 0 {
                            break;
                        }
                    }
                    Ok(())
                };
                do_io().map_err(|cause| Fido2LuksError::KeyfileError { cause })?;
            }
            InputSalt::AskPassword => {
                let password =Command::new(password_helper).arg("FIDO2 Password salt:").output().map_err(|e| Fido2LuksError::AskPassError{ cause: e })?.stdout;
                digest.input(&password);
            }
           InputSalt::Both { path} => {
                digest.input(&InputSalt::AskPassword.obtain(password_helper)?);
                digest.input(&InputSalt::File { path: path.clone() }.obtain(password_helper)?)
            }
        }
        let mut salt = [0u8; 32];
        digest.result(&mut salt);
        Ok(salt)
    }
}

fn open_container(device: &PathBuf, name: &str, secret: &[u8; 32]) -> Fido2LuksResult<()> {
    let mut handle = luks::open(device)?.luks1()?;
    let _slot = handle.activate(name, &secret[..])?;
    Ok(())
}

fn perform_challenge(credential_id: &str, salt: &[u8; 32]) -> Fido2LuksResult<[u8; 32]> {
    let cred = FidoHmacCredential{
        id: hex::decode(credential_id).unwrap(),
        rp_id: "hmac".to_string()
    };
    let mut errs = Vec::new();
    for di in ctap::get_devices()? {
        let mut dev = FidoDevice::new(&di)?;
        match dev.hmac_challange(&cred, &salt[..]) {
            Ok(secret) => {
                return Ok(secret);
            }
            Err(e) => {
                errs.push(e);
            }
        }
    }
    Err(errs.pop().ok_or(Fido2LuksError::NoAuthenticatorError)?)?
}

fn load_config(reader: &mut dyn Read) -> Fido2LuksResult<Config> {
    let mut conf_str = String::new();
    reader.read_to_string(&mut conf_str)?;

    Ok(serde_json::from_str((&conf_str))?)
}

fn setup() {
    let mut config = Config::default();

    let save_config = |c: &Config| {
        File::create("fido2luks.json").expect("Failed to save config").write_all(serde_json::to_string_pretty(c).unwrap().as_bytes()).expect("Failed to save config");
    };

    fn ask_str(q: &str) -> String {
        let stdin = std::io::stdin();
        let mut s = String::new();
        print!("{}", q);
        std::io::stdout().flush().ok().expect("Could not flush stdout");
        stdin.read_line(&mut s).expect("Failed to read rom stdin");
        s.trim().to_owned()
    }

    fn ask_bool(q: &str) -> bool {
        ask_str(&format!("{} (y/n)", q)) == "y"
    }

    println!("1. Generating a credential");
    let mut ccred: Option<FidoHmacCredential> = None;
    for di in ctap::get_devices().expect("Failed to query USB for 2fa devices") {
        let mut dev = FidoDevice::new(&di).expect("Failed to open 2fa device");
        match dev.make_hmac_credential() {
            Ok(cred) => {
                ccred = Some(cred);
                break;
            }
            Err(e) => println!("Failed to to obtain credential trying next device(if applicable)"),
        }
    }
    config.credential_id = hex::encode(ccred.expect("No credential could be obtained").id);
    save_config(&config);

    loop {
        let device = ask_str("Path to your luks device: ");
        if Path::new(&device).exists() ||  ask_bool(&format!("{} does not exist, save anyway?", device)) {
           config.device = device.into();
            break;
        }
    }

    save_config(&config);

    config.mapper_name = ask_str("Name for decrypted disk: ");

    save_config(&config);

    println!("Config saved to: fido2luks.json");

}

fn main() -> Fido2LuksResult<()> {
    let conf = load_config(&mut File::open("/etc/fido2luks.json").or(File::open("fido2luks.json"))?)?;
    let salt = conf.input_salt.obtain(&conf.password_helper)?;
    dbg!(hex::encode(&salt));
    let secret = {
        let mut digest = Sha256::new();
        digest.input(&salt);
        digest.input(&perform_challenge(&conf.credential_id, &salt)?);
        let mut secret = [0u8; 32];
        digest.result(&mut secret);
        secret
    };
    dbg!(hex::encode(&secret));
    open_container(&conf.device, &conf.mapper_name,&secret)?;
    Ok(())
}
