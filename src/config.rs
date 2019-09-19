use crate::error::*;
use crate::*;
use crypto::digest::Digest;
use crypto::sha2::Sha256;

use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryInto;
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Deserialize, Serialize)]
pub struct EnvConfig {
    pub credential_id: String,
    pub device: Option<String>,
    pub salt: String,
    pub mapper_name: Option<String>,
    pub password_helper: String,
}

impl TryInto<Config> for EnvConfig {
    type Error = Fido2LuksError;

    fn try_into(self) -> Fido2LuksResult<Config> {
        Ok(Config {
            credential_id: self.credential_id,
            device: self
                .device
                .ok_or(Fido2LuksError::ConfigurationError {
                    cause: ConfigurationError::MissingField("DEVICE".into()),
                })?
                .into(),
            mapper_name: self.mapper_name.ok_or(Fido2LuksError::ConfigurationError {
                cause: ConfigurationError::MissingField("DEVICE_MAPPER".into()),
            })?,
            password_helper: PasswordHelper::Script(self.password_helper),
            input_salt: self.salt.as_str().into(),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub credential_id: String,
    pub input_salt: InputSalt,
    pub device: PathBuf,
    pub mapper_name: String,
    pub password_helper: PasswordHelper,
}

impl Config {
    pub fn load_default_location() -> Fido2LuksResult<Config> {
        Self::load_config(
            &mut File::open(
                env::vars()
                    .collect::<HashMap<_, _>>()
                    .get("FIDO2LUKS_CONFIG")
                    .unwrap_or(&"/etc/fido2luks.json".to_owned()),
            )
            .or(File::open("fido2luks.json"))?,
        )
    }

    pub fn load_config(reader: &mut dyn Read) -> Fido2LuksResult<Config> {
        let mut conf_str = String::new();
        reader.read_to_string(&mut conf_str)?;

        Ok(serde_json::from_str(&conf_str)?)
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            credential_id: "<required>".into(),
            input_salt: Default::default(),
            device: "/dev/some-vg/<volume>".into(),
            mapper_name: "2fa-secured-luks".into(),
            password_helper: PasswordHelper::default(),
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

impl From<&str> for InputSalt {
    fn from(s: &str) -> Self {
        if PathBuf::from(s).exists() && s != "Ask" {
            InputSalt::File { path: s.into() }
        } else {
            InputSalt::AskPassword
        }
    }
}

impl InputSalt {
    pub fn obtain(&self, password_helper: &PasswordHelper) -> Fido2LuksResult<[u8; 32]> {
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
                digest.input(password_helper.obtain()?.as_bytes());
            }
            InputSalt::Both { path } => {
                digest.input(&InputSalt::AskPassword.obtain(password_helper)?);
                digest.input(&InputSalt::File { path: path.clone() }.obtain(password_helper)?)
            }
        }
        let mut salt = [0u8; 32];
        digest.result(&mut salt);
        Ok(salt)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub enum PasswordHelper {
    Script(String),
    Systemd,
    Stdin,
}

impl Default for PasswordHelper {
    fn default() -> Self {
        PasswordHelper::Script("/usr/bin/systemd-ask-password --no-tty 'Please enter second factor for LUKS disk encryption!'".into())
    }
}

impl From<&str> for PasswordHelper {
    fn from(s: &str) -> Self {
        match s {
            "stdin" => PasswordHelper::Stdin,
            s => PasswordHelper::Script(s.into()),
        }
    }
}

impl PasswordHelper {
    pub fn obtain(&self) -> Fido2LuksResult<String> {
        use PasswordHelper::*;
        match self {
            Systemd => unimplemented!(),
            Stdin => Ok(rpassword::read_password_from_tty(Some("Password: "))
                .map_err(|e| Fido2LuksError::AskPassError {
                    cause: AskPassError::IO(e),
                })
                .and_then(|pass| {
                    match rpassword::read_password_from_tty(Some("Password again: ")).map_err(|e| {
                        Fido2LuksError::AskPassError {
                            cause: AskPassError::IO(e),
                        }
                    }) {
                        Ok(ref pass2) if &pass == pass2 => Ok(pass),
                        Ok(_) => Err(Fido2LuksError::AskPassError {
                            cause: error::AskPassError::Mismatch,
                        }),
                        e => e,
                    }
                })?),
            Script(password_helper) => {
                let mut helper_parts = password_helper.split(" ");

                let password = Command::new((&mut helper_parts).next().unwrap())
                    .args(helper_parts)
                    .output()
                    .map_err(|e| Fido2LuksError::AskPassError {
                        cause: error::AskPassError::IO(e),
                    })?
                    .stdout;
                Ok(String::from_utf8(password)?.trim().to_owned())
            }
        }
    }
}
