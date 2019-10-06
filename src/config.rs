use crate::error::*;
use crate::*;
use crypto::digest::Digest;
use crypto::sha2::Sha256;

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq)]
pub enum InputSalt {
    AskPassword,
    String(String),
    File { path: PathBuf },
}

impl Default for InputSalt {
    fn default() -> Self {
        InputSalt::AskPassword
    }
}

impl From<&str> for InputSalt {
    fn from(s: &str) -> Self {
        let mut parts = s.split(":").into_iter();
        match parts.next() {
            Some("ask") | Some("Ask") => InputSalt::AskPassword,
            Some("file") => InputSalt::File {
                path: parts.collect::<Vec<_>>().join(":").into(),
            },
            Some("string") => InputSalt::String(parts.collect::<Vec<_>>().join(":")),
            _ => Self::default(),
        }
    }
}

impl FromStr for InputSalt {
    type Err = Fido2LuksError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(s))
    }
}

impl fmt::Display for InputSalt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&match self {
            InputSalt::AskPassword => "ask".to_string(),
            InputSalt::String(s) => ["string", s].join(":"),
            InputSalt::File { path } => ["file", path.display().to_string().as_str()].join(":"),
        })
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
            InputSalt::String(s) => digest.input(s.as_bytes()),
        }
        let mut salt = [0u8; 32];
        digest.result(&mut salt);
        Ok(salt)
    }
}

#[derive(Debug, Clone)]
pub enum PasswordHelper {
    Script(String),
    Systemd,
    Stdin,
}

impl Default for PasswordHelper {
    fn default() -> Self {
        PasswordHelper::Script(
            "/usr/bin/systemd-ask-password 'Please enter second factor for LUKS disk encryption!'"
                .into(),
        )
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

impl FromStr for PasswordHelper {
    type Err = Fido2LuksError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(s))
    }
}

impl fmt::Display for PasswordHelper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&match self {
            PasswordHelper::Stdin => "stdin".to_string(),
            PasswordHelper::Systemd => "systemd".to_string(),
            PasswordHelper::Script(path) => path.clone(),
        })
    }
}

impl PasswordHelper {
    pub fn obtain(&self) -> Fido2LuksResult<String> {
        use PasswordHelper::*;
        match self {
            Systemd => unimplemented!(),
            Stdin => Ok(util::read_password("Password", true)?),
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

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn input_salt_from_str() {
        assert_eq!(
            "file:/tmp/abc".parse::<InputSalt>().unwrap(),
            InputSalt::File {
                path: "/tmp/abc".into()
            }
        );
        assert_eq!(
            "string:abc".parse::<InputSalt>().unwrap(),
            InputSalt::String("abc".into())
        );
        assert_eq!("ask".parse::<InputSalt>().unwrap(), InputSalt::AskPassword);
        assert_eq!("lol".parse::<InputSalt>().unwrap(), InputSalt::default());
    }
}
