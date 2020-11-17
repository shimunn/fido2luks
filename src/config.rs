use crate::error::*;
use crate::*;
use ring::digest;

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
        let mut parts = s.split(':');
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
        let mut digest = digest::Context::new(&digest::SHA256);
        match self {
            InputSalt::File { path } => {
                let mut do_io = || {
                    let mut reader = File::open(path)?;
                    let mut buf = [0u8; 512];
                    loop {
                        let red = reader.read(&mut buf)?;
                        digest.update(&buf[0..red]);
                        if red == 0 {
                            break;
                        }
                    }
                    Ok(())
                };
                do_io().map_err(|cause| Fido2LuksError::KeyfileError { cause })?;
            }
            InputSalt::AskPassword => {
                digest.update(password_helper.obtain()?.as_bytes());
            }
            InputSalt::String(s) => digest.update(s.as_bytes()),
        }
        let mut salt = [0u8; 32];
        salt.as_mut().copy_from_slice(digest.finish().as_ref());
        Ok(salt)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordHelper {
    Script(String),
    #[allow(dead_code)]
    Systemd,
    Stdin,
}

impl Default for PasswordHelper {
    fn default() -> Self {
        PasswordHelper::Script(
            "/usr/bin/env systemd-ask-password 'Please enter second factor for LUKS disk encryption!'"
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
                let password = Command::new("sh")
                    .arg("-c")
                    .arg(&password_helper)
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

    #[test]
    fn input_salt_obtain() {
        assert_eq!(
            InputSalt::String("abc".into())
                .obtain(&PasswordHelper::Stdin)
                .unwrap(),
            [
                186, 120, 22, 191, 143, 1, 207, 234, 65, 65, 64, 222, 93, 174, 34, 35, 176, 3, 97,
                163, 150, 23, 122, 156, 180, 16, 255, 97, 242, 0, 21, 173
            ]
        )
    }
}
