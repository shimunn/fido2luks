use crate::error::*;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

pub fn read_password(q: &str, verify: bool) -> Fido2LuksResult<String> {
    match rpassword::read_password_from_tty(Some(&[q, ": "].join("")))? {
        ref pass
            if verify
                && &rpassword::read_password_from_tty(Some(&[q, "(again): "].join(" ")))?
                    != pass =>
        {
            Err(Fido2LuksError::AskPassError {
                cause: AskPassError::Mismatch,
            })?
        }
        pass => Ok(pass),
    }
}

pub fn read_keyfile<P: Into<PathBuf>>(path: P) -> Fido2LuksResult<Vec<u8>> {
    let mut file = File::open(path.into())?;
    let mut key = Vec::new();
    file.read_to_end(&mut key)?;
    Ok(key)
}
