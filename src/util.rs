use crate::error::*;
use ring::digest;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

pub fn sha256(messages: &[&[u8]]) -> [u8; 32] {
    let mut digest = digest::Context::new(&digest::SHA256);
    for m in messages.iter() {
        digest.update(m);
    }
    let mut secret = [0u8; 32];
    secret.as_mut().copy_from_slice(digest.finish().as_ref());
    secret
}
pub fn read_password_tty(q: &str, verify: bool) -> Fido2LuksResult<String> {
    read_password(q, verify, true)
}
pub fn read_password(q: &str, verify: bool, tty: bool) -> Fido2LuksResult<String> {
    let res = if tty {
        rpassword::read_password_from_tty(Some(&[q, ": "].join("")))
    } else {
        print!("{}: ", q);
        rpassword::read_password()
    }?;
    match res {
        ref pass
            if verify
                && &rpassword::read_password_from_tty(Some(&[q, "(again): "].join(" ")))?
                    != pass =>
        {
            Err(Fido2LuksError::AskPassError {
                cause: AskPassError::Mismatch,
            })
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
