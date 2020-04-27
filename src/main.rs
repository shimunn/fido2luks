#[macro_use]
extern crate failure;
extern crate ctap_hmac as ctap;
#[macro_use]
extern crate serde_derive;
use crate::cli::*;
use crate::config::*;
use crate::device::*;
use crate::error::*;
use std::io;
use std::path::PathBuf;
use std::process::exit;

mod cli;
mod config;
mod device;
mod error;
mod luks;
mod util;

fn assemble_secret(hmac_result: &[u8], salt: &[u8]) -> [u8; 32] {
    util::sha256(&[salt, hmac_result])
}

fn main() -> Fido2LuksResult<()> {
    match run_cli() {
        Err(e) => {
            #[cfg(debug_assertions)]
            eprintln!("{:?}", e);
            #[cfg(not(debug_assertions))]
            eprintln!("{}", e);
            exit(e.exit_code())
        }
        _ => exit(0),
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_assemble_secret() {
        assert_eq!(
            assemble_secret(b"abc", b"def"),
            [
                46, 82, 82, 140, 142, 159, 249, 196, 227, 160, 142, 72, 151, 77, 59, 62, 180, 36,
                33, 47, 241, 94, 17, 232, 133, 103, 247, 32, 152, 253, 43, 19
            ]
        )
    }
}
