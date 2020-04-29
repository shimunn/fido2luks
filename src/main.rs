#[macro_use]
extern crate failure;
extern crate ctap_hmac as ctap;
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
