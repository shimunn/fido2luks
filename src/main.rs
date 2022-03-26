#[macro_use]
extern crate failure;
#[macro_use]
extern crate serde_derive;
use crate::cli::*;
use crate::device::*;
use crate::error::*;
use std::io;
use std::process::exit;

mod cli;
pub mod cli_args;
mod device;
mod error;
mod luks;
mod util;

fn main() -> Fido2LuksResult<()> {
    match run_cli() {
        Err(e) => {
            eprintln!("{:?}", e);
            exit(e.exit_code())
        }
        _ => exit(0),
    }
}
