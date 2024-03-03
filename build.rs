#![allow(warnings)]
#[macro_use]
extern crate failure;

#[path = "src/cli_args/mod.rs"]
mod cli_args;
#[path = "src/error.rs"]
mod error;
#[path = "src/util.rs"]
mod util;

use cli_args::Args;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use structopt::clap::Shell;
use structopt::StructOpt;

fn main() {
    let env_outdir = env::var_os("OUT_DIR").unwrap();
    let outdir = PathBuf::from(PathBuf::from(env_outdir).ancestors().nth(3).unwrap());
    fs::create_dir_all(&outdir).unwrap();
    // generate completion scripts, zsh does panic for some reason
    for shell in Shell::variants().iter().filter(|shell| **shell != "zsh") {
        Args::clap().gen_completions(
            env!("CARGO_PKG_NAME"),
            Shell::from_str(shell).unwrap(),
            &outdir,
        );
    }
}
