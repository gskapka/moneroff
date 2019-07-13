#![feature(try_trait)]
#![feature(rustc_private)]

mod types;
mod error;
mod constants;
mod monero_keys;
mod cryptography;

extern crate serde;
#[macro_use] extern crate serde_derive;

use std::result;
use docopt::Docopt;
use crate::error::AppError;
use crate::monero_keys::MoneroKeys;

type Result<T> = result::Result<T, AppError>;

static USAGE_INFO: &'static str = "
❍ Monero Key Generator ❍

    Copyright Greg Kapka 2019
    Questions: greg@kapka.co.uk

Usage:  moneroff [-h | --help]
        moneroff generate random
        moneroff generate from <key>

Commands:

    generate random     ❍ Generates a random set of Monero keys
    generate from <key> ❍ Generates a set of Monero keys from given private spend key.

Options:

    -h, --help          ❍ Show this message.
    --key=<key>         ❍ A Monero private spend key in HEX format w/ NO prefix!.

";

#[derive(Debug, Deserialize)]
struct Args {
    cmd_from: bool,
    arg_key: String,
    cmd_random: bool,
    cmd_generate: bool,
}

fn main() -> () {
    match Docopt::new(USAGE_INFO)
        .and_then(|d| d.deserialize())
        .map(execute_from_cli_args) {
            Ok(_) => (),
            Err(e) => e.exit()
        }
}

fn execute_from_cli_args(args: Args) -> Result<()> {
    match args {
        Args {cmd_generate: true, cmd_from: false, ..} => {
            generate_random_keys()
        },
        Args {cmd_generate: true, cmd_from: true, ..} => {
            generate_keys_from_priv_sk(args.arg_key)
        },
        _ => Ok(println!("{}", USAGE_INFO))
    }
}

fn generate_random_keys() -> Result<()> {
    let keys = MoneroKeys::generate_new_random_key()?;
    println!("{}", keys);
    Ok(())
}

fn generate_keys_from_priv_sk(priv_sk: String) -> Result<()> {
    match MoneroKeys::from_existing_key(priv_sk) {
        Ok(keys) => println!("{}", keys),
        Err(e) => println!("{}", e)
    };
    Ok(())
}
