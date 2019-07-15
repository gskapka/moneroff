use std::result;
use crate::error::AppError;

use crate::monero_keys::{
    generate_monero_keys_from,
    generate_random_monero_keys,
};

type Result<T> = result::Result<T, AppError>;

pub static USAGE_INFO: &'static str = "
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
pub struct CliArgs {
    cmd_from: bool,
    arg_key: String,
    cmd_random: bool,
    cmd_generate: bool,
}

pub fn execute_based_on_cli_args(args: CliArgs) -> Result<()> {
    match args {
        CliArgs {cmd_generate: true, cmd_from: false, ..} => {
            println!("{}", generate_random_monero_keys()?);
            Ok(())
        },
        CliArgs {cmd_generate: true, cmd_from: true, ..} => {
            match generate_monero_keys_from(args.arg_key) {
                Ok(keys) => println!("{}", keys),
                Err(e) => println!("{}", e)
            };
            Ok(())
        },
        _ => Ok(println!("{}", USAGE_INFO))
    }
}
