#![feature(try_trait)]
#![feature(rustc_private)]

mod types;
mod error;
mod keccak;
mod monero_keys;
mod key_cryptography;
mod cli_arg_executor;
mod edwards_curve_cryptography;

extern crate serde;
#[macro_use] extern crate serde_derive;

use docopt::Docopt;
use crate::cli_arg_executor::{
    USAGE_INFO,
    execute_based_on_cli_args
};

fn main() -> () {
    match Docopt::new(USAGE_INFO)
        .and_then(|d| d.deserialize())
        .map(execute_based_on_cli_args) {
            Ok(_) => (),
            Err(e) => e.exit()
        }
}
