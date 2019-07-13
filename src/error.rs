use hex;
use num_bigint;
use std::error::Error;
use std::{fmt, option};

#[derive(Debug)]
pub enum AppError {
    Custom(String),
    FmtError(fmt::Error),
    HexError(hex::FromHexError),
    NoneError(option::NoneError),
    Base58Error(cryptonote_base58::Base58Error),
    ParseBigIntError(num_bigint::ParseBigIntError),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match *self {
            AppError::Custom(ref msg) => msg.clone(),
            AppError::HexError(ref e) => format!("Hex error: {}", e),
            AppError::NoneError(ref e) => format!("Option error: {:?}", e),
            AppError::FmtError(ref e) => format!("Formatter error: {}", e),
            AppError::Base58Error(ref e) => format!("Base58 error: {:?}", e),
            AppError::ParseBigIntError(ref e) => format!("BigUint error: {}", e),
        };
        f.write_fmt(format_args!("{}", msg))
    }
}

impl Error for AppError {
    fn description(&self) -> &str {
        "Program Error"
    }
}

impl From<num_bigint::ParseBigIntError> for AppError {
    fn from(err: num_bigint::ParseBigIntError) -> AppError {
        AppError::ParseBigIntError(err)
    }
}

impl From<option::NoneError> for AppError {
    fn from(err: option::NoneError) -> AppError {
        AppError::NoneError(err)
    }
}

impl From<fmt::Error> for AppError {
    fn from(err: fmt::Error) -> AppError {
        AppError::FmtError(err)
    }
}

impl From<cryptonote_base58::Base58Error> for AppError {
    fn from(err: cryptonote_base58::Base58Error) -> AppError {
        AppError::Base58Error(err)
    }
}

impl From<hex::FromHexError> for AppError {
    fn from(e: hex::FromHexError) -> AppError {
        AppError::HexError(e)
    }
}
