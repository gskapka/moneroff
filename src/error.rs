use hex;
use num_bigint;
use std::error::Error;
use std::{fmt, option};

#[derive(Debug)]
pub enum AppError {
    HexError(hex::FromHexError),
    NoneError(option::NoneError),
    ParseBigIntError(num_bigint::ParseBigIntError),
}

//#[unstable(feature = "try_trait", issue = "42327")]
impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match *self {
            AppError::HexError(ref e) => format!("Hex error: {}", e),
            AppError::NoneError(ref e) => format!("Option error: {:?}", e),
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

impl From<hex::FromHexError> for AppError {
    fn from(e: hex::FromHexError) -> AppError {
        AppError::HexError(e)
    }
}
