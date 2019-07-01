use hex;
use num_bigint;
use std::error::Error;
use std::{fmt, option};

#[derive(Debug)]
pub enum AppError {
    Custom(String),
    HexError(hex::FromHexError),
    NoneError(option::NoneError),
    ParseBigIntError(num_bigint::ParseBigIntError),
}

//#[unstable(feature = "try_trait", issue = "42327")]
impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match *self {
            AppError::Custom(ref msg) => msg.clone(),
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
/*

use hex;
//use reqwest;
//use secp256k1;
use num_bigint;
use std::error::Error;
//use std::{io, fmt, num};
use std::{fmt, option};
//use sgx_types::sgx_status_t;

#[derive(Debug)]
pub enum AppError {
    //Io(io::Error),
    //Custom(String),
    //SGXError(sgx_status_t),
    HexError(hex::FromHexError),
    //ReqwestError(reqwest::Error),
    //Secp256k1Error(secp256k1::Error),
    NoneError(option::NoneError),
    ParseBigIntError(num_bigint::ParseBigIntError),
}

//#[unstable(feature = "try_trait", issue = "42327")]
impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match *self {
            //AppError::Custom(ref msg) => msg.clone(),
            //AppError::Io(ref e) => format!("I/O error: {}", e),
            //AppError::SGXError(ref e) => format!("SGX error: {}", e),
            AppError::HexError(ref e) => format!("Hex error: {}", e),
            //AppError::ReqwestError(ref e) => format!("Reqwest error: {}", e),
            //AppError::Secp256k1Error(ref e) => format!("Crypto error: {}", e),
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

impl Into<String> for AppError {
    fn into(self) -> String {
        format!("{}", self)
    }
}

impl From<io::Error> for AppError {
    fn from(err: io::Error) -> AppError {
        AppError::Io(err)
    }
}

impl From<sgx_status_t> for AppError {
    fn from(err: sgx_status_t) -> AppError {
        AppError::SGXError(err)
    }
}

impl From<secp256k1::Error> for AppError {
    fn from(e: secp256k1::Error) -> AppError {
        AppError::Secp256k1Error(e)
    }
}

impl From<reqwest::Error> for AppError {
    fn from(e: reqwest::Error) -> AppError {
        AppError::ReqwestError(e)
    }
}
*/
