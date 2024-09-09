use core::fmt;
use std::num::ParseIntError;
use std::error::Error as StdError;

use serde::de::{Deserialize, Deserializer};
use derive_more::From;

#[macro_export]
macro_rules! return_error {
    ($($arg:tt)*) => {
        return Err(Error::Custom(format!($($arg)*)))
    };
}

#[macro_export]
macro_rules! invalid_input {
    ($arg:expr) => {
        wrap_message("error", format!("invalid input: {}", $arg))
    };
}

#[macro_export]
macro_rules! length_check_continue {
    ($arg:expr, $len:expr) => {
        if $arg.len() < $len {
            wrap_message("error", format!("invalid arguments: {}", $len));
            continue;
        }
    };
}

#[macro_export]
macro_rules! length_check_defer {
    ($arg:expr, $len:expr) => {
        if $arg.len() < $len {
            return_error!("invalid arguments: {}", $len)
        }
    };
}

#[macro_export]
macro_rules! map_error {
    ($expr:expr, $msg:expr) => {
        $expr.map_err(|e| Error::Custom(format!("{}: {}", $msg, e)))?
    };
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, From)]
pub enum Error {
    #[from] Io(std::io::Error),
    #[from] ParseInt(ParseIntError),
    #[from] SerdeJson(serde_json::error::Error),
    #[from] KeySize(KeySizeError),
    #[from] PeLite(pelite::Error),
    #[from] Custom(String),
}

impl Error {
    pub fn custom(val: impl fmt::Display) -> Self {
        Self::Custom(val.to_string())
    }
}

impl From<&str> for Error {
    fn from(val: &str) -> Self {
        Self::custom(val.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> core::result::Result<(), fmt::Error> {
        write!(fmt, "{self:?}")
    }
}

impl From<&[u8]> for Error {
    fn from(slice: &[u8]) -> Self {
        match std::str::from_utf8(slice) {
            Ok(s)   => Error::Custom(s.to_string()),
            Err(_)  => Error::Custom(format!("invalid UTF-8 sequence: {:?}", slice)),
        }
    }
}

impl From<Box<dyn StdError>> for Error {
    fn from(error: Box<dyn std::error::Error>) -> Self {
        Error::Custom(error.to_string())
    }
}

#[derive(Debug)]
pub struct KeySizeError(pub usize);

impl StdError for KeySizeError {}

impl fmt::Display for KeySizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid key size: {}", self.0)
    }
}

impl<'de> Deserialize<'de> for Error {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where D: Deserializer<'de>,
    {
        let msg = String::deserialize(deserializer)?;
        Ok(Error::custom(msg))
    }
}

