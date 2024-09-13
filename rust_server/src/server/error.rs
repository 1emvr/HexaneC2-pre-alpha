use std::io;
use core::fmt;
use derive_more::From;
use serde::de::{Deserialize, Deserializer};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub struct KeySizeError(pub usize);
impl std::error::Error for KeySizeError {}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    ParseInt(std::num::ParseIntError),
    SerdeJson(serde_json::error::Error),
    PeLite(pelite::Error),
    KeySize(KeySizeError),
    Custom(String),
}


impl Error {
    pub fn Custom(val: impl fmt::Display) -> Self {
        Self::Custom(val.to_string())
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<&str> for Error {
    fn from(val: &str) -> Self {
        Self::Custom(val.to_string())
    }
}

impl From<Box<dyn std::error::Error>> for Error {
    fn from(error: Box<dyn std::error::Error>) -> Self {
        Error::Custom(error.to_string())
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

impl From<std::num::ParseIntError> for Error {
    fn from(err: std::num::ParseIntError) -> Self {
        Error::Custom(format!("int error: {}", err))
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::SerdeJson(err)
    }
}


impl<T> From<std::sync::PoisonError<T>> for Error {
    fn from(_: std::sync::PoisonError<T>) -> Self {
        Error::Custom("mutex lock poisoned".to_string())
    }
}

impl From<pelite::Error> for Error {
    fn from(err: pelite::Error) -> Self {
        Error::Custom(format!("PE file parsing error: {}", err))
    }
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Error::Custom(err)
    }
}



impl fmt::Display for KeySizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid key size: {}", self.0)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> core::result::Result<(), fmt::Error> {
        write!(fmt, "{self:?}")
    }
}


impl<'de> Deserialize<'de> for Error {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where D: Deserializer<'de>,
    {
        let msg = String::deserialize(deserializer)?;
        Ok(Error::Custom(msg))
    }
}



#[macro_export]
macro_rules! return_error {
    ($msg:expr) => {
        return Err(crate::server::error::Error::Custom($msg.to_string()))
    };
}

#[macro_export]
macro_rules! assert_bool {
    ($condition:expr, $msg:expr) => {
        if !$condition {
            return Err(crate::server::error::Error::Custom($msg.to_string()))
        }
    };
}

#[macro_export]
macro_rules! assert_result {
    ($result:expr, $msg:expr) => {
        $result.map_err(|e| crate::server::error::Error::Custom(format!("{}: {}", $msg, e)))?
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
            Err(Error::Custom("invalid arguments: {}", $len))
        }
    };
}


