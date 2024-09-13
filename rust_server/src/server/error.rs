use std::io;
use std::fmt;
use derive_more::From;
use serde::de::{Deserialize, Deserializer};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub struct KeySizeError(pub usize);

impl std::error::Error for KeySizeError {}

impl fmt::Display for KeySizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid key size: {}", self.0)
    }
}

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
    pub fn custom(val: impl fmt::Display) -> Self {
        Self::Custom(val.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e)        => write!(f, "IO: {}", e),
            Error::ParseInt(e)  => write!(f, "INT: {}", e),
            Error::SerdeJson(e) => write!(f, "JSON: {}", e),
            Error::PeLite(e)    => write!(f, "PE: {}", e),
            Error::KeySize(e)   => write!(f, "{}", e),
            Error::Custom(msg)  => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e)        => Some(e),
            Error::ParseInt(e)  => Some(e),
            Error::SerdeJson(e) => Some(e),
            Error::PeLite(e)    => Some(e),
            Error::KeySize(e)   => Some(e),
            Error::Custom(_)    => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(err: std::num::ParseIntError) -> Self {
        Error::ParseInt(err)
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(err: serde_json::error::Error) -> Self {
        Error::SerdeJson(err)
    }
}

impl From<pelite::Error> for Error {
    fn from(err: pelite::Error) -> Self {
        Error::PeLite(err)
    }
}

impl From<KeySizeError> for Error {
    fn from(err: KeySizeError) -> Self {
        Error::KeySize(err)
    }
}

impl From<&str> for Error {
    fn from(val: &str) -> Self {
        Self::Custom(val.to_string())
    }
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Error::Custom(err)
    }
}

impl From<&[u8]> for Error {
    fn from(slice: &[u8]) -> Self {
        match std::str::from_utf8(slice) {
            Ok(s) => Error::Custom(s.to_string()),
            Err(_) => Error::Custom(format!("invalid UTF-8 sequence: {:?}", slice)),
        }
    }
}

impl<T> From<std::sync::PoisonError<T>> for Error {
    fn from(_: std::sync::PoisonError<T>) -> Self {
        Error::Custom("mutex lock poisoned".to_string())
    }
}

impl<'de> Deserialize<'de> for Error {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let msg = String::deserialize(deserializer)?;
        Ok(Error::Custom(msg))
    }
}

#[macro_export]
macro_rules! invalid_input {
    ($arg:expr) => {
        log_error!("invalid input: {}", $arg)
    };
}

#[macro_export]
macro_rules! log_error {
    ($msg:expr) => {
        wrap_message("error", $msg);
    };
    ($fmt:expr, $($arg:tt)*) => {
        wrap_message("error", &format!($fmt, $($arg)*));
    };
}

#[macro_export]
macro_rules! log_info {
    ($msg:expr) => {
        wrap_message("info", $msg);
    };
    ($fmt:expr, $($arg:tt)*) => {
        wrap_message("info", &format!($fmt, $($arg)*));
    };
}

#[macro_export]
macro_rules! log_debug {
    ($msg:expr) => {
        wrap_message("debug", $msg);
    };
    ($fmt:expr, $($arg:tt)*) => {
        wrap_message("debug", &format!($fmt, $($arg)*));
    };
}
