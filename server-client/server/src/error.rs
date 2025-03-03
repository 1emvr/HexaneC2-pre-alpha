use std::io;
use std::fmt;

use derive_more::From;
use serde::de::{Deserialize, Deserializer};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Warp(warp::Error),
    ParseInt(std::num::ParseIntError),
    SerdeJson(serde_json::error::Error),
    Tungstenite(tungstenite::Error),
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
            Error::Io(e)           => write!(f, "IO: {}", e),
            Error::ParseInt(e)     => write!(f, "INT: {}", e),
            Error::SerdeJson(e)    => write!(f, "JSON: {}", e),
            Error::KeySize(e)      => write!(f, "KEY: {}", e),
            Error::Tungstenite(e)  => write!(f, "TUNG: {}", e),
            Error::Warp(e)         => write!(f, "WARP: {}", e),
            Error::Custom(e)       => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e)           => Some(e),
            Error::ParseInt(e)     => Some(e),
            Error::SerdeJson(e)    => Some(e),
            Error::KeySize(e)      => Some(e),
            Error::Tungstenite(e)  => Some(e),
            Error::Warp(e)         => Some(e),
            Error::Custom(_)       => None,
        }
    }
}


#[derive(Debug)]
pub struct KeySizeError(pub usize);
impl std::error::Error for KeySizeError {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<warp::Error> for Error {
    fn from(err: warp::Error) -> Self {
        Error::Warp(err)
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

impl fmt::Display for KeySizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid key size: {}", self.0)
    }
}

