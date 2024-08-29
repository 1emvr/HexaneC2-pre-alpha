use std::num::ParseIntError;
use serde::de::{Deserialize, Deserializer, Error as DeError};
use derive_more::From;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, From)]
pub enum Error {
    #[from]
    Custom(String),

    #[from]
    Io(std::io::Error),

    #[from]
    ParseInt(ParseIntError),

    #[from]
    SerdeJson(serde_json::error::Error),

    #[from]
    KeySize(KeySizeError),
}

#[macro_export]
macro_rules! return_error {
    ($($arg:tt)*) => {
        return Err(Error::Custom(format!($($arg)*)))
    };
}

#[macro_export]
macro_rules! invalid_input {
    ($arg:expr) => { wrap_message("error", format!("invalid input: {}", $arg)); };
}

#[derive(Debug)]
pub struct KeySizeError(pub usize);

impl std::error::Error for KeySizeError {}
impl std::fmt::Display for KeySizeError {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        write!(fmt, "invalid key size: {}", self.0)
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

impl core::fmt::Display for Error {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        write!(fmt, "{self:?}")
    }
}

impl Error {
    pub fn custom(val: impl std::fmt::Display) -> Self {
        Self::Custom(val.to_string())
    }
}

impl From<&str> for Error {
    fn from(val: &str) -> Self {
        Self::custom(val.to_string())
    }
}

impl From<KeySizeError> for Error {
    fn from(err: KeySizeError) -> Self {
        Error::KeySize(err)
    }
}
