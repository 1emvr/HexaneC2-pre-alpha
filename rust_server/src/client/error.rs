use serde::de::{self, Deserialize, Deserializer};
use derive_more::From;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, From)]
pub enum Error {
    #[from]
    Custom(String),

    #[from]
    Io(std::io::Error),

    #[from]
    SerdeJson(serde_json::Error),
}

impl Error {
    pub fn custom(val: impl std::fmt::Display) -> Self { Self::custom(val.to_string()) }
}

impl From<&str> for Error {
    fn from(val: &str) -> Self { Self::custom(val.to_string()) }
}

impl core::fmt::Display for Error {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::result::Result<(), core::fmt::Error> {
        write!(fmt, "{self:?}")
    }
}

impl<'de> Deserialize<'de> for Error {
    fn deserialize<Dsr>(ds: Dsr) -> core::result::Result<Self, Dsr::Error> where Dsr: Deserializer<'de>, {
        let json_err: core::result::Result<serde_json::Error, Dsr::Error> = Deserialize::deserialize(ds);

        match json_err {
            Ok(err) => Ok(Error::SerdeJson(err)),
            Err(_) => Err(de::Error::custom("failed to deserialize into error"))

        }
    }
}

impl std::error::Error for Error {}