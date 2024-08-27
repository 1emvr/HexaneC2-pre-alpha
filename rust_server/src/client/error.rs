use derive_more::From;
use core::fmt::Formatter;

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
    fn fmt(&self, fmt: &mut Formatter) -> core::result::Result<(), core::fmt::Error> {
        write!(fmt, "{self:?}")
    }
}

impl std::error::Error for Error {}