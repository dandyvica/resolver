use std::{io, net::AddrParseError};

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    AddrParseError(AddrParseError),
    #[cfg(target_family = "windows")]
    Windows(u32),
}

// All convertion for internal errors for DNSError
impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<AddrParseError> for Error {
    fn from(err: AddrParseError) -> Self {
        Error::AddrParseError(err)
    }
}
