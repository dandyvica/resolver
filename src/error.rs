use std::{net::AddrParseError, io};

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    AddrParseError(AddrParseError),
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
