//! The error module.
use std::{io, net::AddrParseError};

#[derive(Debug)]
pub enum Error {
    /// On UNIX, the error returned when the file containing the name servers is not readable.
    Io(io::Error),

    /// IP address parsing error.
    AddrParseError(AddrParseError),

    /// When no resolver is found (shouldn't occur but left when using a dedicated resolver file on UNIX).
    NoResolverConfigured,

    /// Windows API return code from `GetAdaptersAddresses`.
    #[cfg(any(windows, doc))]
    Windows(u32),

    /// Returned on Windows when the provided interface (either by index or by name) is not found.
    #[cfg(any(windows, doc))]
    InterfaceNotFound,
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
