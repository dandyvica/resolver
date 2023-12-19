//! Definitions for the UNIX platform.
use std::convert::AsRef;
use std::net::IpAddr;
use std::ops::Deref;
use std::path::Path;
use std::str::FromStr;

use crate::error::Error;

/// Hold the list of DNS resolvers IP addresses (IPV4 and IPV6).
#[derive(Debug, Clone)]
pub struct ResolverList(Vec<IpAddr>);

impl ResolverList {
    /// Return the list of IPV4 & IPV6 DNS resolvers by reading the `/etc/resolv.conf` file.
    pub fn new() -> Result<Self, Error> {
        const RESOLV_CONF_FILE: &str = "/etc/resolv.conf";

        let path = Path::new(RESOLV_CONF_FILE);
        ResolverList::try_from(path)
    }
}

impl Deref for ResolverList {
    /// The resulting type after dereferencing.
    type Target = Vec<IpAddr>;

    /// Dereferences the value, giving the vector of DNS ip addresses.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[IpAddr]> for ResolverList {
    /// Converts this type into a slice of ip addresses.
    fn as_ref(&self) -> &[IpAddr] {
        &self.0
    }
}

impl TryFrom<&Path> for ResolverList {
    type Error = Error;

    /// TryFrom will be used to build the DNS servers' list from a resolve.conf-like file.
    fn try_from(resolv_file: &Path) -> Result<Self, Self::Error> {
        // read whole file, get rid of comments and extract DNS stubs
        let resolv_conf = std::fs::read_to_string(resolv_file)?;

        let resolvers: Vec<IpAddr> = resolv_conf
            .lines()
            .filter(|line| line.trim().starts_with("nameserver"))
            .filter_map(|addr| addr.split_ascii_whitespace().nth(1))
            .map(IpAddr::from_str)
            .collect::<Result<Vec<_>, _>>()?;

        if resolvers.is_empty() {
            return Err(Error::NoResolverConfigured);
        }

        Ok(Self(resolvers))
    }
}

// IntoIterator to benefit from already defined iterator on Vec
impl<'a> IntoIterator for &'a ResolverList {
    type Item = &'a IpAddr;
    type IntoIter = std::slice::Iter<'a, IpAddr>;

    /// Create an iterator to loop on DNS resolvers ip addresses.
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use std::net::IpAddr;
    use std::str::FromStr;

    use super::*;

    #[test]
    fn unix() {
        let list = ResolverList::try_from(Path::new("./tests/resolv.conf"));
        assert!(list.is_ok());

        let list = list.unwrap();
        assert_eq!(list.len(), 4);

        assert!(list.contains(&IpAddr::from_str("45.90.28.55").unwrap()));
        assert!(list.contains(&IpAddr::from_str("45.90.30.55").unwrap()));
        assert!(list.contains(&IpAddr::from_str("2a07:a8c0::").unwrap()));
        assert!(list.contains(&IpAddr::from_str("2a07:a8c1::").unwrap()));

        let mut iter = list.into_iter();
        assert_eq!(iter.next(), Some(&IpAddr::from_str("45.90.28.55").unwrap()));
        assert_eq!(iter.next(), Some(&IpAddr::from_str("2a07:a8c0::").unwrap()));
        assert_eq!(iter.next(), Some(&IpAddr::from_str("45.90.30.55").unwrap()));
        assert_eq!(iter.next(), Some(&IpAddr::from_str("2a07:a8c1::").unwrap()));
        assert!(iter.next().is_none());
    }
}
