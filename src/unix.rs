use crate::error::Error;
use std::net::IpAddr;

use std::path::Path;
use std::str::FromStr;

use crate::ResolverList;

impl ResolverList {
    pub fn len(&self) -> usize {
        self.resolvers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.resolvers.is_empty()
    } 

    // get the list of all resolvers
    pub fn to_ip_vec(&self) -> &[IpAddr] {
        &self.resolvers
    }       
}

impl ResolverList {
    /// Return IPV4 & IPV6 DNS resolvers on the machine.
    pub fn get() -> Result<Self, Error> {
        const RESOLV_CONF_FILE: &str = "/etc/resolv.conf";

        let path = Path::new(RESOLV_CONF_FILE);
        ResolverList::try_from(path)
    }
}

// TryFrom will be used to build the DNS servers' list from a resolve.conf-like file
impl TryFrom<&Path> for ResolverList {
    type Error = Error;

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

        Ok(Self { resolvers })
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use std::net::IpAddr;
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_unix() {
        let list = ResolverList::try_from(Path::new("./tests/resolv.conf"));
        assert!(list.is_ok());

        let list = list.unwrap();
        assert_eq!(list.len(), 4);

        assert!(list.resolvers.contains(&IpAddr::from_str("45.90.28.55").unwrap()));
        assert!(list.resolvers.contains(&IpAddr::from_str("45.90.30.55").unwrap()));
        assert!(list.resolvers.contains(&IpAddr::from_str("2a07:a8c0::").unwrap()));
        assert!(list.resolvers.contains(&IpAddr::from_str("2a07:a8c1::").unwrap()));
    }
}
