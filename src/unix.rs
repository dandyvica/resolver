use crate::error::Error;
use std::net::IpAddr;

use std::str::FromStr;

impl Resolvers {
    /// Return IPV4 & IPV6 DNS resolvers on the machine.
    pub fn get_servers(conf: Option<&str>) -> Result<Self, Error> {
        const RESOLV_CONF_FILE: &str = "/etc/resolv.conf";

        // resolv file is usually at "/etc/resolv.conf" but some distros (Ubuntu) moved it elsewhere
        let resolv_file = conf.unwrap_or(RESOLV_CONF_FILE);

        // read whole file, get rid of comments and extract DNS stubs
        let resolv_conf = std::fs::read_to_string(resolv_file)?;

        let servers: Vec<IpAddr> = resolv_conf
            .lines()
            .filter(|line| line.trim().starts_with("nameserver"))
            .filter_map(|addr| addr.split_ascii_whitespace().nth(1))
            .map(IpAddr::from_str)
            .collect::<Result<Vec<_>, _>>()?;

        if servers.is_empty() {
            return Err(Error::NoResolverConfigured);
        }

        let v4: Vec<IpAddr> = servers.iter().filter(|x| x.is_ipv4()).cloned().collect();
        let v6: Vec<IpAddr> = servers.iter().filter(|x| x.is_ipv6()).cloned().collect();

        Ok(Self { v4, v6 })
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use std::net::IpAddr;
    use std::str::FromStr;

    use crate::resolver::Resolvers;

    #[test]
    fn test_unix() {
        let s1 = Resolvers::get_servers(Some("./tests/resolv.conf"));
        assert!(s1.is_ok());

        let s2 = s1.unwrap();
        assert_eq!(s2.v4.len(), 2);
        assert_eq!(s2.v6.len(), 2);

        assert!(s2.v4.contains(&IpAddr::from_str("45.90.28.55").unwrap()));
        assert!(s2.v4.contains(&IpAddr::from_str("45.90.30.55").unwrap()));
        assert!(s2.v6.contains(&IpAddr::from_str("2a07:a8c0::").unwrap()));
        assert!(s2.v6.contains(&IpAddr::from_str("2a07:a8c1::").unwrap()));
    }
}
