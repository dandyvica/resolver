pub mod error;
pub mod resolver;



#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    use crate::resolver::Resolver;    

    #[test]
    #[cfg(target_family = "unix")]
    fn test_unix() {
        let s1 = Resolver::get_servers(Some("./tests/resolv.conf"));
        assert!(s1.is_ok());

        let s2 = s1.unwrap();
        assert_eq!(s2.servers.len(), 4);

        assert!(s2.servers.contains(&IpAddr::from_str("45.90.28.55").unwrap()));
        assert!(s2.servers.contains(&IpAddr::from_str("45.90.30.55").unwrap()));
        assert!(s2.servers.contains(&IpAddr::from_str("2a07:a8c0::").unwrap()));
        assert!(s2.servers.contains(&IpAddr::from_str("2a07:a8c1::").unwrap()));

        let s1 = Resolver::get_ipv4_servers(Some("./tests/resolv.conf"));
        assert_eq!(s1.unwrap().servers.len(), 2);

        let s1 = Resolver::get_ipv6_servers(Some("./tests/resolv.conf"));
        assert_eq!(s1.unwrap().servers.len(), 2);
    }


}
