pub mod error;
pub mod resolver;

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use std::net::IpAddr;
    use std::str::FromStr;

    use crate::resolver::Resolvers;

    #[test]
    #[cfg(target_family = "unix")]
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

    #[test]
    #[cfg(target_family = "windows")]
    fn test_windows() {
        let s1 = Resolvers::get_servers(None);
        assert!(s1.is_ok());

        println!("{:?}", s1);
        let s2 = s1.unwrap();
        assert_eq!(s2.v4.len(), 4);
        assert_eq!(s2.v6.len(), 3);

        assert!(s2.v4.contains(&IpAddr::from_str("192.168.122.1").unwrap()));
        assert!(s2.v4.contains(&IpAddr::from_str("8.8.8.8").unwrap()));
        assert!(s2.v4.contains(&IpAddr::from_str("1.1.1.1").unwrap()));
        assert!(s2.v6.contains(&IpAddr::from_str("fec0:0:0:ffff::1").unwrap()));        
        assert!(s2.v6.contains(&IpAddr::from_str("fec0:0:0:ffff::2").unwrap()));        
        assert!(s2.v6.contains(&IpAddr::from_str("fec0:0:0:ffff::3").unwrap()));        
    }
}
