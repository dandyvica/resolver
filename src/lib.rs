//! A utility crate to retrieve the DNS resolvers of the underlying OS.
//!
//! On UNIX-like platforms, it merely read the `/etc/resonlv.conf` file.
//!
//! On Windows, it uses the [windows](https://crates.io/crates/windows) crate and calls the dedicated APIs to get the list of DNS resolvers for all interfaces (`GetAdaptersAddresses`).
//! In addition on this platform, the ability to provide a interface index or interface name to all get the resolvers on those.
//!
//! Usage on Unix:
//!
//! ```ignore
//! use resolver::ResolverList;
//!
//! let addresses = ResolverList::new().expect("failed to load DNS addresses");
//! println!("{} addresses found", addresses.len());
//! ```
pub mod error;

use std::{
    net::{IpAddr, SocketAddr},
    ops::{Deref, DerefMut},
    str::FromStr,
};

#[cfg(target_os = "unix")]
use std::path::Path;

use crate::error::Error;

//----------------------------------------------------------------------------------
// Cross-platfrom definitions
//----------------------------------------------------------------------------------
/// Identify a single resolver tied to a network interface optionnally identified by its name and index.
#[derive(Debug, Default, Clone)]
pub struct Resolver {
    // interface name (like "Ethernet 2")
    if_name: Option<String>,

    // interface index (like 12)
    if_index: Option<u32>,

    // list of DNS resolvers for this interface
    ip_list: Vec<IpAddr>,
}

impl Resolver {
    /// Return the network interface name.
    pub fn if_name(&self) -> Option<&str> {
        self.if_name.as_deref()
    }

    /// Return the network interface index.
    pub fn if_index(&self) -> Option<u32> {
        self.if_index
    }

    /// Return the list of resolvers' ip addresses for this interface.
    pub fn ip_list(&self) -> &[IpAddr] {
        self.ip_list.as_slice()
    }

    /// Return the number of ip addresses in the adapter.
    pub fn len(&self) -> usize {
        self.ip_list.len()
    }

    /// True if empty.
    pub fn is_empty(&self) -> bool {
        self.ip_list.is_empty()
    }
}

impl Resolver {
    /// Return true if the ip address is found in the list.
    pub fn contains(&self, ip: &str) -> Result<bool, Error> {
        let ip = IpAddr::from_str(ip)?;

        Ok(self.ip_list.contains(&ip))
    }
}

/// IntoIterator implementation to benefit from already defined iterator on `ip_list`.
impl<'a> IntoIterator for &'a Resolver {
    type Item = &'a IpAddr;
    type IntoIter = std::slice::Iter<'a, IpAddr>;

    fn into_iter(self) -> Self::IntoIter {
        self.ip_list.iter()
    }
}

/// Hold the list of DNS resolvers IP addresses (IPV4 and IPV6), with the associated network interface name and index.
#[derive(Debug, Clone)]
pub struct ResolverList(Vec<Resolver>);

impl ResolverList {
    /// Return true if the ip address is found in the list.
    pub fn contains(&self, ip: &str) -> Result<bool, Error> {
        Ok(self.0.iter().filter_map(|x| x.contains(ip).ok()).any(|x| x))
    }

    /// Convert the list of resolvers to a list of socket addresses.
    pub fn to_socketaddresses(&self, port: u16) -> Vec<SocketAddr> {
        self.iter()
            .fold(Vec::new(), |mut acc, x| {
                acc.extend(&x.ip_list);
                acc
            })
            .iter()
            .map(|x| SocketAddr::new(*x, port))
            .collect()
    }
}

impl Deref for ResolverList {
    /// The resulting type after dereferencing.
    type Target = Vec<Resolver>;

    /// Dereferences the value, giving the vector of DNS ip addresses.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ResolverList {
    /// Dereferences the value, giving the vector of DNS ip addresses.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// IntoIterator implementation to benefit from already defined iterator on `ip_list`.
// impl<'a> IntoIterator for &'a ResolverList {
//     type Item = &'a IpAddr;
//     type IntoIter = std::slice::Iter<'a, IpAddr>;

//     fn into_iter(self) -> Self::IntoIter {
//         let x = self.0.iter().map(|x| x.ip_list.iter());
//         x.into_iter()

//     }
// }

// #[derive(Debug)]
// pub struct IterHelper<'a> {
//     ip_index: usize,
//     resolver_iter: Iter<'a, Resolver>,
//     ipaddr_iter: Option<Iter<'a, IpAddr>>,
// }

// impl<'a> IntoIterator for &'a ResolverList {
//     type Item = &'a IpAddr;
//     type IntoIter = IterHelper<'a>;

//     fn into_iter(self) -> Self::IntoIter {
//         IterHelper {
//             ip_index: 0,
//             resolver_iter: self.0.iter(),
//             ipaddr_iter: None,
//         }
//     }
// }

// impl<'a> Iterator for IterHelper<'a> {
//     type Item = &'a IpAddr;

//     // just return the str reference
//     fn next(&mut self) -> Option<Self::Item> {
//         if let Some(resolver) = self.resolver_iter.next() {
//             // we start the Resolver iteration for the first time
//             if self.ip_index == 0 {
//                 self.ip_index = resolver.len();
//             }

//             //

//         } else {
//             None
//         }
//     }
// }

//----------------------------------------------------------------------------------
// Unix definitions
//----------------------------------------------------------------------------------
#[cfg(target_os = "linux")]
impl ResolverList {
    /// Return the list of IPV4 & IPV6 DNS resolvers by reading the `/etc/resolv.conf` file.
    pub fn new() -> Result<Self, Error> {
        const RESOLV_CONF_FILE: &str = "/etc/resolv.conf";

        let path = Path::new(RESOLV_CONF_FILE);
        ResolverList::try_from(path)
    }
}

#[cfg(target_os = "linux")]
impl TryFrom<&Path> for ResolverList {
    type Error = Error;

    /// TryFrom will be used to build the DNS servers' list from a resolve.conf-like file.
    fn try_from(resolv_file: &Path) -> Result<Self, Self::Error> {
        // read whole file, get rid of comments and extract DNS stubs
        let resolv_conf = std::fs::read_to_string(resolv_file)?;

        let resolvers: Vec<Resolver> = resolv_conf
            .lines()
            // only get lines startgin with "nameserver"
            .filter(|line| line.trim().starts_with("nameserver"))
            // get rid of whitespaces
            .filter_map(|addr| addr.split_ascii_whitespace().nth(1))
            // build a Resolver struct from string matching an ip address
            .map(|s| {
                let mut res = Resolver::default();
                let ip = IpAddr::from_str(s);
                res.ip_list.push(ip.unwrap());

                res
            })
            .collect();

        if resolvers.is_empty() {
            return Err(Error::NoResolverConfigured);
        }

        Ok(Self(resolvers))
    }
}

//----------------------------------------------------------------------------------
// Windows definitions
//----------------------------------------------------------------------------------
#[cfg(target_family = "windows")]
use windows::Win32::{
    Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_INVALID_PARAMETER, ERROR_SUCCESS},
    NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH,
    },
    Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6},
};

#[cfg(target_os = "windows")]
impl ResolverList {
    /// Return the list of IPV4 & IPV6 DNS resolvers for all the network interfaces.
    pub fn new() -> Result<Self, Error> {
        let mut list: Vec<Resolver> = Vec::new();

        // first call
        let family = AF_UNSPEC.0 as u32;
        let mut buflen = 0u32;
        let mut rc = unsafe {
            GetAdaptersAddresses(family, GAA_FLAG_INCLUDE_PREFIX, None, None, &mut buflen)
        };

        // second with the actual buffer size large enough to hold data
        if rc == ERROR_BUFFER_OVERFLOW.0 {
            let mut addr = vec![0u8; buflen as usize];
            let ptr = addr.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

            rc = unsafe {
                GetAdaptersAddresses(
                    family,
                    GAA_FLAG_INCLUDE_PREFIX,
                    None,
                    Some(ptr),
                    &mut buflen,
                )
            };

            // second with the actual buffer size large enough to hold data
            if rc == ERROR_SUCCESS.0 {
                // loop through adapters and grab DNS addresses and other info
                let mut p = ptr;

                while !p.is_null() {
                    unsafe {
                        // get info an network interface
                        let if_name = (*p).FriendlyName.display().to_string();
                        let if_index = (*p).Ipv6IfIndex;

                        // now get all DNS ips for this interface
                        let mut ip_list: Vec<IpAddr> = Vec::new();
                        let mut p_dns = (*p).FirstDnsServerAddress;

                        // loop through DNS addresses for this adapter
                        while !p_dns.is_null() {
                            let sockaddr = (*p_dns).Address.lpSockaddr;
                            let dns_addr = Self::from_sockaddr(sockaddr)?;
                            ip_list.push(dns_addr);

                            p_dns = (*p_dns).Next;
                        }

                        // save resolver into the list
                        let res = Resolver {
                            if_name: Some(if_name),
                            if_index: Some(if_index),
                            ip_list,
                        };

                        list.push(res);

                        p = (*p).Next;
                    }
                }
            } else {
                return Err(Error::Windows(rc));
            }
        } else {
            return Err(Error::Windows(rc));
        }

        Ok(ResolverList(list))
    }

    // utility function which is used to build an IpAddr from an array used in Windows OS
    fn from_sockaddr(sockaddr: *const SOCKADDR) -> Result<IpAddr, Error> {
        use std::net::{Ipv4Addr, Ipv6Addr};

        // this is only valid for INET4 or 6 family
        unsafe {
            match (*sockaddr).sa_family {
                AF_INET => {
                    // ip v4 addresses reported by GetAdaptersAddresses() API are like: [0, 0, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0] (for 8.8.8.8)
                    let sockaddr_in = sockaddr as *const SOCKADDR_IN;
                    let bytes = (*sockaddr_in).sin_addr.S_un.S_un_b;
                    let ip = IpAddr::V4(Ipv4Addr::new(
                        bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4,
                    ));
                    Ok(ip)
                }
                AF_INET6 => {
                    // ip v6 addresses reported by GetAdaptersAddresses() API are like: [0, 0, 0, 0, 0, 0, 254, 192, 0, 0, 0, 0, 255, 255] (for 8.8.8.8)
                    let sockaddr_in = sockaddr as *const SOCKADDR_IN6;
                    let bytes = (*sockaddr_in).sin6_addr.u.Byte;
                    let ip = IpAddr::V6(Ipv6Addr::from(bytes));
                    Ok(ip)
                }
                _ => Err(Error::Windows(ERROR_INVALID_PARAMETER.0)),
            }
        }
    }
}

#[cfg(target_os = "windows")]
impl TryFrom<&str> for Resolver {
    type Error = Error;

    /// Build the DNS servers' list from an interface name.
    fn try_from(if_name: &str) -> Result<Self, Self::Error> {
        let mut list = ResolverList::new()?;
        list.retain(|x| x.if_name.as_ref() == Some(&if_name.to_string()));
        debug_assert!(list.len() <= 1);

        if list.is_empty() {
            return Err(Error::InterfaceNotFound);
        }

        Ok(list[0].clone())
    }
}

#[cfg(target_os = "windows")]
// TryFrom will be used to build the DNS servers' list from an interface index
impl TryFrom<u32> for Resolver {
    type Error = Error;

    /// Build the DNS servers' list from an interface index.
    fn try_from(if_index: u32) -> Result<Self, Self::Error> {
        let mut list = ResolverList::new()?;
        list.0.retain(|x| x.if_index == Some(if_index));
        debug_assert!(list.len() <= 1);

        if list.is_empty() {
            return Err(Error::InterfaceNotFound);
        }

        Ok(list[0].clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver() {
        let v = vec![
            IpAddr::from_str("45.90.28.55").unwrap(),
            IpAddr::from_str("2a07:a8c0::").unwrap(),
            IpAddr::from_str("45.90.30.55").unwrap(),
            IpAddr::from_str("2a07:a8c1::").unwrap(),
        ];

        let r = Resolver {
            if_index: None,
            if_name: None,
            ip_list: v,
        };

        let mut iter = r.into_iter();
        assert_eq!(iter.next(), Some(&IpAddr::from_str("45.90.28.55").unwrap()));
        assert_eq!(iter.next(), Some(&IpAddr::from_str("2a07:a8c0::").unwrap()));
        assert_eq!(iter.next(), Some(&IpAddr::from_str("45.90.30.55").unwrap()));
        assert_eq!(iter.next(), Some(&IpAddr::from_str("2a07:a8c1::").unwrap()));
    }

    // #[test]
    // fn iter() {
    //     let v1 = vec![
    //         IpAddr::from_str("45.90.28.55").unwrap(),
    //         IpAddr::from_str("2a07:a8c0::").unwrap(),
    //     ];

    //     let v2 = vec![
    //         IpAddr::from_str("8.8.8.8").unwrap(),
    //         IpAddr::from_str("1.1.1.1").unwrap(),
    //     ];

    //     let v3 = vec![IpAddr::from_str("127.0.0.53").unwrap()];

    //     let r1 = Resolver {
    //         if_index: None,
    //         if_name: None,
    //         ip_list: v1,
    //     };

    //     let r2 = Resolver {
    //         if_index: None,
    //         if_name: None,
    //         ip_list: v2,
    //     };

    //     let r3 = Resolver {
    //         if_index: None,
    //         if_name: None,
    //         ip_list: v3,
    //     };

    //     let list = ResolverList(vec![r1, r2, r3]);

    //     let mut iter = list.into_iter();
    //     assert_eq!(iter.next(), Some(&IpAddr::from_str("45.90.28.55").unwrap()));
    //     assert_eq!(iter.next(), Some(&IpAddr::from_str("2a07:a8c0::").unwrap()));
    //     assert_eq!(iter.next(), Some(&IpAddr::from_str("8.8.8.8").unwrap()));
    //     assert_eq!(iter.next(), Some(&IpAddr::from_str("1.1.1.1").unwrap()));
    //     assert_eq!(iter.next(), Some(&IpAddr::from_str("127.0.0.53").unwrap()));
    //     assert!(iter.next().is_none());
    // }

    #[cfg(target_os = "linux")]
    #[test]
    fn unix() {
        let list = ResolverList::try_from(Path::new("./tests/resolv.conf"));
        assert!(list.is_ok());

        let list = list.unwrap();
        assert_eq!(list.len(), 4);

        assert!(list.contains("45.90.28.55").unwrap());
        assert!(list.contains("45.90.30.55").unwrap());
        assert!(list.contains("2a07:a8c0::").unwrap());
        assert!(list.contains("2a07:a8c1::").unwrap());
        assert!(list.contains("2a07:a8c1::").unwrap());
        assert!(!list.contains("1.1.1.1").unwrap());

        // let mut iter = list.into_iter();
        // assert_eq!(iter.next(), Some(&IpAddr::from_str("45.90.28.55").unwrap()));
        // assert_eq!(iter.next(), Some(&IpAddr::from_str("2a07:a8c0::").unwrap()));
        // assert_eq!(iter.next(), Some(&IpAddr::from_str("45.90.30.55").unwrap()));
        // assert_eq!(iter.next(), Some(&IpAddr::from_str("2a07:a8c1::").unwrap()));
        // assert!(iter.next().is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows() {
        let list = ResolverList::new();
        assert!(list.is_ok());

        let list = list.unwrap();
        assert_eq!(list.len(), 4);

        assert!(list.contains("192.168.122.1").unwrap());
        assert!(list.contains("8.8.8.8").unwrap());
        assert!(list.contains("1.1.1.1").unwrap());
        assert!(list.contains("fec0:0:0:ffff::1").unwrap());
        assert!(list.contains("fec0:0:0:ffff::2").unwrap());
        assert!(list.contains("fec0:0:0:ffff::3").unwrap());
        assert!(!list.contains("9.9.9.9").unwrap());


        let res = Resolver::try_from(2).unwrap();
        assert_eq!(res.len(), 2);

        let res = Resolver::try_from("Ethernet 2").unwrap();
        assert_eq!(res.len(), 2);

        let res = Resolver::try_from(u32::MAX).unwrap_err();
        assert!(matches!(res, Error::InterfaceNotFound));

        let res = Resolver::try_from("XXXXXX").unwrap_err();
        assert!(matches!(res, Error::InterfaceNotFound));
    }    
}
