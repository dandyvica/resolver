//! Windows-specific implementation.
use std::{
    net::IpAddr,
    ops::{Deref, DerefMut},
};

#[cfg(target_family = "windows")]
use windows::Win32::{
    Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_INVALID_PARAMETER, ERROR_SUCCESS},
    NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH,
    },
    Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6},
};

use crate::error::Error;

/// Identify a single resolver tied to a network interface identified by its name and index.
#[derive(Debug, Clone)]
pub struct Resolver {
    // interface name (like "Ethernet 2")
    if_name: String,

    // interface index (like 12)
    if_index: u32,

    // list of DNS resolvers for this interface
    ip_list: Vec<IpAddr>,
}

impl Resolver {
    /// Return the network interface name.
    pub fn if_name(&self) -> &str {
        self.if_name.as_str()
    }

    /// Return the network interface index.
    pub fn if_index(&self) -> u32 {
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
}

/// Hold the list of DNS resolvers IP addresses (IPV4 and IPV6), with the associated network interface name and index.
#[derive(Debug, Clone)]
pub struct ResolverList(Vec<Resolver>);

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
                            if_name,
                            if_index,
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

impl TryFrom<&str> for Resolver {
    type Error = Error;

    /// Build the DNS servers' list from an interface name.
    fn try_from(if_name: &str) -> Result<Self, Self::Error> {
        let mut list = ResolverList::new()?;
        list.retain(|x| x.if_name.as_str() == if_name);
        debug_assert!(list.len() <= 1);

        if list.is_empty() {
            return Err(Error::InterfaceNotFound);
        }

        Ok(list[0].clone())
    }
}

// TryFrom will be used to build the DNS servers' list from an interface index
impl TryFrom<u32> for Resolver {
    type Error = Error;

    /// Build the DNS servers' list from an interface index.
    fn try_from(if_index: u32) -> Result<Self, Self::Error> {
        let mut list = ResolverList::new()?;
        list.0.retain(|x| x.if_index == if_index);
        debug_assert!(list.len() <= 1);

        if list.is_empty() {
            return Err(Error::InterfaceNotFound);
        }

        Ok(list[0].clone())
    }
}

// IntoIterator to benefit from already defined iterator on Vec
// impl<'a> IntoIterator for &'a ResolverList {
//     type Item = &'a IpAddr;
//     type IntoIter = std::slice::Iter<'a, IpAddr>;

//     /// Create an iterator to loop on DNS resolvers ip addresses.
//     fn into_iter(self) -> Self::IntoIter {
//         self.0.iter().flatten().next()
//     }
// }

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_windows() {
        let list = ResolverList::new();
        assert!(list.is_ok());

        let list = list.unwrap();
        assert_eq!(list.len(), 4);

        // let ips = list.to_ip_vec();

        // assert!(ips.contains(&IpAddr::from_str("192.168.122.1").unwrap()));
        // assert!(ips.contains(&IpAddr::from_str("8.8.8.8").unwrap()));
        // assert!(ips.contains(&IpAddr::from_str("1.1.1.1").unwrap()));
        // assert!(ips.contains(&IpAddr::from_str("fec0:0:0:ffff::1").unwrap()));
        // assert!(ips.contains(&IpAddr::from_str("fec0:0:0:ffff::2").unwrap()));
        // assert!(ips.contains(&IpAddr::from_str("fec0:0:0:ffff::3").unwrap()));

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
