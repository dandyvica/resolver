//! A utility crate to retrieve the DNS resolvers of the underlying hot OS.
//!
//! On UNIX-like platforms, it merely read the `/etc/resolv.conf` file.
//!
//! On Windows, it uses the [windows](https://crates.io/crates/windows) crate and calls the dedicated APIs to get the list of
//! DNS resolvers for all interfaces (`GetAdaptersAddresses`).
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
use std::{
    io,
    net::{AddrParseError, IpAddr, SocketAddr},
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    str::FromStr,
};

use thiserror::Error;

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

/// All possible errors when getting information on host resolvers.
#[derive(Error, Debug)]
pub enum Error {
    /// I/O error when reading DNS configuration files like `/etc/resolv.conf`.
    #[error("cannot open resolver file '{1}' ({0})")]
    OpenFile(#[source] io::Error, PathBuf),

    /// IP address parsing error when converting a string to an IP address.
    #[error("unable to parse IP '{0}'")]
    IPParse(#[source] AddrParseError, String),

    /// When no resolver is found (shouldn't occur but left when using a dedicated resolver file on UNIX).
    #[error("no configured resolver")]
    NoConfiguredResolver,

    /// Windows API return code from [GetAdaptersAddresses()](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses).
    #[cfg(any(windows, doc))]
    #[error("Windows error {0}")]
    Windows(u32),

    /// Returned on Windows when the provided interface (either by index or by name) is not found.
    #[cfg(any(windows, doc))]
    #[error("no network interface found")]
    NoNetworkInterface,
}

/// Identify a single DNS stub resolver configured in the host OS.
///
/// On Windows platforms, it's associated to a network interface and identified by its name
/// and its index.
///
/// On UNIX platforms, it's generally configured regardless of the network interfaces and the interface
/// name and index are not available.
#[derive(Debug, Clone)]
pub struct Resolver {
    // resolver ip address
    ip_addr: IpAddr,

    // interface name (like "Ethernet 2" or "eth1")
    if_name: Option<String>,

    // interface index (like 12)
    if_index: Option<u32>,
}

impl Resolver {
    /// Returns a reference on the resolver's ip address
    #[inline(always)]
    pub fn ip_addr(&self) -> &IpAddr {
        &self.ip_addr
    }

    /// Returns the network interface name associated to this resolver if any.
    #[inline(always)]
    pub fn if_name(&self) -> Option<&str> {
        self.if_name.as_deref()
    }

    /// Returns the network interface index associated to this resolver if any.
    #[inline(always)]
    pub fn if_index(&self) -> Option<u32> {
        self.if_index
    }
}

/// Holds the list of system-wide DNS resolvers' IP addresses (IPV4 and/or IPV6), with the associated network interface name and index if
/// available.
#[derive(Debug, Clone)]
pub struct ResolverList(Vec<Resolver>);

impl ResolverList {
    /// `UNIX only`: returns the list of IPV4 & IPV6 DNS resolvers by reading the `/etc/resolv.conf` file.
    #[cfg(any(unix, doc))]
    pub fn new() -> Result<Self, Error> {
        const RESOLV_CONF_FILE: &str = "/etc/resolv.conf";

        let path = Path::new(RESOLV_CONF_FILE);
        ResolverList::try_from(path)
    }

    #[cfg(any(windows, doc))]
    /// `Windows only`: returns the list of IPV4 & IPV6 DNS resolvers for all the network interfaces by querying
    /// the `GetAdaptersAddresses()` API.
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
                        let mut p_dns = (*p).FirstDnsServerAddress;

                        // loop through DNS addresses for this adapter
                        while !p_dns.is_null() {
                            let sockaddr = (*p_dns).Address.lpSockaddr;
                            let dns_addr = Self::from_sockaddr(sockaddr)?;

                            // create new resolver
                            let res = Resolver {
                                ip_addr: dns_addr,
                                if_name: Some(if_name.clone()),
                                if_index: Some(if_index),
                            };
                            list.push(res);

                            p_dns = (*p_dns).Next;
                        }

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
    #[cfg(target_family = "windows")]
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

    /// Returns `true` if the ip address is found in `self`.
    pub fn contains<T>(&self, ip: T) -> bool
    where
        T: Into<IpAddr>,
        IpAddr: PartialEq<T>,
    {
        self.0.iter().map(|x| x.ip_addr == ip).any(|x| x)
    }

    /// Convert `self` to a vector of `SocketAddr`.
    pub fn to_socketaddr(&self, port: u16) -> Vec<SocketAddr> {
        self.iter()
            .map(|x| SocketAddr::new(x.ip_addr, port))
            .collect()
    }

    /// Convert `self` to a vector of `IpAddr`.
    pub fn to_ip_vec(&self) -> Vec<IpAddr> {
        self.iter().map(|x| x.ip_addr).collect()
    }
}

impl TryFrom<&Path> for ResolverList {
    type Error = Error;

    /// TryFrom will be used to build the DNS servers' list from a resolve.conf-like file.
    fn try_from(resolv_file: &Path) -> Result<Self, Self::Error> {
        // read whole file, get rid of comments and extract DNS stubs
        let resolv_conf = std::fs::read_to_string(resolv_file)
            .map_err(|e| Error::OpenFile(e, resolv_file.to_path_buf()))?;

        let resolvers: Vec<Resolver> = resolv_conf
            .lines()
            // only get lines starting with "nameserver"
            .filter(|line| line.trim().starts_with("nameserver"))
            // get rid of whitespaces
            .filter_map(|addr| addr.split_ascii_whitespace().nth(1))
            // convert to IpAddr
            .filter_map(|s| IpAddr::from_str(s).ok())
            // collect Resolv structs
            .map(|ip| Resolver {
                ip_addr: ip,
                if_name: None,
                if_index: None,
            })
            .collect();

        if resolvers.is_empty() {
            return Err(Error::NoConfiguredResolver);
        }

        Ok(Self(resolvers))
    }
}

impl Deref for ResolverList {
    /// The resulting type after dereferencing.
    type Target = Vec<Resolver>;

    /// Dereferences the value, giving the vector of `Resolver` structs.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ResolverList {
    /// Dereferences the value, giving the mutable vector of `Resolver` structs.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(target_family = "windows")]
impl TryFrom<&str> for Resolver {
    type Error = Error;

    /// Build the DNS servers' list from an interface name.
    fn try_from(if_name: &str) -> Result<Self, Self::Error> {
        let mut list = ResolverList::new()?;
        list.retain(|x| x.if_name.as_ref() == Some(&if_name.to_string()));

        if list.is_empty() {
            return Err(Error::NoNetworkInterface);
        }

        Ok(list[0].clone())
    }
}

#[cfg(target_family = "windows")]
// TryFrom will be used to build the DNS servers' list from an interface index
impl TryFrom<u32> for Resolver {
    type Error = Error;

    /// Build the DNS servers' list from an interface index.
    fn try_from(if_index: u32) -> Result<Self, Self::Error> {
        let mut list = ResolverList::new()?;
        list.0.retain(|x| x.if_index == Some(if_index));

        if list.is_empty() {
            return Err(Error::NoNetworkInterface);
        }

        Ok(list[0].clone())
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn from_file() {
        let list = ResolverList::try_from(Path::new("./tests/resolv.conf"));
        assert!(list.is_ok());

        let list = list.unwrap();
        assert_eq!(list.len(), 4);

        assert!(list.contains(IpAddr::from_str("45.90.28.55").unwrap()));
        assert!(list.contains(IpAddr::from_str("45.90.30.55").unwrap()));
        assert!(list.contains(IpAddr::from_str("2a07:a8c0::").unwrap()));
        assert!(list.contains(IpAddr::from_str("2a07:a8c1::").unwrap()));
        assert!(list.contains(IpAddr::from_str("2a07:a8c1::").unwrap()));
        assert!(!list.contains(IpAddr::from_str("1.1.1.1").unwrap()));
    }

    #[cfg(target_family = "windows")]
    #[test]
    fn windows() {
        let list = ResolverList::new();
        assert!(list.is_ok());

        let list = list.unwrap();
        for r in list.iter() {
            println!("r={:?}", r);
        }

        assert_eq!(list.len(), 4);

        assert!(list.contains(IpAddr::from_str("192.168.122.1").unwrap()));
        assert!(list.contains(IpAddr::from_str("8.8.8.8").unwrap()));
        assert!(list.contains(IpAddr::from_str("1.1.1.1").unwrap()));
        assert!(list.contains(IpAddr::from_str("fec0:0:0:ffff::1").unwrap()));
        assert!(list.contains(IpAddr::from_str("fec0:0:0:ffff::2").unwrap()));
        assert!(list.contains(IpAddr::from_str("fec0:0:0:ffff::3").unwrap()));
    }
}