pub mod error;

#[cfg(target_family = "unix")]
pub mod unix;

#[cfg(target_family = "unix")]
#[derive(Debug)]
pub struct ResolverList {
    resolvers: Vec<std::net::IpAddr>,
}

// #[cfg(target_family = "unix")]
// #[derive(Debug)]
// pub struct ResolverList {
//     resolvers: Vec<std::net::IpAddr>,
// }
//pub mod resolver;
#[cfg(target_family = "windows")]
pub mod win;
// Identify a single resolver

#[cfg(target_family = "windows")]
#[derive(Debug, Clone)]
pub struct Resolver {
    // interface name (like "Ethernet 2")
    if_name: String,

    // interface index (like 12)
    if_index: u32,

    // list of DNS resolvers for this interface
    ip_list: Vec<IpAddr>,
}

#[cfg(target_family = "windows")]
#[derive(Debug)]
pub struct ResolverList {
    resolvers: Vec<Resolver>,
}