use std::net::IpAddr;

pub mod error;

#[cfg(target_family = "unix")]
pub mod unix;

//pub mod resolver;
#[cfg(target_family = "windows")]
pub mod win;

#[derive(Debug)]
pub struct Resolvers {
    pub v4: Vec<IpAddr>,
    pub v6: Vec<IpAddr>,
}
