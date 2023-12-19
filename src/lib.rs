//! A utility crate to retrieve the DNS resolvers of the underlying OS.
//!
//! On UNIX-like platforms, it merely read the `/etc/resonlv.conf` file.
//!
//! On Windows, it uses the [windows](https://crates.io/crates/windows) crate and calls the dedicated APIs to get the list of DNS resolvers for all interfaces (`GetAdaptersAddresses`).
//! In addition on this platform, the ability to provide a interface index or interface name to all get the resolvers on those.
//! 
//! Usage on Unix:
//! 
//! ```no_run
//! use resolver::ResolverList;
//! 
//! let addresses = ResolverList::new().expect("failed to load DNS addresses");
//! println!("{} addresses found", addresses.len());
//! ```
pub mod error;

#[cfg(any(unix, doc))]
pub mod unix;
pub type ResolverList = unix::ResolverList;

#[cfg(any(windows))]
pub mod win;


