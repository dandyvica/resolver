pub mod error;

#[cfg(target_family = "unix")]
pub mod unix;

//pub mod resolver;
#[cfg(target_family = "windows")]
pub mod win;