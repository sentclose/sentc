#![no_std]

extern crate alloc;

pub mod crypto;
mod error;
pub mod group;
pub mod test_fn;
pub mod user;
mod util;
pub mod util_pub;
#[cfg(feature = "server")]
pub mod util_server;

pub use self::error::{err_to_msg, SdkError};
pub use self::util::{KeyData, PrivateKeyFormat, PublicKeyFormat, SignKeyFormat, SymKeyFormat, VerifyKeyFormat};
