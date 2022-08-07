#![no_std]

extern crate alloc;

pub mod crypto;
mod error;
pub mod group;
#[cfg(feature = "server")]
pub mod test_fn;
pub mod user;
pub mod util;
pub mod util_pub;

/**
For server testing export every common
because using common from path via submodule resolve in version conflicts when using it in tests
 */
#[cfg(feature = "server_test")]
pub use sentc_crypto_common as sdk_common;

pub use self::error::{err_to_msg, SdkError};
pub use self::util::{KeyData, PrivateKeyFormat, PublicKeyFormat, SignKeyFormat, SymKeyFormat, VerifyKeyFormat};
