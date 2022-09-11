#![no_std]

extern crate alloc;

pub mod crypto;
mod error;
pub mod file;
pub mod group;
pub mod user;
pub mod util;

/**
For server testing export every common
because using common from path via submodule resolve in version conflicts when using it in tests
 */
#[cfg(feature = "server_test")]
pub use sentc_crypto_common as sdk_common;

pub use self::error::{err_to_msg, SdkError};
pub use self::util::{DeviceKeyData, PrivateKeyFormat, PublicKeyFormat, SignKeyFormat, SymKeyFormat, UserData, UserKeyData, VerifyKeyFormat};
