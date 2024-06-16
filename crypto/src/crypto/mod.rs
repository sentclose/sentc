pub(crate) mod crypto;
#[cfg(not(feature = "rust"))]
mod crypto_export;
pub(crate) mod mimic_keys;

#[cfg(feature = "rust")]
pub use self::crypto::*;
#[cfg(not(feature = "rust"))]
pub use self::crypto_export::*;
#[cfg(not(feature = "rust"))]
pub(crate) use self::crypto_export::{prepare_sign_key, prepare_verify_key};
