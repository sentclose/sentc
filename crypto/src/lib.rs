#![no_std]
#![allow(
	clippy::module_inception,
	clippy::infallible_destructuring_match,
	clippy::tabs_in_doc_comments,
	clippy::manual_map,
	clippy::explicit_counter_loop,
	clippy::manual_range_contains,
	clippy::type_complexity
)]

extern crate alloc;

pub mod crypto;
pub mod crypto_searchable;
pub mod crypto_sortable;
pub mod entities;
mod error;
pub mod file;
pub mod group;
pub mod user;
pub mod util;

pub mod keys;
#[cfg(any(feature = "full_rustls", feature = "full_wasm"))]
pub mod util_req_full;

/**
For server testing export every common
because using common from path via submodule resolve in version conflicts when using it in tests
 */
#[cfg(feature = "server_test")]
pub use sentc_crypto_common as sdk_common;
/**
Reexport of the crypto core crate to access the raw types
*/
pub use sentc_crypto_core as sdk_core;
#[cfg(feature = "fips_keys")]
pub use sentc_crypto_fips_keys as fips_keys;
#[cfg(feature = "rec_keys")]
pub use sentc_crypto_rec_keys as rec_keys;
#[cfg(feature = "std_keys")]
pub use sentc_crypto_std_keys as std_keys;
pub use sentc_crypto_utils as sdk_utils;

pub use self::error::{err_to_msg, SdkError};
