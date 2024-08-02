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

//! The base lib for all sentc libraries. Containing user- and group management as well as encryption, file-handling and search- and sortable encryption
//!
//! These are very low-level functionalities. It is recommended to use it with a sdks.
//!
//! This lib is defined as a "template" to use it with different crypto implementations thanks to rusts generic.
//! As long as the implementation follows the traits defined in sentc-crypto-core and sentc-crypto-utils crate it can be used with this lib.
//!
//! # Overview
//!
//! Users and groups are structs with generic parameter.
//! Pre-defined users and groups can be found in the keys mod
//!
//! Online actions like creating a new user or group can be found in the util_req_full mod
//! and is only available when activating the feature full_rustls or full_wasm.
//!
//! For sdk implementations that uses ffi or wasm, the export feature can be used.
//! All Keys are returned as exported string in base64 and all errors are string as well. This makes it easy to integrate with wasm.
//! In every mod there are an _export file with the export implementation of the actual mod.
//! For a full rust implementation this is not recommended.
//!
//! Every function with prepare and done or finish prefix can be used "offline" without server interactions
//! but required the server responses. This is useful when certain processes needs to be handled differently.
//!
//! # Get started
//!
//! ```toml
//! sentc-crypto = "<the actual version number>"
//! ```
//!
//! To install it with pre-defined crypto implementation:
//!
//! * For the std keys:
//! ```toml
//! sentc-crypto = { version = "<the actual version number>", features = ["std_keys"] }
//! ```
//!
//! * For fips complaint keys:
//! ```toml
//! sentc-crypto = { version = "<the actual version number>", features = ["fips_keys"] }
//! ```
//!
//! * For the recommended keys:
//! ```toml
//! sentc-crypto = { version = "<the actual version number>", features = ["rec_keys"] }
//! ```
//!
//! To get the online actions add the feature:
//! * full_rustls to use rustls
//! * full_wasm to use the web assembly requests

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
