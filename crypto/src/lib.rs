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
pub use sentc_crypto_utils as sdk_utils;

pub use self::error::{err_to_msg, SdkError};

pub type StdGroup = group::Group<
	sdk_utils::keys::SymmetricKey,
	sdk_utils::keys::SecretKey,
	sdk_utils::keys::SignKey,
	sdk_core::HmacKey,
	sdk_core::SortKeys,
	sdk_utils::keys::SymmetricKey,
	sdk_utils::keys::SecretKey,
	sdk_utils::keys::SignKey,
	sdk_utils::keys::HmacKey,
	sdk_utils::keys::SortableKey,
	sdk_utils::keys::PublicKey,
	sdk_utils::keys::VerifyKey,
>;

pub type StdUser = user::User<
	sdk_utils::keys::SymmetricKey,
	sdk_utils::keys::SecretKey,
	sdk_utils::keys::SignKey,
	sdk_core::HmacKey,
	sdk_core::SortKeys,
	sdk_utils::keys::SymmetricKey,
	sdk_utils::keys::SecretKey,
	sdk_utils::keys::SignKey,
	sdk_utils::keys::HmacKey,
	sdk_utils::keys::SortableKey,
	sdk_utils::keys::PublicKey,
	sdk_utils::keys::VerifyKey,
>;

pub type StdUserDataInt = entities::user::UserDataInt<
	sdk_utils::keys::SymmetricKey,
	sdk_utils::keys::SecretKey,
	sdk_utils::keys::PublicKey,
	sdk_utils::keys::SignKey,
	sdk_utils::keys::VerifyKey,
>;

pub type StdUserKeyDataInt = entities::user::UserKeyDataInt<
	sdk_utils::keys::SymmetricKey,
	sdk_utils::keys::SecretKey,
	sdk_utils::keys::PublicKey,
	sdk_utils::keys::SignKey,
	sdk_utils::keys::VerifyKey,
>;
