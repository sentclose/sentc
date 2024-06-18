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
#[cfg(feature = "std_keys")]
pub use sentc_crypto_std_keys as std_keys;
pub use sentc_crypto_utils as sdk_utils;

pub use self::error::{err_to_msg, SdkError};

#[cfg(feature = "std_keys")]
pub type StdGroup = group::Group<
	sentc_crypto_std_keys::util::SymmetricKey,
	sentc_crypto_std_keys::util::SecretKey,
	sentc_crypto_std_keys::util::SignKey,
	sentc_crypto_std_keys::core::HmacKey,
	sentc_crypto_std_keys::core::SortKeys,
	sentc_crypto_std_keys::util::SymmetricKey,
	sentc_crypto_std_keys::util::SecretKey,
	sentc_crypto_std_keys::util::SignKey,
	sentc_crypto_std_keys::util::HmacKey,
	sentc_crypto_std_keys::util::SortableKey,
	sentc_crypto_std_keys::util::PublicKey,
	sentc_crypto_std_keys::util::VerifyKey,
>;

#[cfg(feature = "std_keys")]
pub type StdGroupKeyData = entities::group::GroupKeyData<
	sentc_crypto_std_keys::util::SymmetricKey,
	sentc_crypto_std_keys::util::SecretKey,
	sentc_crypto_std_keys::util::PublicKey,
>;

#[cfg(feature = "std_keys")]
pub type StdUser = user::User<
	sentc_crypto_std_keys::util::SymmetricKey,
	sentc_crypto_std_keys::util::SecretKey,
	sentc_crypto_std_keys::util::SignKey,
	sentc_crypto_std_keys::core::HmacKey,
	sentc_crypto_std_keys::core::SortKeys,
	sentc_crypto_std_keys::util::SymmetricKey,
	sentc_crypto_std_keys::util::SecretKey,
	sentc_crypto_std_keys::util::SignKey,
	sentc_crypto_std_keys::util::HmacKey,
	sentc_crypto_std_keys::util::SortableKey,
	sentc_crypto_std_keys::util::PublicKey,
	sentc_crypto_std_keys::util::VerifyKey,
	sentc_crypto_std_keys::core::PwHasherGetter,
>;

#[cfg(feature = "std_keys")]
pub type StdUserDataInt = entities::user::UserDataInt<
	sentc_crypto_std_keys::util::SymmetricKey,
	sentc_crypto_std_keys::util::SecretKey,
	sentc_crypto_std_keys::util::PublicKey,
	sentc_crypto_std_keys::util::SignKey,
	sentc_crypto_std_keys::util::VerifyKey,
>;

#[cfg(feature = "std_keys")]
pub type StdUserKeyDataInt = entities::user::UserKeyDataInt<
	sentc_crypto_std_keys::util::SymmetricKey,
	sentc_crypto_std_keys::util::SecretKey,
	sentc_crypto_std_keys::util::PublicKey,
	sentc_crypto_std_keys::util::SignKey,
	sentc_crypto_std_keys::util::VerifyKey,
>;

#[cfg(feature = "std_keys")]
pub type StdKeyGenerator = crypto::KeyGenerator<
	sentc_crypto_std_keys::util::SymmetricKey,
	sentc_crypto_std_keys::util::SymmetricKey,
	sentc_crypto_std_keys::util::PublicKey,
>;

#[cfg(feature = "std_keys")]
pub type StdFileEncryptor =
	file::FileEncryptor<sentc_crypto_std_keys::core::SymmetricKey, sentc_crypto_std_keys::core::SymmetricKey, sentc_crypto_std_keys::util::VerifyKey>;

#[cfg(all(feature = "std_keys", any(feature = "full_rustls", feature = "full_wasm")))]
pub type StdPreLoginOut = util_req_full::user::PreLoginOut<
	sentc_crypto_std_keys::util::SymmetricKey,
	sentc_crypto_std_keys::util::SecretKey,
	sentc_crypto_std_keys::util::PublicKey,
	sentc_crypto_std_keys::util::SignKey,
	sentc_crypto_std_keys::util::VerifyKey,
	sentc_crypto_std_keys::core::DeriveMasterKeyForAuth,
>;
