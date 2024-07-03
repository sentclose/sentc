use sentc_crypto_fips_keys::core::pw_hash::PwHasherGetter;
use sentc_crypto_fips_keys::core::sortable::NonSortableKeys;
use sentc_crypto_fips_keys::core::sym::Aes256GcmKey;
use sentc_crypto_fips_keys::util::{HmacKey, PublicKey, SecretKey, SignKey, SortableKey, SymmetricKey, VerifyKey};

use crate::crypto::KeyGenerator;
use crate::entities::group::GroupKeyData;
use crate::entities::user::{UserDataInt, UserKeyDataInt};
use crate::file::FileEncryptor;
use crate::group::Group;
use crate::user::User;

pub type FipsGroup = Group<
	SymmetricKey,
	SecretKey,
	SignKey,
	sentc_crypto_fips_keys::core::hmac::HmacKey,
	NonSortableKeys,
	SymmetricKey,
	SecretKey,
	SignKey,
	HmacKey,
	SortableKey,
	PublicKey,
	VerifyKey,
>;

pub type FipsGroupKeyData = GroupKeyData<SymmetricKey, SecretKey, PublicKey>;

pub type FipsUser = User<
	SymmetricKey,
	SecretKey,
	SignKey,
	sentc_crypto_fips_keys::core::hmac::HmacKey,
	NonSortableKeys,
	SymmetricKey,
	SecretKey,
	SignKey,
	HmacKey,
	SortableKey,
	PublicKey,
	VerifyKey,
	PwHasherGetter,
>;

pub type FipsUserDataInt = UserDataInt<SymmetricKey, SecretKey, PublicKey, SignKey, VerifyKey>;

pub type FipsUserKeyDataInt = UserKeyDataInt<SymmetricKey, SecretKey, PublicKey, SignKey, VerifyKey>;

pub type FipsKeyGenerator = KeyGenerator<SymmetricKey, SymmetricKey, PublicKey>;

pub type FipsFileEncryptor = FileEncryptor<Aes256GcmKey, Aes256GcmKey, SignKey, VerifyKey>;

#[cfg(any(feature = "full_rustls", feature = "full_wasm"))]
pub type FipsPreLoginOut = crate::util_req_full::user::PreLoginOut<
	SymmetricKey,
	SecretKey,
	PublicKey,
	SignKey,
	VerifyKey,
	sentc_crypto_fips_keys::core::pw_hash::DeriveAuthKeyForAuth,
>;
