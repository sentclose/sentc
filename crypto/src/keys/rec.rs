use sentc_crypto_rec_keys::core::pw_hash::PwHasher;
use sentc_crypto_rec_keys::core::sym::Aes256GcmKey;
use sentc_crypto_rec_keys::util::{HmacKey, PublicKey, SecretKey, SignKey, SortableKey, SymmetricKey, VerifyKey};

use crate::crypto::KeyGenerator;
use crate::entities::group::GroupKeyData;
use crate::entities::user::{UserDataInt, UserKeyDataInt};
use crate::file::FileEncryptor;
use crate::group::Group;
use crate::user::User;

pub type RecGroup = Group<
	SymmetricKey,
	SecretKey,
	SignKey,
	sentc_crypto_rec_keys::core::hmac::HmacKey,
	sentc_crypto_rec_keys::core::sortable::OpeSortableKey,
	SymmetricKey,
	SecretKey,
	SignKey,
	HmacKey,
	SortableKey,
	PublicKey,
	VerifyKey,
>;

pub type RecGroupKeyData = GroupKeyData<SymmetricKey, SecretKey, PublicKey>;

pub type RecUser = User<
	SymmetricKey,
	SecretKey,
	SignKey,
	sentc_crypto_rec_keys::core::hmac::HmacKey,
	sentc_crypto_rec_keys::core::sortable::OpeSortableKey,
	SymmetricKey,
	SecretKey,
	SignKey,
	HmacKey,
	SortableKey,
	PublicKey,
	VerifyKey,
	PwHasher,
>;

pub type RecUserDataInt = UserDataInt<SymmetricKey, SecretKey, PublicKey, SignKey, VerifyKey>;

pub type RecUserKeyDataInt = UserKeyDataInt<SymmetricKey, SecretKey, PublicKey, SignKey, VerifyKey>;

pub type RecKeyGenerator = KeyGenerator<SymmetricKey, SymmetricKey, PublicKey>;

pub type RecFileEncryptor = FileEncryptor<Aes256GcmKey, Aes256GcmKey, SignKey, VerifyKey>;

#[cfg(any(feature = "full_rustls", feature = "full_wasm"))]
pub type FipsPreLoginOut = crate::util_req_full::user::PreLoginOut<
	SymmetricKey,
	SecretKey,
	PublicKey,
	SignKey,
	VerifyKey,
	sentc_crypto_rec_keys::core::pw_hash::DeriveAuthKeyForAuth,
>;
