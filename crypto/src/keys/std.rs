use sentc_crypto_std_keys::core::PwHasherGetter;
use sentc_crypto_std_keys::util::{HmacKey, PublicKey, SecretKey, SignKey, SortableKey, SymmetricKey, VerifyKey};

use crate::{crypto, entities, file, group, user};

pub type StdGroup = group::Group<
	SymmetricKey,
	SecretKey,
	SignKey,
	sentc_crypto_std_keys::core::HmacKey,
	sentc_crypto_std_keys::core::SortKeys,
	SymmetricKey,
	SecretKey,
	SignKey,
	HmacKey,
	SortableKey,
	PublicKey,
	VerifyKey,
>;

pub type StdGroupKeyData = entities::group::GroupKeyData<SymmetricKey, SecretKey, PublicKey>;

pub type StdUser = user::User<
	SymmetricKey,
	SecretKey,
	SignKey,
	sentc_crypto_std_keys::core::HmacKey,
	sentc_crypto_std_keys::core::SortKeys,
	SymmetricKey,
	SecretKey,
	SignKey,
	HmacKey,
	SortableKey,
	PublicKey,
	VerifyKey,
	PwHasherGetter,
>;

pub type StdUserDataInt = entities::user::UserDataInt<SymmetricKey, SecretKey, PublicKey, SignKey, VerifyKey>;

pub type StdUserKeyDataInt = entities::user::UserKeyDataInt<SymmetricKey, SecretKey, PublicKey, SignKey, VerifyKey>;

pub type StdKeyGenerator = crypto::KeyGenerator<SymmetricKey, SymmetricKey, PublicKey>;

pub type StdFileEncryptor =
	file::FileEncryptor<sentc_crypto_std_keys::core::SymmetricKey, sentc_crypto_std_keys::core::SymmetricKey, SignKey, VerifyKey>;

#[cfg(any(feature = "full_rustls", feature = "full_wasm"))]
pub type StdPreLoginOut = crate::util_req_full::user::PreLoginOut<
	SymmetricKey,
	SecretKey,
	PublicKey,
	SignKey,
	VerifyKey,
	sentc_crypto_std_keys::core::DeriveMasterKeyForAuth,
>;
