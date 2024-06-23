use sentc_crypto::crypto::KeyGenerator;
use sentc_crypto::entities::group::GroupKeyData;
use sentc_crypto::entities::user::{UserDataInt, UserKeyDataInt};
use sentc_crypto::file::FileEncryptor;
use sentc_crypto::group::Group;
use sentc_crypto::user::User;

use crate::core::hmac::HmacKey as CoreHmac;
use crate::core::pw_hash::PwHasherGetter;
use crate::core::sortable::NonSortableKeys;
use crate::core::sym::Aes256GcmKey;
use crate::util::{HmacKey, PublicKey, SecretKey, SignKey, SortableKey, SymmetricKey, VerifyKey};

pub type FipsGroup =
	Group<SymmetricKey, SecretKey, SignKey, CoreHmac, NonSortableKeys, SymmetricKey, SecretKey, SignKey, HmacKey, SortableKey, PublicKey, VerifyKey>;

pub type FipsGroupKeyData = GroupKeyData<SymmetricKey, SecretKey, PublicKey>;

pub type FipsUser = User<
	SymmetricKey,
	SecretKey,
	SignKey,
	CoreHmac,
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

pub type FipsFileEncryptor = FileEncryptor<Aes256GcmKey, Aes256GcmKey, VerifyKey>;

#[cfg(feature = "sdk_full")]
pub type FipsPreLoginOut = sentc_crypto::util_req_full::user::PreLoginOut<
	SymmetricKey,
	SecretKey,
	PublicKey,
	SignKey,
	VerifyKey,
	crate::core::pw_hash::DeriveAuthKeyForAuth,
>;
