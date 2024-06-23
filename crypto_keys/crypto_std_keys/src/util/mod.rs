#[cfg(feature = "full")]
mod crypto;
pub mod export;

use alloc::string::String;
use core::ops::Deref;
use core::str::FromStr;

use base64ct::{Base64, Encoding};
use export::{export_raw_public_key_to_pem, import_public_key_from_pem_with_alg, import_sig_from_string, import_verify_key_from_pem_with_alg};
use sentc_crypto_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto_common::{EncryptionKeyPairId, SignKeyPairId, SymKeyId};
use sentc_crypto_core::cryptomat::{SignK, SignKeyComposer, SignKeyPair, SkComposer, StaticKeyPair, SymKeyComposer, SymKeyGen, VerifyK};
use sentc_crypto_utils::cryptomat::{
	KeyToString,
	PkWrapper,
	SignComposerWrapper,
	SignKWrapper,
	SignKeyPairWrapper,
	SkWrapper,
	StaticKeyComposerWrapper,
	StaticKeyPairWrapper,
	SymKeyComposerWrapper,
	SymKeyGenWrapper,
	SymKeyWrapper,
	VerifyKWrapper,
};
use sentc_crypto_utils::error::SdkUtilError;
#[cfg(feature = "full")]
pub use sentc_crypto_utils::split_head_and_encrypted_data;
use sentc_crypto_utils::{from_string_impl, to_string_impl, wrapper_impl};
use serde::{Deserialize, Serialize};

#[cfg(feature = "full")]
pub use self::crypto::{HmacKey, SortableKey};
use crate::core::{
	PublicKey as CorePublicKey,
	SecretKey as CoreSecretKey,
	SignKey as CoreSignKey,
	SymmetricKey as CoreSymmetricKey,
	VerifyKey as CoreVerifyKey,
};
use crate::util::export::{export_raw_verify_key_to_pem, sig_to_string};

macro_rules! deref_impl {
	($st:ty, $t:ty) => {
		impl Deref for $st
		{
			type Target = $t;

			fn deref(&self) -> &Self::Target
			{
				&self.key
			}
		}
	};
}

pub(crate) use deref_impl;

//__________________________________________________________________________________________________

pub struct SymmetricKey
{
	pub key: CoreSymmetricKey,
	pub key_id: SymKeyId,
}

impl SymKeyGenWrapper for SymmetricKey
{
	type SymmetricKeyWrapper = Self;
	type KeyGen = CoreSymmetricKey;

	fn from_inner(inner: <<Self as SymKeyGenWrapper>::KeyGen as SymKeyGen>::SymmetricKey, id: String) -> Self::SymmetricKeyWrapper
	{
		Self {
			key_id: id,
			key: inner,
		}
	}
}

impl SymKeyComposerWrapper for SymmetricKey
{
	type SymmetricKeyWrapper = Self;
	type Composer = CoreSymmetricKey;

	fn from_inner(inner: <<Self as SymKeyComposerWrapper>::Composer as SymKeyComposer>::SymmetricKey, id: String) -> Self::SymmetricKeyWrapper
	{
		Self {
			key_id: id,
			key: inner,
		}
	}
}

wrapper_impl!(SymKeyWrapper, SymmetricKey, CoreSymmetricKey);
deref_impl!(SymmetricKey, CoreSymmetricKey);
to_string_impl!(SymmetricKey, SymKeyFormatExport);
from_string_impl!(SymmetricKey, SymKeyFormatExport);

#[derive(Serialize, Deserialize)]
pub enum SymKeyFormatExport
{
	Aes
	{
		key: String, key_id: SymKeyId
	},
}

impl From<SymmetricKey> for SymKeyFormatExport
{
	fn from(value: SymmetricKey) -> Self
	{
		let key = Base64::encode_string(value.as_ref());

		match value.key {
			CoreSymmetricKey::Aes(_) => {
				Self::Aes {
					key_id: value.key_id,
					key,
				}
			},
		}
	}
}

impl TryInto<SymmetricKey> for SymKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<SymmetricKey, Self::Error>
	{
		match self {
			SymKeyFormatExport::Aes {
				key,
				key_id,
			} => {
				//to bytes via base64
				let bytes = Base64::decode_vec(&key).map_err(|_| SdkUtilError::ImportSymmetricKeyFailed)?;

				Ok(SymmetricKey {
					key: CoreSymmetricKey::aes_key_from_bytes_owned(bytes)?,
					key_id,
				})
			},
		}
	}
}

impl<'a> TryInto<SymmetricKey> for &'a SymKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<SymmetricKey, Self::Error>
	{
		match self {
			SymKeyFormatExport::Aes {
				key,
				key_id,
			} => {
				//to bytes via base64
				let bytes = Base64::decode_vec(key).map_err(|_| SdkUtilError::ImportSymmetricKeyFailed)?;

				Ok(SymmetricKey {
					key: CoreSymmetricKey::aes_key_from_bytes_owned(bytes).unwrap(),
					key_id: key_id.clone(),
				})
			},
		}
	}
}

//__________________________________________________________________________________________________

pub struct SecretKey
{
	pub key: CoreSecretKey,
	pub key_id: EncryptionKeyPairId,
}

impl StaticKeyPairWrapper for SecretKey
{
	type PkWrapper = PublicKey;
	type KeyGen = CoreSecretKey;

	fn pk_from_inner(inner: <<Self as StaticKeyPairWrapper>::KeyGen as StaticKeyPair>::PublicKey, id: String) -> Self::PkWrapper
	{
		PublicKey {
			key: inner,
			key_id: id,
		}
	}

	fn pk_inner_to_pem(inner: &<<Self as StaticKeyPairWrapper>::KeyGen as StaticKeyPair>::PublicKey) -> Result<String, SdkUtilError>
	{
		export_raw_public_key_to_pem(inner)
	}
}

impl StaticKeyComposerWrapper for SecretKey
{
	type SkWrapper = Self;
	type PkWrapper = PublicKey;
	type InnerPk = CorePublicKey;
	type Composer = CoreSecretKey;

	fn sk_from_inner(inner: <<Self as StaticKeyComposerWrapper>::Composer as SkComposer>::SecretKey, id: String) -> Self::SkWrapper
	{
		Self {
			key_id: id,
			key: inner,
		}
	}

	fn pk_from_pem(public_key: &str, alg: &str, id: String) -> Result<Self::PkWrapper, SdkUtilError>
	{
		let key = import_public_key_from_pem_with_alg(public_key, alg)?;

		Ok(PublicKey {
			key,
			key_id: id,
		})
	}

	fn pk_inner_from_pem(public_key: &str, alg: &str) -> Result<Self::InnerPk, SdkUtilError>
	{
		import_public_key_from_pem_with_alg(public_key, alg)
	}
}

wrapper_impl!(SkWrapper, SecretKey, CoreSecretKey);
deref_impl!(SecretKey, CoreSecretKey);
to_string_impl!(SecretKey, SecretKeyFormatExport);
from_string_impl!(SecretKey, SecretKeyFormatExport);

#[derive(Serialize, Deserialize)]
pub enum SecretKeyFormatExport
{
	Ecies
	{
		key: String, key_id: EncryptionKeyPairId
	},

	Kyber
	{
		key: String, key_id: EncryptionKeyPairId
	},

	EciesKyberHybrid
	{
		x: String, k: String, key_id: EncryptionKeyPairId
	},
}

impl From<SecretKey> for SecretKeyFormatExport
{
	fn from(value: SecretKey) -> Self
	{
		match value.key {
			CoreSecretKey::Ecies(k) => {
				let key = Base64::encode_string(k.as_ref());

				Self::Ecies {
					key,
					key_id: value.key_id,
				}
			},
			CoreSecretKey::Kyber(k) => {
				let key = Base64::encode_string(k.as_ref());

				Self::Kyber {
					key,
					key_id: value.key_id,
				}
			},
			CoreSecretKey::EciesKyberHybrid(key) => {
				let (x, k) = key.get_raw_keys();

				let x = Base64::encode_string(x);
				let k = Base64::encode_string(k);

				Self::EciesKyberHybrid {
					k,
					x,
					key_id: value.key_id,
				}
			},
		}
	}
}

impl TryInto<SecretKey> for SecretKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<SecretKey, Self::Error>
	{
		match self {
			Self::Ecies {
				key_id,
				key,
			} => {
				//to bytes via base64
				let bytes = Base64::decode_vec(&key).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;

				Ok(SecretKey {
					key: CoreSecretKey::ecies_from_bytes_owned(bytes)?,
					key_id,
				})
			},
			Self::Kyber {
				key_id,
				key,
			} => {
				//to bytes via base64
				let bytes = Base64::decode_vec(&key).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;

				Ok(SecretKey {
					key: CoreSecretKey::kyber_from_bytes_owned(bytes)?,
					key_id,
				})
			},
			Self::EciesKyberHybrid {
				key_id,
				x,
				k,
			} => {
				let bytes_x = Base64::decode_vec(&x).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;
				let bytes_k = Base64::decode_vec(&k).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;

				Ok(SecretKey {
					key_id,
					key: CoreSecretKey::ecies_kyber_hybrid_from_bytes_owned(bytes_x, bytes_k)?,
				})
			},
		}
	}
}

//__________________________________________________________________________________________________

/**
This is used for the hybrid keys when exporting it to pem
 */
#[derive(Serialize, Deserialize)]
pub struct HybridPublicKeyExportFormat
{
	pub x: String,
	pub k: String,
}

#[derive(Clone)]
pub struct PublicKey
{
	pub key: CorePublicKey,
	pub key_id: EncryptionKeyPairId,
}

impl PublicKey
{
	pub fn to_string_ref(&self) -> Result<String, SdkUtilError>
	{
		serde_json::to_string(&Into::<PublicKeyFormatExport>::into(self)).map_err(|_e| SdkUtilError::JsonToStringFailed)
	}
}

wrapper_impl!(PkWrapper, PublicKey, CorePublicKey);
deref_impl!(PublicKey, CorePublicKey);
to_string_impl!(PublicKey, PublicKeyFormatExport);
from_string_impl!(PublicKey, PublicKeyFormatExport);

#[derive(Serialize, Deserialize)]
pub enum PublicKeyFormatExport
{
	Ecies
	{
		key: String, key_id: EncryptionKeyPairId
	},

	Kyber
	{
		key: String, key_id: EncryptionKeyPairId
	},

	EciesKyberHybrid
	{
		x: String, k: String, key_id: EncryptionKeyPairId
	},
}

impl From<PublicKey> for PublicKeyFormatExport
{
	fn from(value: PublicKey) -> Self
	{
		match value.key {
			CorePublicKey::Ecies(k) => {
				let key = Base64::encode_string(k.as_ref());

				Self::Ecies {
					key,
					key_id: value.key_id,
				}
			},
			CorePublicKey::Kyber(k) => {
				let key = Base64::encode_string(k.as_ref());

				Self::Kyber {
					key,
					key_id: value.key_id,
				}
			},
			CorePublicKey::EciesKyberHybrid(key) => {
				let (x, k) = key.get_raw_keys();

				let x = Base64::encode_string(x);
				let k = Base64::encode_string(k);

				Self::EciesKyberHybrid {
					k,
					x,
					key_id: value.key_id,
				}
			},
		}
	}
}

impl<'a> From<&'a PublicKey> for PublicKeyFormatExport
{
	fn from(value: &'a PublicKey) -> Self
	{
		match &value.key {
			CorePublicKey::Ecies(k) => {
				let key = Base64::encode_string(k.as_ref());

				Self::Ecies {
					key,
					key_id: value.key_id.clone(),
				}
			},
			CorePublicKey::Kyber(k) => {
				let key = Base64::encode_string(k.as_ref());

				Self::Kyber {
					key,
					key_id: value.key_id.clone(),
				}
			},
			CorePublicKey::EciesKyberHybrid(key) => {
				let (x, k) = key.get_raw_keys();

				let x = Base64::encode_string(x);
				let k = Base64::encode_string(k);

				Self::EciesKyberHybrid {
					k,
					x,
					key_id: value.key_id.clone(),
				}
			},
		}
	}
}

impl TryInto<PublicKey> for PublicKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<PublicKey, Self::Error>
	{
		match self {
			Self::Ecies {
				key_id,
				key,
			} => {
				//to bytes via base64
				let bytes = Base64::decode_vec(&key).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;

				Ok(PublicKey {
					key: CorePublicKey::ecies_from_bytes_owned(bytes)?,
					key_id,
				})
			},
			Self::Kyber {
				key_id,
				key,
			} => {
				//to bytes via base64
				let bytes = Base64::decode_vec(&key).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;

				Ok(PublicKey {
					key: CorePublicKey::kyber_from_bytes_owned(bytes)?,
					key_id,
				})
			},
			Self::EciesKyberHybrid {
				key_id,
				x,
				k,
			} => {
				let bytes_x = Base64::decode_vec(&x).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;
				let bytes_k = Base64::decode_vec(&k).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;

				Ok(PublicKey {
					key_id,
					key: CorePublicKey::ecies_kyber_hybrid_from_bytes_owned(bytes_x, bytes_k)?,
				})
			},
		}
	}
}

impl TryFrom<UserPublicKeyData> for PublicKey
{
	type Error = SdkUtilError;

	fn try_from(value: UserPublicKeyData) -> Result<Self, Self::Error>
	{
		Ok(Self {
			key_id: value.public_key_id,
			key: import_public_key_from_pem_with_alg(&value.public_key_pem, &value.public_key_alg)?,
		})
	}
}

impl<'a> TryFrom<&'a UserPublicKeyData> for PublicKey
{
	type Error = SdkUtilError;

	fn try_from(value: &'a UserPublicKeyData) -> Result<Self, Self::Error>
	{
		Ok(Self {
			key_id: value.public_key_id.clone(),
			key: import_public_key_from_pem_with_alg(&value.public_key_pem, &value.public_key_alg)?,
		})
	}
}

//__________________________________________________________________________________________________

pub struct SignKey
{
	pub key: CoreSignKey,
	pub key_id: SignKeyPairId,
}

impl SignKeyPairWrapper for SignKey
{
	type KeyGen = CoreSignKey;

	fn vk_inner_to_pem(inner: &<<Self as SignKeyPairWrapper>::KeyGen as SignKeyPair>::VerifyKey) -> Result<String, SdkUtilError>
	{
		export_raw_verify_key_to_pem(inner)
	}

	fn sig_to_string(sig: <<<Self as SignKeyPairWrapper>::KeyGen as SignKeyPair>::SignKey as SignK>::Signature) -> String
	{
		sig_to_string(&sig)
	}
}

impl SignComposerWrapper for SignKey
{
	type SignKWrapper = Self;
	type VerifyKWrapper = VerifyKey;
	type InnerVk = CoreVerifyKey;
	type Composer = CoreSignKey;

	fn sk_from_inner(inner: <<Self as SignComposerWrapper>::Composer as SignKeyComposer>::Key, id: String) -> Self::SignKWrapper
	{
		Self {
			key_id: id,
			key: inner,
		}
	}

	fn vk_from_pem(public_key: &str, alg: &str, id: String) -> Result<Self::VerifyKWrapper, SdkUtilError>
	{
		let key = import_verify_key_from_pem_with_alg(public_key, alg)?;

		Ok(VerifyKey {
			key,
			key_id: id,
		})
	}

	fn vk_inner_from_pem(public_key: &str, alg: &str) -> Result<Self::InnerVk, SdkUtilError>
	{
		import_verify_key_from_pem_with_alg(public_key, alg)
	}

	fn sig_from_string(sig: &str, alg: &str) -> Result<<<Self as SignComposerWrapper>::InnerVk as VerifyK>::Signature, SdkUtilError>
	{
		import_sig_from_string(sig, alg)
	}
}

wrapper_impl!(SignKWrapper, SignKey, CoreSignKey);
deref_impl!(SignKey, CoreSignKey);
to_string_impl!(SignKey, SignKeyFormatExport);
from_string_impl!(SignKey, SignKeyFormatExport);

#[derive(Serialize, Deserialize)]
pub enum SignKeyFormatExport
{
	Ed25519
	{
		key: String, key_id: SignKeyPairId
	},

	Dilithium
	{
		key: String, key_id: SignKeyPairId
	},

	Ed25519DilithiumHybrid
	{
		x: String, k: String, key_id: SignKeyPairId
	},
}

impl From<SignKey> for SignKeyFormatExport
{
	fn from(value: SignKey) -> Self
	{
		match value.key {
			CoreSignKey::Ed25519(k) => {
				let key = Base64::encode_string(k.as_ref());

				Self::Ed25519 {
					key,
					key_id: value.key_id,
				}
			},
			CoreSignKey::Dilithium(k) => {
				let key = Base64::encode_string(k.as_ref());

				Self::Dilithium {
					key,
					key_id: value.key_id,
				}
			},
			CoreSignKey::Ed25519DilithiumHybrid(key) => {
				let (x, k) = key.get_raw_keys();

				let x = Base64::encode_string(x);
				let k = Base64::encode_string(k);

				Self::Ed25519DilithiumHybrid {
					x,
					k,
					key_id: value.key_id,
				}
			},
		}
	}
}

impl TryInto<SignKey> for SignKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<SignKey, Self::Error>
	{
		match self {
			Self::Ed25519 {
				key,
				key_id,
			} => {
				let bytes = Base64::decode_vec(&key).map_err(|_| SdkUtilError::ImportingSignKeyFailed)?;

				Ok(SignKey {
					key_id,
					key: CoreSignKey::ed25519_from_bytes_owned(bytes)?,
				})
			},
			Self::Dilithium {
				key,
				key_id,
			} => {
				let bytes = Base64::decode_vec(&key).map_err(|_| SdkUtilError::ImportingSignKeyFailed)?;

				Ok(SignKey {
					key_id,
					key: CoreSignKey::dilithium_from_bytes_owned(bytes)?,
				})
			},
			Self::Ed25519DilithiumHybrid {
				x,
				k,
				key_id,
			} => {
				let bytes_x = Base64::decode_vec(&x).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;
				let bytes_k = Base64::decode_vec(&k).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;

				Ok(SignKey {
					key_id,
					key: CoreSignKey::ed25519_dilithium_hybrid_from_bytes_owned(bytes_x, bytes_k)?,
				})
			},
		}
	}
}

//__________________________________________________________________________________________________

pub struct VerifyKey
{
	pub key: CoreVerifyKey,
	pub key_id: SignKeyPairId,
}

wrapper_impl!(VerifyKWrapper, VerifyKey, CoreVerifyKey);
deref_impl!(VerifyKey, CoreVerifyKey);
to_string_impl!(VerifyKey, VerifyKeyFormatExport);
from_string_impl!(VerifyKey, VerifyKeyFormatExport);

#[derive(Serialize, Deserialize)]
pub enum VerifyKeyFormatExport
{
	Ed25519
	{
		key: String, key_id: SignKeyPairId
	},

	Dilithium
	{
		key: String, key_id: SignKeyPairId
	},

	Ed25519DilithiumHybrid
	{
		x: String, k: String, key_id: SignKeyPairId
	},
}

impl From<VerifyKey> for VerifyKeyFormatExport
{
	fn from(value: VerifyKey) -> Self
	{
		match value.key {
			CoreVerifyKey::Ed25519(k) => {
				let key = Base64::encode_string(k.as_ref());

				Self::Ed25519 {
					key_id: value.key_id,
					key,
				}
			},
			CoreVerifyKey::Dilithium(k) => {
				let key = Base64::encode_string(k.as_ref());

				Self::Dilithium {
					key_id: value.key_id,
					key,
				}
			},
			CoreVerifyKey::Ed25519DilithiumHybrid(key) => {
				let (x, k) = key.get_raw_keys();

				let x = Base64::encode_string(x);
				let k = Base64::encode_string(k);

				Self::Ed25519DilithiumHybrid {
					x,
					k,
					key_id: value.key_id,
				}
			},
		}
	}
}

impl TryInto<VerifyKey> for VerifyKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<VerifyKey, Self::Error>
	{
		match self {
			Self::Ed25519 {
				key,
				key_id,
			} => {
				let bytes = Base64::decode_vec(&key).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;

				Ok(VerifyKey {
					key: CoreVerifyKey::ed25519_from_bytes_owned(bytes)?,
					key_id,
				})
			},
			Self::Dilithium {
				key,
				key_id,
			} => {
				let bytes = Base64::decode_vec(&key).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;

				Ok(VerifyKey {
					key: CoreVerifyKey::dilithium_from_bytes_owned(bytes)?,
					key_id,
				})
			},
			Self::Ed25519DilithiumHybrid {
				x,
				k,
				key_id,
			} => {
				let bytes_x = Base64::decode_vec(&x).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;
				let bytes_k = Base64::decode_vec(&k).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;

				Ok(VerifyKey {
					key_id,
					key: CoreVerifyKey::ed25519_dilithium_hybrid_from_bytes_owned(bytes_x, bytes_k)?,
				})
			},
		}
	}
}

impl TryFrom<UserVerifyKeyData> for VerifyKey
{
	type Error = SdkUtilError;

	fn try_from(value: UserVerifyKeyData) -> Result<Self, Self::Error>
	{
		Ok(Self {
			key_id: value.verify_key_id,
			key: import_verify_key_from_pem_with_alg(&value.verify_key_pem, &value.verify_key_alg)?,
		})
	}
}

impl<'a> TryFrom<&'a UserVerifyKeyData> for VerifyKey
{
	type Error = SdkUtilError;

	fn try_from(value: &'a UserVerifyKeyData) -> Result<Self, Self::Error>
	{
		Ok(Self {
			key_id: value.verify_key_id.clone(),
			key: import_verify_key_from_pem_with_alg(&value.verify_key_pem, &value.verify_key_alg)?,
		})
	}
}

//__________________________________________________________________________________________________

/**
This key is used if the user enabled mfa, and we need more data of the user for login.
it is used to temporary store the key for the next process
 */
#[derive(Serialize, Deserialize)]
pub enum MasterKeyFormat
{
	Argon2(String), //Base64 encoded string from prepare login, is used in done_login
}

impl MasterKeyFormat
{
	pub fn to_string(self) -> Result<String, SdkUtilError>
	{
		serde_json::to_string(&self).map_err(|_e| SdkUtilError::JsonToStringFailed)
	}
}

impl FromStr for MasterKeyFormat
{
	type Err = SdkUtilError;

	fn from_str(s: &str) -> Result<Self, Self::Err>
	{
		serde_json::from_str(s).map_err(|_| SdkUtilError::ImportAuthMasterKeyFailed)
	}
}

impl TryInto<crate::core::DeriveMasterKeyForAuth> for MasterKeyFormat
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<crate::core::DeriveMasterKeyForAuth, Self::Error>
	{
		match self {
			Self::Argon2(mk) => {
				let bytes = Base64::decode_vec(mk.as_str()).map_err(|_e| SdkUtilError::ImportAuthMasterKeyFailed)?;

				Ok(crate::core::DeriveMasterKeyForAuth::argon2_from_bytes_owned(bytes)?)
			},
		}
	}
}

impl From<crate::core::DeriveMasterKeyForAuth> for MasterKeyFormat
{
	fn from(value: crate::core::DeriveMasterKeyForAuth) -> Self
	{
		match value {
			crate::core::DeriveMasterKeyForAuth::Argon2(k) => {
				let key = Base64::encode_string(&k);

				Self::Argon2(key)
			},
		}
	}
}
