#[cfg(feature = "full")]
mod crypto;
pub mod export;

use alloc::string::String;
use core::str::FromStr;

use base64ct::{Base64, Encoding};
use export::{export_raw_public_key_to_pem, import_public_key_from_pem_with_alg, import_sig_from_string, import_verify_key_from_pem_with_alg};
use sentc_crypto_common::{EncryptionKeyPairId, SignKeyPairId, SymKeyId};
use sentc_crypto_core::cryptomat::SignK;
use sentc_crypto_utils::cryptomat::{PkWrapper, SignKWrapper, SkWrapper, SymKeyWrapper, VerifyKWrapper};
use sentc_crypto_utils::error::SdkUtilError;
#[cfg(feature = "full")]
pub use sentc_crypto_utils::split_head_and_encrypted_data;
use sentc_crypto_utils::{
	from_string_impl,
	pk_user_pk,
	sign_key_composer_self,
	sign_key_pair_self,
	static_key_composer_self,
	static_key_pair_self,
	sym_key_com_self,
	sym_key_gen_self,
	to_string_impl,
	vk_user_vk,
	wrapper_impl,
};
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

//__________________________________________________________________________________________________

pub struct SymmetricKey
{
	pub key: CoreSymmetricKey,
	pub key_id: SymKeyId,
}

wrapper_impl!(SymKeyWrapper, SymmetricKey, CoreSymmetricKey);
to_string_impl!(SymmetricKey, SymKeyFormatExport);
from_string_impl!(SymmetricKey, SymKeyFormatExport);
sym_key_gen_self!(SymmetricKey, CoreSymmetricKey);
sym_key_com_self!(SymmetricKey, CoreSymmetricKey);

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
		let key = Base64::encode_string(value.key.as_ref());

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

impl<'a> From<&'a SymmetricKey> for SymKeyFormatExport
{
	fn from(value: &'a SymmetricKey) -> Self
	{
		let key = Base64::encode_string(value.key.as_ref());

		match value.key {
			CoreSymmetricKey::Aes(_) => {
				Self::Aes {
					key_id: value.key_id.clone(),
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

static_key_pair_self!(SecretKey, CoreSecretKey, PublicKey, export_raw_public_key_to_pem);
static_key_composer_self!(
	SecretKey,
	CoreSecretKey,
	PublicKey,
	CorePublicKey,
	import_public_key_from_pem_with_alg
);
wrapper_impl!(SkWrapper, SecretKey, CoreSecretKey);
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

impl<'a> From<&'a SecretKey> for SecretKeyFormatExport
{
	fn from(value: &'a SecretKey) -> Self
	{
		match &value.key {
			CoreSecretKey::Ecies(k) => {
				let key = Base64::encode_string(k.as_ref());

				Self::Ecies {
					key,
					key_id: value.key_id.clone(),
				}
			},
			CoreSecretKey::Kyber(k) => {
				let key = Base64::encode_string(k.as_ref());

				Self::Kyber {
					key,
					key_id: value.key_id.clone(),
				}
			},
			CoreSecretKey::EciesKyberHybrid(key) => {
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
to_string_impl!(PublicKey, PublicKeyFormatExport);
from_string_impl!(PublicKey, PublicKeyFormatExport);
pk_user_pk!(PublicKey, import_public_key_from_pem_with_alg);

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

//__________________________________________________________________________________________________

pub struct SignKey
{
	pub key: CoreSignKey,
	pub key_id: SignKeyPairId,
}

wrapper_impl!(SignKWrapper, SignKey, CoreSignKey);
to_string_impl!(SignKey, SignKeyFormatExport);
from_string_impl!(SignKey, SignKeyFormatExport);
sign_key_pair_self!(SignKey, CoreSignKey, export_raw_verify_key_to_pem, sig_to_string);
sign_key_composer_self!(
	SignKey,
	CoreSignKey,
	VerifyKey,
	CoreVerifyKey,
	import_verify_key_from_pem_with_alg,
	import_sig_from_string,
	sig_to_string
);

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

impl<'a> From<&'a SignKey> for SignKeyFormatExport
{
	fn from(value: &'a SignKey) -> Self
	{
		match &value.key {
			CoreSignKey::Ed25519(k) => {
				let key = Base64::encode_string(k.as_ref());

				Self::Ed25519 {
					key,
					key_id: value.key_id.clone(),
				}
			},
			CoreSignKey::Dilithium(k) => {
				let key = Base64::encode_string(k.as_ref());

				Self::Dilithium {
					key,
					key_id: value.key_id.clone(),
				}
			},
			CoreSignKey::Ed25519DilithiumHybrid(key) => {
				let (x, k) = key.get_raw_keys();

				let x = Base64::encode_string(x);
				let k = Base64::encode_string(k);

				Self::Ed25519DilithiumHybrid {
					x,
					k,
					key_id: value.key_id.clone(),
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
to_string_impl!(VerifyKey, VerifyKeyFormatExport);
from_string_impl!(VerifyKey, VerifyKeyFormatExport);
vk_user_vk!(VerifyKey, import_verify_key_from_pem_with_alg);

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

impl<'a> From<&'a VerifyKey> for VerifyKeyFormatExport
{
	fn from(value: &'a VerifyKey) -> Self
	{
		match &value.key {
			CoreVerifyKey::Ed25519(k) => {
				let key = Base64::encode_string(k.as_ref());

				Self::Ed25519 {
					key_id: value.key_id.clone(),
					key,
				}
			},
			CoreVerifyKey::Dilithium(k) => {
				let key = Base64::encode_string(k.as_ref());

				Self::Dilithium {
					key_id: value.key_id.clone(),
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
					key_id: value.key_id.clone(),
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
