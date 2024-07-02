#[cfg(feature = "full")]
mod crypto;
mod export;

use std::str::FromStr;

use openssl::base64::{decode_block, encode_block};
use sentc_crypto_common::{EncryptionKeyPairId, SignKeyPairId, SymKeyId};
use sentc_crypto_core::cryptomat::SignK;
#[cfg(feature = "full")]
pub use sentc_crypto_fips_keys::util::HmacKey;
use sentc_crypto_utils::cryptomat::{PkWrapper, SignKWrapper, SkWrapper, SymKeyWrapper, VerifyKWrapper};
use sentc_crypto_utils::error::SdkUtilError;
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
	to_string_try_impl,
	vk_user_vk,
	wrapper_impl,
};
use serde::{Deserialize, Serialize};

use crate::core::asym::{PublicKey as CorePk, SecretKey as CoreSk};
use crate::core::sign::{SignKey as CoreSign, VerifyKey as CoreVk};
use crate::core::sym::Aes256GcmKey;
#[cfg(feature = "full")]
pub use crate::util::crypto::SortableKey;
use crate::util::export::{
	export_raw_public_key_to_pem,
	export_raw_verify_key_to_pem,
	import_public_key_from_pem_with_alg,
	import_sig_from_string,
	import_verify_key_from_pem_with_alg,
	sig_to_string,
};

pub struct SymmetricKey
{
	pub key: Aes256GcmKey,
	pub key_id: SymKeyId,
}

wrapper_impl!(SymKeyWrapper, SymmetricKey, Aes256GcmKey);
to_string_impl!(SymmetricKey, SymKeyFormatExport);
from_string_impl!(SymmetricKey, SymKeyFormatExport);
sym_key_gen_self!(SymmetricKey, Aes256GcmKey);
sym_key_com_self!(SymmetricKey, Aes256GcmKey);

#[derive(Serialize, Deserialize)]
pub struct SymKeyFormatExport
{
	key: String,
	key_id: SymKeyId,
}

impl From<SymmetricKey> for SymKeyFormatExport
{
	fn from(value: SymmetricKey) -> Self
	{
		let key = encode_block(value.key.as_ref());

		Self {
			key,
			key_id: value.key_id,
		}
	}
}

impl TryInto<SymmetricKey> for SymKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<SymmetricKey, Self::Error>
	{
		let bytes = decode_block(&self.key).map_err(|_| SdkUtilError::ImportSymmetricKeyFailed)?;

		Ok(SymmetricKey {
			key: Aes256GcmKey::try_from(bytes)?,
			key_id: self.key_id,
		})
	}
}

impl<'a> TryInto<SymmetricKey> for &'a SymKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<SymmetricKey, Self::Error>
	{
		let bytes = decode_block(&self.key).map_err(|_| SdkUtilError::ImportSymmetricKeyFailed)?;

		Ok(SymmetricKey {
			key: Aes256GcmKey::try_from(bytes)?,
			key_id: self.key_id.clone(),
		})
	}
}

//__________________________________________________________________________________________________

pub struct SecretKey
{
	pub key: CoreSk,
	pub key_id: EncryptionKeyPairId,
}

to_string_try_impl!(SecretKey, SecretKeyFormatExport);
from_string_impl!(SecretKey, SecretKeyFormatExport);
static_key_pair_self!(SecretKey, CoreSk, PublicKey, export_raw_public_key_to_pem);
static_key_composer_self!(
	SecretKey,
	CoreSk,
	PublicKey,
	CorePk,
	import_public_key_from_pem_with_alg
);
wrapper_impl!(SkWrapper, SecretKey, CoreSk);

#[derive(Serialize, Deserialize)]
pub enum SecretKeyFormatExport
{
	Ecies
	{
		key: String, key_id: EncryptionKeyPairId
	},
	MlKem
	{
		key: String, key_id: EncryptionKeyPairId
	},
	EciesMlKemHybrid
	{
		x: String, k: String, key_id: EncryptionKeyPairId
	},
}

impl TryFrom<SecretKey> for SecretKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_from(value: SecretKey) -> Result<Self, Self::Error>
	{
		match value.key {
			CoreSk::Ecies(k) => {
				let key = encode_block(&k.export()?);

				Ok(Self::Ecies {
					key,
					key_id: value.key_id,
				})
			},
			CoreSk::MlKem(k) => {
				let key = encode_block(k.as_ref());

				Ok(Self::MlKem {
					key,
					key_id: value.key_id,
				})
			},
			CoreSk::EciesMlKemHybrid(k) => {
				let (x, k) = k.prepare_export()?;

				let x = encode_block(&x);
				let k = encode_block(k);

				Ok(Self::EciesMlKemHybrid {
					k,
					x,
					key_id: value.key_id.clone(),
				})
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
				let bytes = decode_block(&key).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;

				Ok(SecretKey {
					key_id,
					key: CoreSk::ecies_from_bytes_owned(bytes)?,
				})
			},
			Self::MlKem {
				key,
				key_id,
			} => {
				let bytes = decode_block(&key).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;

				Ok(SecretKey {
					key_id,
					key: CoreSk::ml_kem_from_bytes_owned(bytes),
				})
			},
			Self::EciesMlKemHybrid {
				x,
				k,
				key_id,
			} => {
				let bytes_x = decode_block(&x).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;
				let bytes_k = decode_block(&k).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;

				Ok(SecretKey {
					key_id,
					key: CoreSk::ecies_ml_kem_hybrid_from_bytes_owned(bytes_x, bytes_k)?,
				})
			},
		}
	}
}

//__________________________________________________________________________________________________

#[derive(Serialize, Deserialize)]
pub struct HybridPublicKeyExportFormat
{
	pub x: String,
	pub k: String,
}

#[derive(Clone)]
pub struct PublicKey
{
	pub key: CorePk,
	pub key_id: EncryptionKeyPairId,
}

to_string_try_impl!(PublicKey, PublicKeyFormatExport);
from_string_impl!(PublicKey, PublicKeyFormatExport);
pk_user_pk!(PublicKey, import_public_key_from_pem_with_alg);
wrapper_impl!(PkWrapper, PublicKey, CorePk);

#[derive(Serialize, Deserialize)]
pub enum PublicKeyFormatExport
{
	Ecies
	{
		key: String, key_id: EncryptionKeyPairId
	},

	MlKem
	{
		key: String, key_id: EncryptionKeyPairId
	},

	EciesMlKemHybrid
	{
		x: String, k: String, key_id: EncryptionKeyPairId
	},
}

impl TryFrom<PublicKey> for PublicKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_from(value: PublicKey) -> Result<Self, Self::Error>
	{
		match value.key {
			CorePk::Ecies(k) => {
				let key = encode_block(&k.export()?);

				Ok(Self::Ecies {
					key,
					key_id: value.key_id,
				})
			},
			CorePk::MlKem(k) => {
				let key = encode_block(k.as_ref());

				Ok(Self::MlKem {
					key,
					key_id: value.key_id,
				})
			},
			CorePk::EciesMlKemHybrid(k) => {
				let (x, k) = k.prepare_export()?;

				let x = encode_block(&x);
				let k = encode_block(k);

				Ok(Self::EciesMlKemHybrid {
					x,
					k,
					key_id: value.key_id,
				})
			},
		}
	}
}

impl<'a> TryFrom<&'a PublicKey> for PublicKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_from(value: &'a PublicKey) -> Result<Self, Self::Error>
	{
		match &value.key {
			CorePk::Ecies(k) => {
				let key = encode_block(&k.export()?);

				Ok(Self::Ecies {
					key,
					key_id: value.key_id.clone(),
				})
			},
			CorePk::MlKem(k) => {
				let key = encode_block(k.as_ref());

				Ok(Self::MlKem {
					key,
					key_id: value.key_id.clone(),
				})
			},
			CorePk::EciesMlKemHybrid(k) => {
				let (x, k) = k.prepare_export()?;

				let x = encode_block(&x);
				let k = encode_block(k);

				Ok(Self::EciesMlKemHybrid {
					x,
					k,
					key_id: value.key_id.clone(),
				})
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
				let bytes = decode_block(&key).map_err(|_| SdkUtilError::ImportPublicKeyFailed)?;

				Ok(PublicKey {
					key: CorePk::ecies_from_bytes_owned(bytes)?,
					key_id,
				})
			},
			Self::MlKem {
				key_id,
				key,
			} => {
				let bytes = decode_block(&key).map_err(|_| SdkUtilError::ImportPublicKeyFailed)?;

				Ok(PublicKey {
					key: CorePk::ml_kem_from_bytes_owned(bytes),
					key_id,
				})
			},
			Self::EciesMlKemHybrid {
				key_id,
				x,
				k,
			} => {
				let bytes_x = decode_block(&x).map_err(|_| SdkUtilError::ImportPublicKeyFailed)?;
				let bytes_k = decode_block(&k).map_err(|_| SdkUtilError::ImportPublicKeyFailed)?;

				Ok(PublicKey {
					key_id,
					key: CorePk::ecies_ml_kem_hybrid_from_bytes_owned(bytes_x, bytes_k)?,
				})
			},
		}
	}
}

//__________________________________________________________________________________________________

pub struct SignKey
{
	pub key: CoreSign,
	pub key_id: SignKeyPairId,
}
wrapper_impl!(SignKWrapper, SignKey, CoreSign);
from_string_impl!(SignKey, SignKeyFormatExport);
to_string_try_impl!(SignKey, SignKeyFormatExport);
sign_key_pair_self!(SignKey, CoreSign, export_raw_verify_key_to_pem, sig_to_string);
sign_key_composer_self!(
	SignKey,
	CoreSign,
	VerifyKey,
	CoreVk,
	import_verify_key_from_pem_with_alg,
	import_sig_from_string
);

#[derive(Serialize, Deserialize)]
pub enum SignKeyFormatExport
{
	Ed25519
	{
		key: String, key_id: SignKeyPairId
	},

	MlDsa
	{
		key: String, key_id: SignKeyPairId
	},

	Ed25519MlDsaHybrid
	{
		x: String, k: String, key_id: SignKeyPairId
	},
}

impl TryFrom<SignKey> for SignKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_from(value: SignKey) -> Result<Self, Self::Error>
	{
		match value.key {
			CoreSign::Ed25519(k) => {
				let key = encode_block(&k.export()?);

				Ok(Self::Ed25519 {
					key,
					key_id: value.key_id,
				})
			},
			CoreSign::MlDsa(k) => {
				let key = encode_block(k.as_ref());

				Ok(Self::MlDsa {
					key,
					key_id: value.key_id,
				})
			},
			CoreSign::Ed25519MlDsaHybrid(k) => {
				let (x, k) = k.prepare_export()?;

				let x = encode_block(&x);
				let k = encode_block(k);

				Ok(Self::Ed25519MlDsaHybrid {
					x,
					k,
					key_id: value.key_id,
				})
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
				let bytes = decode_block(&key).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;

				Ok(SignKey {
					key_id,
					key: CoreSign::ed25519_from_bytes_owned(bytes)?,
				})
			},
			Self::MlDsa {
				key,
				key_id,
			} => {
				let bytes = decode_block(&key).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;

				Ok(SignKey {
					key_id,
					key: CoreSign::ml_dsa_from_bytes_owned(bytes),
				})
			},
			Self::Ed25519MlDsaHybrid {
				x,
				k,
				key_id,
			} => {
				let bytes_x = decode_block(&x).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;
				let bytes_k = decode_block(&k).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;

				Ok(SignKey {
					key_id,
					key: CoreSign::ed25519_ml_dsa_hybrid_from_bytes_owned(bytes_x, bytes_k)?,
				})
			},
		}
	}
}

//__________________________________________________________________________________________________

pub struct VerifyKey
{
	pub key: CoreVk,
	pub key_id: SignKeyPairId,
}

wrapper_impl!(VerifyKWrapper, VerifyKey, CoreVk);
to_string_try_impl!(VerifyKey, VerifyKeyFormatExport);
from_string_impl!(VerifyKey, VerifyKeyFormatExport);
vk_user_vk!(VerifyKey, import_verify_key_from_pem_with_alg);

#[derive(Serialize, Deserialize)]
pub enum VerifyKeyFormatExport
{
	Ed25519
	{
		key: String, key_id: SignKeyPairId
	},

	MlDsa
	{
		key: String, key_id: SignKeyPairId
	},

	Ed25519MlDsaHybrid
	{
		x: String, k: String, key_id: SignKeyPairId
	},
}

impl TryFrom<VerifyKey> for VerifyKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_from(value: VerifyKey) -> Result<Self, Self::Error>
	{
		match value.key {
			CoreVk::Ed25519(k) => {
				let key = encode_block(&k.export()?);

				Ok(Self::Ed25519 {
					key,
					key_id: value.key_id.clone(),
				})
			},
			CoreVk::MlDsa(k) => {
				let key = encode_block(k.as_ref());

				Ok(Self::MlDsa {
					key,
					key_id: value.key_id.clone(),
				})
			},
			CoreVk::Ed25519MlDsaHybrid(k) => {
				let (x, k) = k.prepare_export()?;

				let x = encode_block(&x);
				let k = encode_block(k);

				Ok(Self::Ed25519MlDsaHybrid {
					x,
					k,
					key_id: value.key_id.clone(),
				})
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
				key_id,
				key,
			} => {
				let bytes = decode_block(&key).map_err(|_| SdkUtilError::ImportPublicKeyFailed)?;

				Ok(VerifyKey {
					key: CoreVk::ed25519_from_bytes_owned(bytes)?,
					key_id,
				})
			},
			Self::MlDsa {
				key_id,
				key,
			} => {
				let bytes = decode_block(&key).map_err(|_| SdkUtilError::ImportPublicKeyFailed)?;

				Ok(VerifyKey {
					key: CoreVk::ml_dsa_from_bytes_owned(bytes),
					key_id,
				})
			},
			Self::Ed25519MlDsaHybrid {
				key_id,
				x,
				k,
			} => {
				let bytes_x = decode_block(&x).map_err(|_| SdkUtilError::ImportPublicKeyFailed)?;
				let bytes_k = decode_block(&k).map_err(|_| SdkUtilError::ImportPublicKeyFailed)?;

				Ok(VerifyKey {
					key_id,
					key: CoreVk::ed25519_ml_dsa_hybrid_from_bytes_owned(bytes_x, bytes_k)?,
				})
			},
		}
	}
}
