use alloc::string::String;
use core::str::FromStr;

use base64ct::{Base64, Encoding};
use sentc_crypto_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto_common::{EncryptionKeyPairId, SignKeyPairId, SymKeyId};
use sentc_crypto_core::{HmacKey, Pk, SignK, Sk, SortableKey, SymKey, VerifyK, ECIES_OUTPUT};
use serde::{Deserialize, Serialize};

use crate::error::SdkUtilError;
use crate::import_key_from_pem;

pub struct SymKeyFormatInt
{
	pub key: SymKey,
	pub key_id: SymKeyId,
}

impl SymKeyFormatInt
{
	pub fn to_string(self) -> Result<String, SdkUtilError>
	{
		serde_json::to_string(&Into::<SymKeyFormatExport>::into(self)).map_err(|_e| SdkUtilError::JsonToStringFailed)
	}
}

pub struct HmacKeyFormatInt
{
	pub key_id: SymKeyId,
	pub key: HmacKey,
}

impl HmacKeyFormatInt
{
	pub fn to_string(self) -> Result<String, SdkUtilError>
	{
		serde_json::to_string(&Into::<HmacFormatExport>::into(self)).map_err(|_e| SdkUtilError::JsonToStringFailed)
	}
}

pub struct SortableKeyFormatInt
{
	pub key_id: SymKeyId,
	pub key: SortableKey,
}

impl SortableKeyFormatInt
{
	pub fn to_string(self) -> Result<String, SdkUtilError>
	{
		serde_json::to_string(&Into::<SortableFormatExport>::into(self)).map_err(|_e| SdkUtilError::JsonToStringFailed)
	}
}

pub struct PrivateKeyFormatInt
{
	pub key: Sk,
	pub key_id: EncryptionKeyPairId,
}

impl PrivateKeyFormatInt
{
	pub fn to_string(self) -> Result<String, SdkUtilError>
	{
		serde_json::to_string(&Into::<PrivateKeyFormatExport>::into(self)).map_err(|_e| SdkUtilError::JsonToStringFailed)
	}
}

pub struct PublicKeyFormatInt
{
	pub key: Pk,
	pub key_id: EncryptionKeyPairId,
}

impl PublicKeyFormatInt
{
	pub fn to_string(self) -> Result<String, SdkUtilError>
	{
		serde_json::to_string(&Into::<PublicKeyFormatExport>::into(self)).map_err(|_e| SdkUtilError::JsonToStringFailed)
	}
}

pub struct SignKeyFormatInt
{
	pub key: SignK,
	pub key_id: SignKeyPairId,
}

impl SignKeyFormatInt
{
	pub fn to_string(self) -> Result<String, SdkUtilError>
	{
		serde_json::to_string(&Into::<SignKeyFormatExport>::into(self)).map_err(|_e| SdkUtilError::JsonToStringFailed)
	}
}

pub struct VerifyKeyFormatInt
{
	pub key: VerifyK,
	pub key_id: SignKeyPairId,
}

impl VerifyKeyFormatInt
{
	pub fn to_string(self) -> Result<String, SdkUtilError>
	{
		serde_json::to_string(&Into::<VerifyKeyFormatExport>::into(self)).map_err(|_e| SdkUtilError::JsonToStringFailed)
	}
}

//==================================================================================================
//exported keys

#[derive(Serialize, Deserialize)]
pub enum SymKeyFormatExport
{
	Aes
	{
		key: String, key_id: SymKeyId
	},
}

impl TryInto<SymKeyFormatInt> for SymKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<SymKeyFormatInt, Self::Error>
	{
		match self {
			SymKeyFormatExport::Aes {
				key,
				key_id,
			} => {
				//to bytes via base64
				let bytes = Base64::decode_vec(&key).map_err(|_| SdkUtilError::ImportSymmetricKeyFailed)?;

				let key = bytes
					.try_into()
					.map_err(|_| SdkUtilError::ImportSymmetricKeyFailed)?;

				Ok(SymKeyFormatInt {
					key_id,
					key: SymKey::Aes(key),
				})
			},
		}
	}
}

impl<'a> TryInto<SymKeyFormatInt> for &'a SymKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<SymKeyFormatInt, Self::Error>
	{
		match self {
			SymKeyFormatExport::Aes {
				key,
				key_id,
			} => {
				//to bytes via base64
				let bytes = Base64::decode_vec(key).map_err(|_| SdkUtilError::ImportSymmetricKeyFailed)?;

				let key = bytes
					.try_into()
					.map_err(|_| SdkUtilError::ImportSymmetricKeyFailed)?;

				Ok(SymKeyFormatInt {
					key_id: key_id.clone(),
					key: SymKey::Aes(key),
				})
			},
		}
	}
}

impl From<SymKeyFormatInt> for SymKeyFormatExport
{
	fn from(value: SymKeyFormatInt) -> Self
	{
		match value.key {
			SymKey::Aes(k) => {
				let sym_key = Base64::encode_string(&k);

				Self::Aes {
					key_id: value.key_id,
					key: sym_key,
				}
			},
		}
	}
}

impl FromStr for SymKeyFormatInt
{
	type Err = SdkUtilError;

	fn from_str(s: &str) -> Result<Self, Self::Err>
	{
		let key: SymKeyFormatExport = serde_json::from_str(s).map_err(|_| SdkUtilError::ImportSymmetricKeyFailed)?;

		key.try_into()
	}
}

//__________________________________________________________________________________________________

#[derive(Serialize, Deserialize)]
pub enum HmacFormatExport
{
	HmacSha256
	{
		key: String, key_id: SymKeyId
	},
}

impl TryInto<HmacKeyFormatInt> for HmacFormatExport
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<HmacKeyFormatInt, Self::Error>
	{
		match self {
			HmacFormatExport::HmacSha256 {
				key,
				key_id,
			} => {
				let bytes = Base64::decode_vec(&key).map_err(|_| SdkUtilError::ImportSymmetricKeyFailed)?;

				let key = bytes
					.try_into()
					.map_err(|_| SdkUtilError::ImportSymmetricKeyFailed)?;

				Ok(HmacKeyFormatInt {
					key: HmacKey::HmacSha256(key),
					key_id,
				})
			},
		}
	}
}

impl From<HmacKeyFormatInt> for HmacFormatExport
{
	fn from(value: HmacKeyFormatInt) -> Self
	{
		match value.key {
			HmacKey::HmacSha256(k) => {
				let key = Base64::encode_string(&k);

				Self::HmacSha256 {
					key,
					key_id: value.key_id,
				}
			},
		}
	}
}

impl FromStr for HmacKeyFormatInt
{
	type Err = SdkUtilError;

	fn from_str(s: &str) -> Result<Self, Self::Err>
	{
		let key: HmacFormatExport = serde_json::from_str(s).map_err(|_| SdkUtilError::ImportSymmetricKeyFailed)?;

		key.try_into()
	}
}

//__________________________________________________________________________________________________

#[derive(Serialize, Deserialize)]
pub enum SortableFormatExport
{
	Ope16
	{
		key: String, key_id: SymKeyId
	},
}

impl TryInto<SortableKeyFormatInt> for SortableFormatExport
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<SortableKeyFormatInt, Self::Error>
	{
		match self {
			SortableFormatExport::Ope16 {
				key,
				key_id,
			} => {
				let bytes = Base64::decode_vec(&key).map_err(|_| SdkUtilError::ImportSymmetricKeyFailed)?;

				let key = bytes
					.try_into()
					.map_err(|_| SdkUtilError::ImportSymmetricKeyFailed)?;

				Ok(SortableKeyFormatInt {
					key: SortableKey::Ope(key),
					key_id,
				})
			},
		}
	}
}

impl From<SortableKeyFormatInt> for SortableFormatExport
{
	fn from(value: SortableKeyFormatInt) -> Self
	{
		match value.key {
			SortableKey::Ope(k) => {
				let key = Base64::encode_string(&k);

				Self::Ope16 {
					key,
					key_id: value.key_id,
				}
			},
		}
	}
}

impl FromStr for SortableKeyFormatInt
{
	type Err = SdkUtilError;

	fn from_str(s: &str) -> Result<Self, Self::Err>
	{
		let key: SortableFormatExport = serde_json::from_str(s).map_err(|_| SdkUtilError::ImportSymmetricKeyFailed)?;

		key.try_into()
	}
}

//__________________________________________________________________________________________________

#[derive(Serialize, Deserialize)]
pub enum PrivateKeyFormatExport
{
	Ecies
	{
		key: String, key_id: EncryptionKeyPairId
	},
}

impl TryInto<PrivateKeyFormatInt> for PrivateKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<PrivateKeyFormatInt, Self::Error>
	{
		match self {
			PrivateKeyFormatExport::Ecies {
				key_id,
				key,
			} => {
				//to bytes via base64
				let bytes = Base64::decode_vec(&key).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;

				let private_key: [u8; 32] = bytes
					.try_into()
					.map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;

				Ok(PrivateKeyFormatInt {
					key_id,
					key: Sk::Ecies(private_key),
				})
			},
		}
	}
}

impl From<PrivateKeyFormatInt> for PrivateKeyFormatExport
{
	fn from(value: PrivateKeyFormatInt) -> Self
	{
		match value.key {
			Sk::Ecies(k) => {
				let key = Base64::encode_string(&k);

				Self::Ecies {
					key_id: value.key_id,
					key,
				}
			},
		}
	}
}

impl FromStr for PrivateKeyFormatInt
{
	type Err = SdkUtilError;

	fn from_str(s: &str) -> Result<Self, Self::Err>
	{
		let key: PrivateKeyFormatExport = serde_json::from_str(s).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;

		key.try_into()
	}
}

//__________________________________________________________________________________________________

#[derive(Serialize, Deserialize)]
pub enum PublicKeyFormatExport
{
	Ecies
	{
		key: String, key_id: EncryptionKeyPairId
	},
}

impl TryInto<PublicKeyFormatInt> for PublicKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<PublicKeyFormatInt, Self::Error>
	{
		match self {
			PublicKeyFormatExport::Ecies {
				key,
				key_id,
			} => {
				let bytes = Base64::decode_vec(&key).map_err(|_| SdkUtilError::ImportPublicKeyFailed)?;

				let key = bytes
					.try_into()
					.map_err(|_| SdkUtilError::ImportPublicKeyFailed)?;

				Ok(PublicKeyFormatInt {
					key_id,
					key: Pk::Ecies(key),
				})
			},
		}
	}
}

impl From<PublicKeyFormatInt> for PublicKeyFormatExport
{
	fn from(value: PublicKeyFormatInt) -> Self
	{
		match value.key {
			Pk::Ecies(k) => {
				let key = Base64::encode_string(&k);

				Self::Ecies {
					key_id: value.key_id,
					key,
				}
			},
		}
	}
}

impl FromStr for PublicKeyFormatInt
{
	type Err = SdkUtilError;

	fn from_str(s: &str) -> Result<Self, Self::Err>
	{
		let key: PublicKeyFormatExport = serde_json::from_str(s).map_err(|_| SdkUtilError::ImportPublicKeyFailed)?;

		key.try_into()
	}
}

impl<'a> TryFrom<&'a UserPublicKeyData> for PublicKeyFormatInt
{
	type Error = SdkUtilError;

	fn try_from(value: &'a UserPublicKeyData) -> Result<Self, Self::Error>
	{
		let public_key = import_key_from_pem(&value.public_key_pem)?;

		match value.public_key_alg.as_str() {
			ECIES_OUTPUT => {
				let public_key = public_key
					.try_into()
					.map_err(|_| SdkUtilError::DecodePublicKeyFailed)?;

				Ok(Self {
					key_id: value.public_key_id.clone(),
					key: Pk::Ecies(public_key),
				})
			},
			_ => Err(SdkUtilError::AlgNotFound),
		}
	}
}

//__________________________________________________________________________________________________

#[derive(Serialize, Deserialize)]
pub enum SignKeyFormatExport
{
	Ed25519
	{
		key: String, key_id: SignKeyPairId
	},
}

impl TryInto<SignKeyFormatInt> for SignKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<SignKeyFormatInt, Self::Error>
	{
		match self {
			SignKeyFormatExport::Ed25519 {
				key,
				key_id,
			} => {
				let bytes = Base64::decode_vec(&key).map_err(|_| SdkUtilError::ImportingSignKeyFailed)?;

				let sign_key: [u8; 32] = bytes
					.try_into()
					.map_err(|_| SdkUtilError::ImportingSignKeyFailed)?;

				Ok(SignKeyFormatInt {
					key_id,
					key: SignK::Ed25519(sign_key),
				})
			},
		}
	}
}

impl From<SignKeyFormatInt> for SignKeyFormatExport
{
	fn from(value: SignKeyFormatInt) -> Self
	{
		match value.key {
			SignK::Ed25519(k) => {
				let key = Base64::encode_string(&k);

				Self::Ed25519 {
					key_id: value.key_id,
					key,
				}
			},
		}
	}
}

impl FromStr for SignKeyFormatInt
{
	type Err = SdkUtilError;

	fn from_str(s: &str) -> Result<Self, Self::Err>
	{
		let key: SignKeyFormatExport = serde_json::from_str(s).map_err(|_| SdkUtilError::ImportingSignKeyFailed)?;

		key.try_into()
	}
}

//__________________________________________________________________________________________________

#[derive(Serialize, Deserialize)]
pub enum VerifyKeyFormatExport
{
	Ed25519
	{
		key: String, key_id: SignKeyPairId
	},
}

impl TryInto<VerifyKeyFormatInt> for VerifyKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<VerifyKeyFormatInt, Self::Error>
	{
		match self {
			VerifyKeyFormatExport::Ed25519 {
				key,
				key_id,
			} => {
				let bytes = Base64::decode_vec(&key).map_err(|_| SdkUtilError::ImportVerifyKeyFailed)?;

				let verify_key: [u8; 32] = bytes
					.try_into()
					.map_err(|_| SdkUtilError::ImportVerifyKeyFailed)?;

				Ok(VerifyKeyFormatInt {
					key: VerifyK::Ed25519(verify_key),
					key_id,
				})
			},
		}
	}
}

impl From<VerifyKeyFormatInt> for VerifyKeyFormatExport
{
	fn from(value: VerifyKeyFormatInt) -> Self
	{
		match value.key {
			VerifyK::Ed25519(k) => {
				let key = Base64::encode_string(&k);

				Self::Ed25519 {
					key_id: value.key_id,
					key,
				}
			},
		}
	}
}

impl FromStr for VerifyKeyFormatInt
{
	type Err = SdkUtilError;

	fn from_str(s: &str) -> Result<Self, Self::Err>
	{
		let key: VerifyKeyFormatExport = serde_json::from_str(s).map_err(|_| SdkUtilError::ImportingSignKeyFailed)?;

		key.try_into()
	}
}

impl<'a> TryFrom<&'a UserVerifyKeyData> for VerifyKeyFormatInt
{
	type Error = SdkUtilError;

	fn try_from(value: &'a UserVerifyKeyData) -> Result<Self, Self::Error>
	{
		let verify_key = import_key_from_pem(&value.verify_key_pem)?;

		match value.verify_key_alg.as_str() {
			ECIES_OUTPUT => {
				let verify_key = verify_key
					.try_into()
					.map_err(|_| SdkUtilError::DecodePublicKeyFailed)?;

				Ok(Self {
					key_id: value.verify_key_id.clone(),
					key: VerifyK::Ed25519(verify_key),
				})
			},
			_ => Err(SdkUtilError::AlgNotFound),
		}
	}
}

//__________________________________________________________________________________________________

/**
This key is used if the user enabled mfa and we need more data of the user for login.
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

impl TryInto<sentc_crypto_core::DeriveMasterKeyForAuth> for MasterKeyFormat
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<sentc_crypto_core::DeriveMasterKeyForAuth, Self::Error>
	{
		match self {
			MasterKeyFormat::Argon2(mk) => {
				let mk = Base64::decode_vec(mk.as_str()).map_err(|_e| SdkUtilError::ImportAuthMasterKeyFailed)?;
				let master_key_encryption_key: [u8; 32] = mk
					.try_into()
					.map_err(|_e| SdkUtilError::ImportAuthMasterKeyFailed)?;

				Ok(sentc_crypto_core::DeriveMasterKeyForAuth::Argon2(
					master_key_encryption_key,
				))
			},
		}
	}
}

impl From<sentc_crypto_core::DeriveMasterKeyForAuth> for MasterKeyFormat
{
	fn from(value: sentc_crypto_core::DeriveMasterKeyForAuth) -> Self
	{
		match value {
			sentc_crypto_core::DeriveMasterKeyForAuth::Argon2(k) => {
				let key = Base64::encode_string(&k);

				Self::Argon2(key)
			},
		}
	}
}
