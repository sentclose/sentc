use alloc::string::String;
use core::str::FromStr;

use base64ct::{Base64, Encoding};
use sentc_crypto_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto_common::{EncryptionKeyPairId, SignKeyPairId, SymKeyId};
use sentc_crypto_core::{HmacKey, Pk, SignK, Sk, SymKey, VerifyK, ECIES_OUTPUT};
use serde::{Deserialize, Serialize};

use crate::util::import_key_from_pem;
use crate::SdkError;

pub struct SymKeyFormatInt
{
	pub key: SymKey,
	pub key_id: SymKeyId,
}

impl SymKeyFormatInt
{
	pub fn to_string(self) -> Result<String, SdkError>
	{
		match self.key {
			SymKey::Aes(k) => {
				let sym_key = Base64::encode_string(&k);

				let key = SymKeyFormatExport::Aes {
					key_id: self.key_id,
					key: sym_key,
				};

				serde_json::to_string(&key).map_err(|_e| SdkError::JsonToStringFailed)
			},
		}
	}
}

pub struct HmacKeyFormatInt
{
	pub key_id: SymKeyId,
	pub key: HmacKey,
}

impl HmacKeyFormatInt
{
	pub fn to_string(self) -> Result<String, SdkError>
	{
		match self.key {
			HmacKey::HmacSha256(k) => {
				let key = Base64::encode_string(&k);

				let key = HmacFormatExport::HmacSha256 {
					key,
					key_id: self.key_id,
				};

				serde_json::to_string(&key).map_err(|_e| SdkError::JsonToStringFailed)
			},
		}
	}
}

pub struct PrivateKeyFormatInt
{
	pub key: Sk,
	pub key_id: EncryptionKeyPairId,
}

impl PrivateKeyFormatInt
{
	pub fn to_string(self) -> Result<String, SdkError>
	{
		match self.key {
			Sk::Ecies(k) => {
				let key = Base64::encode_string(&k);

				let key = PrivateKeyFormatExport::Ecies {
					key_id: self.key_id,
					key,
				};

				serde_json::to_string(&key).map_err(|_e| SdkError::JsonToStringFailed)
			},
		}
	}
}

pub struct PublicKeyFormatInt
{
	pub key: Pk,
	pub key_id: EncryptionKeyPairId,
}

impl PublicKeyFormatInt
{
	pub fn to_string(self) -> Result<String, SdkError>
	{
		match self.key {
			Pk::Ecies(k) => {
				let key = Base64::encode_string(&k);

				let key = PublicKeyFormatExport::Ecies {
					key_id: self.key_id,
					key,
				};

				serde_json::to_string(&key).map_err(|_e| SdkError::JsonToStringFailed)
			},
		}
	}
}

pub struct SignKeyFormatInt
{
	pub key: SignK,
	pub key_id: SignKeyPairId,
}

impl SignKeyFormatInt
{
	pub fn to_string(self) -> Result<String, SdkError>
	{
		match self.key {
			SignK::Ed25519(k) => {
				let key = Base64::encode_string(&k);

				let key = SignKeyFormatExport::Ed25519 {
					key_id: self.key_id,
					key,
				};

				serde_json::to_string(&key).map_err(|_e| SdkError::JsonToStringFailed)
			},
		}
	}
}

pub struct VerifyKeyFormatInt
{
	pub key: VerifyK,
	pub key_id: SignKeyPairId,
}

impl VerifyKeyFormatInt
{
	pub fn to_string(self) -> Result<String, SdkError>
	{
		match self.key {
			VerifyK::Ed25519(k) => {
				let key = Base64::encode_string(&k);

				let key = VerifyKeyFormatExport::Ed25519 {
					key_id: self.key_id,
					key,
				};

				serde_json::to_string(&key).map_err(|_e| SdkError::JsonToStringFailed)
			},
		}
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
	type Error = SdkError;

	fn try_into(self) -> Result<SymKeyFormatInt, Self::Error>
	{
		match self {
			SymKeyFormatExport::Aes {
				key,
				key_id,
			} => {
				//to bytes via base64
				let bytes = Base64::decode_vec(&key).map_err(|_| SdkError::ImportSymmetricKeyFailed)?;

				let key = bytes
					.try_into()
					.map_err(|_| SdkError::ImportSymmetricKeyFailed)?;

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
	type Error = SdkError;

	fn try_into(self) -> Result<SymKeyFormatInt, Self::Error>
	{
		match self {
			SymKeyFormatExport::Aes {
				key,
				key_id,
			} => {
				//to bytes via base64
				let bytes = Base64::decode_vec(key).map_err(|_| SdkError::ImportSymmetricKeyFailed)?;

				let key = bytes
					.try_into()
					.map_err(|_| SdkError::ImportSymmetricKeyFailed)?;

				Ok(SymKeyFormatInt {
					key_id: key_id.clone(),
					key: SymKey::Aes(key),
				})
			},
		}
	}
}

impl FromStr for SymKeyFormatInt
{
	type Err = SdkError;

	fn from_str(s: &str) -> Result<Self, Self::Err>
	{
		let key: SymKeyFormatExport = serde_json::from_str(s).map_err(|_| SdkError::ImportSymmetricKeyFailed)?;

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
	type Error = SdkError;

	fn try_into(self) -> Result<HmacKeyFormatInt, Self::Error>
	{
		match self {
			HmacFormatExport::HmacSha256 {
				key,
				key_id,
			} => {
				let bytes = Base64::decode_vec(&key).map_err(|_| SdkError::ImportSymmetricKeyFailed)?;

				let key = bytes
					.try_into()
					.map_err(|_| SdkError::ImportSymmetricKeyFailed)?;

				Ok(HmacKeyFormatInt {
					key: HmacKey::HmacSha256(key),
					key_id,
				})
			},
		}
	}
}

impl FromStr for HmacKeyFormatInt
{
	type Err = SdkError;

	fn from_str(s: &str) -> Result<Self, Self::Err>
	{
		let key: HmacFormatExport = serde_json::from_str(s).map_err(|_| SdkError::ImportSymmetricKeyFailed)?;

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
	type Error = SdkError;

	fn try_into(self) -> Result<PrivateKeyFormatInt, Self::Error>
	{
		match self {
			PrivateKeyFormatExport::Ecies {
				key_id,
				key,
			} => {
				//to bytes via base64
				let bytes = Base64::decode_vec(&key).map_err(|_| SdkError::ImportingPrivateKeyFailed)?;

				let private_key: [u8; 32] = bytes
					.try_into()
					.map_err(|_| SdkError::ImportingPrivateKeyFailed)?;

				Ok(PrivateKeyFormatInt {
					key_id,
					key: Sk::Ecies(private_key),
				})
			},
		}
	}
}

impl FromStr for PrivateKeyFormatInt
{
	type Err = SdkError;

	fn from_str(s: &str) -> Result<Self, Self::Err>
	{
		let key: PrivateKeyFormatExport = serde_json::from_str(s).map_err(|_| SdkError::ImportingPrivateKeyFailed)?;

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
	type Error = SdkError;

	fn try_into(self) -> Result<PublicKeyFormatInt, Self::Error>
	{
		match self {
			PublicKeyFormatExport::Ecies {
				key,
				key_id,
			} => {
				let bytes = Base64::decode_vec(&key).map_err(|_| SdkError::ImportPublicKeyFailed)?;

				let key = bytes
					.try_into()
					.map_err(|_| SdkError::ImportPublicKeyFailed)?;

				Ok(PublicKeyFormatInt {
					key_id,
					key: Pk::Ecies(key),
				})
			},
		}
	}
}

impl FromStr for PublicKeyFormatInt
{
	type Err = SdkError;

	fn from_str(s: &str) -> Result<Self, Self::Err>
	{
		let key: PublicKeyFormatExport = serde_json::from_str(s).map_err(|_| SdkError::ImportPublicKeyFailed)?;

		key.try_into()
	}
}

impl<'a> TryFrom<&'a UserPublicKeyData> for PublicKeyFormatInt
{
	type Error = SdkError;

	fn try_from(value: &'a UserPublicKeyData) -> Result<Self, Self::Error>
	{
		let public_key = import_key_from_pem(&value.public_key_pem)?;

		match value.public_key_alg.as_str() {
			ECIES_OUTPUT => {
				let public_key = public_key
					.try_into()
					.map_err(|_| SdkError::DecodePublicKeyFailed)?;

				Ok(Self {
					key_id: value.public_key_id.clone(),
					key: Pk::Ecies(public_key),
				})
			},
			_ => Err(SdkError::AlgNotFound),
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
	type Error = SdkError;

	fn try_into(self) -> Result<SignKeyFormatInt, Self::Error>
	{
		match self {
			SignKeyFormatExport::Ed25519 {
				key,
				key_id,
			} => {
				let bytes = Base64::decode_vec(&key).map_err(|_| SdkError::ImportingSignKeyFailed)?;

				let sign_key: [u8; 32] = bytes
					.try_into()
					.map_err(|_| SdkError::ImportingSignKeyFailed)?;

				Ok(SignKeyFormatInt {
					key_id,
					key: SignK::Ed25519(sign_key),
				})
			},
		}
	}
}

impl FromStr for SignKeyFormatInt
{
	type Err = SdkError;

	fn from_str(s: &str) -> Result<Self, Self::Err>
	{
		let key: SignKeyFormatExport = serde_json::from_str(s).map_err(|_| SdkError::ImportingSignKeyFailed)?;

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
	type Error = SdkError;

	fn try_into(self) -> Result<VerifyKeyFormatInt, Self::Error>
	{
		match self {
			VerifyKeyFormatExport::Ed25519 {
				key,
				key_id,
			} => {
				let bytes = Base64::decode_vec(&key).map_err(|_| SdkError::ImportVerifyKeyFailed)?;

				let verify_key: [u8; 32] = bytes
					.try_into()
					.map_err(|_| SdkError::ImportVerifyKeyFailed)?;

				Ok(VerifyKeyFormatInt {
					key: VerifyK::Ed25519(verify_key),
					key_id,
				})
			},
		}
	}
}

impl FromStr for VerifyKeyFormatInt
{
	type Err = SdkError;

	fn from_str(s: &str) -> Result<Self, Self::Err>
	{
		let key: VerifyKeyFormatExport = serde_json::from_str(s).map_err(|_| SdkError::ImportingSignKeyFailed)?;

		key.try_into()
	}
}

impl<'a> TryFrom<&'a UserVerifyKeyData> for VerifyKeyFormatInt
{
	type Error = SdkError;

	fn try_from(value: &'a UserVerifyKeyData) -> Result<Self, Self::Error>
	{
		let verify_key = import_key_from_pem(&value.verify_key_pem)?;

		match value.verify_key_alg.as_str() {
			ECIES_OUTPUT => {
				let verify_key = verify_key
					.try_into()
					.map_err(|_| SdkError::DecodePublicKeyFailed)?;

				Ok(Self {
					key_id: value.verify_key_id.clone(),
					key: VerifyK::Ed25519(verify_key),
				})
			},
			_ => Err(SdkError::AlgNotFound),
		}
	}
}
