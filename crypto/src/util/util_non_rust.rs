use alloc::string::String;
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use sentc_crypto_common::{DeviceId, EncryptionKeyPairId, SignKeyPairId, SymKeyId, UserId};
use sentc_crypto_core::{HmacKey, Pk, SignK, Sk, SymKey, VerifyK};
use serde::{Deserialize, Serialize};
use serde_json::{from_str, to_string};

use crate::group::GroupOutDataHmacKeys;
use crate::util::{HmacKeyFormatInt, PrivateKeyFormatInt, PublicKeyFormatInt, SignKeyFormatInt, SymKeyFormatInt, VerifyKeyFormatInt};
use crate::SdkError;

#[derive(Serialize, Deserialize)]
pub enum PrivateKeyFormat
{
	Ecies
	{
		key: String, key_id: EncryptionKeyPairId
	},
}

impl PrivateKeyFormat
{
	pub fn from_string(v: &str) -> serde_json::Result<Self>
	{
		from_str::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}

#[derive(Serialize, Deserialize)]
pub enum PublicKeyFormat
{
	Ecies
	{
		key: String, key_id: EncryptionKeyPairId
	},
}

impl PublicKeyFormat
{
	pub fn from_string(v: &str) -> serde_json::Result<Self>
	{
		from_str::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}

#[derive(Serialize, Deserialize)]
pub enum SignKeyFormat
{
	Ed25519
	{
		key: String, key_id: SignKeyPairId
	},
}

impl SignKeyFormat
{
	pub fn from_string(v: &str) -> serde_json::Result<Self>
	{
		from_str::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}

#[derive(Serialize, Deserialize)]
pub enum VerifyKeyFormat
{
	Ed25519
	{
		key: String, key_id: SignKeyPairId
	},
}

impl VerifyKeyFormat
{
	pub fn from_string(v: &str) -> serde_json::Result<Self>
	{
		from_str::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}

#[derive(Serialize, Deserialize)]
pub enum HmacFormat
{
	HmacSha256
	{
		key: String, key_id: SymKeyId
	},
}

impl HmacFormat
{
	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}

/**
# Key data to communicate with other ffi programs via Strings

This data must be serialized for exporting and deserialized for import
 */
#[derive(Serialize, Deserialize)]
pub struct DeviceKeyData
{
	pub private_key: String, //Base64 exported keys
	pub public_key: String,
	pub sign_key: String,
	pub verify_key: String,
	pub exported_public_key: String,
	pub exported_verify_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct UserKeyData
{
	pub private_key: String,
	pub public_key: String,
	pub group_key: String,
	pub time: u128,
	pub group_key_id: SymKeyId,
	pub sign_key: String,
	pub verify_key: String,
	pub exported_public_key: String,
	pub exported_verify_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct UserData
{
	pub user_keys: Vec<UserKeyData>,
	pub device_keys: DeviceKeyData,
	pub jwt: String,
	pub refresh_token: String,
	pub user_id: UserId,
	pub device_id: DeviceId,
	pub hmac_keys: Vec<GroupOutDataHmacKeys>,
}

#[derive(Serialize, Deserialize)]
pub enum SymKeyFormat
{
	Aes
	{
		key: String, key_id: SymKeyId
	},
}

impl SymKeyFormat
{
	pub fn from_string(v: &str) -> serde_json::Result<Self>
	{
		from_str::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}

pub(crate) fn import_private_key(private_key_string: &str) -> Result<PrivateKeyFormatInt, SdkError>
{
	let private_key_format = PrivateKeyFormat::from_string(private_key_string).map_err(|_| SdkError::ImportingPrivateKeyFailed)?;

	import_private_key_from_format(&private_key_format)
}

pub(crate) fn import_private_key_from_format(key: &PrivateKeyFormat) -> Result<PrivateKeyFormatInt, SdkError>
{
	match key {
		PrivateKeyFormat::Ecies {
			key_id,
			key,
		} => {
			//to bytes via base64
			let bytes = Base64::decode_vec(key.as_str()).map_err(|_| SdkError::ImportingPrivateKeyFailed)?;

			let private_key: [u8; 32] = bytes
				.try_into()
				.map_err(|_| SdkError::ImportingPrivateKeyFailed)?;

			Ok(PrivateKeyFormatInt {
				key_id: key_id.clone(),
				key: Sk::Ecies(private_key),
			})
		},
	}
}

pub(crate) fn import_public_key(public_key_string: &str) -> Result<PublicKeyFormatInt, SdkError>
{
	let public_key_format = PublicKeyFormat::from_string(public_key_string).map_err(|_| SdkError::ImportPublicKeyFailed)?;

	import_public_key_from_format(&public_key_format)
}

pub(crate) fn import_public_key_from_format(key: &PublicKeyFormat) -> Result<PublicKeyFormatInt, SdkError>
{
	match key {
		PublicKeyFormat::Ecies {
			key_id,
			key,
		} => {
			let bytes = Base64::decode_vec(key.as_str()).map_err(|_| SdkError::ImportPublicKeyFailed)?;

			let key = bytes
				.try_into()
				.map_err(|_| SdkError::ImportPublicKeyFailed)?;

			Ok(PublicKeyFormatInt {
				key_id: key_id.clone(),
				key: Pk::Ecies(key),
			})
		},
	}
}

pub(crate) fn import_sign_key(sign_key_string: &str) -> Result<SignKeyFormatInt, SdkError>
{
	let sign_key_format = SignKeyFormat::from_string(sign_key_string).map_err(|_| SdkError::ImportingSignKeyFailed)?;

	import_sign_key_from_format(&sign_key_format)
}

pub(crate) fn import_sign_key_from_format(key: &SignKeyFormat) -> Result<SignKeyFormatInt, SdkError>
{
	match key {
		SignKeyFormat::Ed25519 {
			key_id,
			key,
		} => {
			//to bytes via base64
			let bytes = Base64::decode_vec(key.as_str()).map_err(|_| SdkError::ImportingSignKeyFailed)?;

			let sign_key: [u8; 32] = bytes
				.try_into()
				.map_err(|_| SdkError::ImportingSignKeyFailed)?;

			Ok(SignKeyFormatInt {
				key_id: key_id.clone(),
				key: SignK::Ed25519(sign_key),
			})
		},
	}
}

pub(crate) fn export_private_key(private_key: PrivateKeyFormatInt) -> PrivateKeyFormat
{
	match private_key.key {
		Sk::Ecies(k) => {
			let private_key_string = Base64::encode_string(&k);

			PrivateKeyFormat::Ecies {
				key_id: private_key.key_id,
				key: private_key_string,
			}
		},
	}
}

pub(crate) fn export_private_key_to_string(key: PrivateKeyFormatInt) -> Result<String, SdkError>
{
	let key = export_private_key(key);

	key.to_string().map_err(|_e| SdkError::JsonToStringFailed)
}

pub(crate) fn export_public_key(public_key: PublicKeyFormatInt) -> PublicKeyFormat
{
	match public_key.key {
		Pk::Ecies(k) => {
			let public_key_string = Base64::encode_string(&k);

			PublicKeyFormat::Ecies {
				key_id: public_key.key_id,
				key: public_key_string,
			}
		},
	}
}

pub(crate) fn export_public_key_to_string(key: PublicKeyFormatInt) -> Result<String, SdkError>
{
	let key = export_public_key(key);

	key.to_string().map_err(|_e| SdkError::JsonToStringFailed)
}

pub(crate) fn export_sign_key(sign_key: SignKeyFormatInt) -> SignKeyFormat
{
	match sign_key.key {
		SignK::Ed25519(k) => {
			let sign_key_string = Base64::encode_string(&k);

			SignKeyFormat::Ed25519 {
				key_id: sign_key.key_id,
				key: sign_key_string,
			}
		},
	}
}

pub(crate) fn export_sign_key_to_string(key: SignKeyFormatInt) -> Result<String, SdkError>
{
	let key = export_sign_key(key);

	key.to_string().map_err(|_e| SdkError::JsonToStringFailed)
}

pub(crate) fn export_verify_key(verify_key: VerifyKeyFormatInt) -> VerifyKeyFormat
{
	match verify_key.key {
		VerifyK::Ed25519(k) => {
			let verify_key_string = Base64::encode_string(&k);

			VerifyKeyFormat::Ed25519 {
				key_id: verify_key.key_id,
				key: verify_key_string,
			}
		},
	}
}

pub(crate) fn export_verify_key_to_string(key: VerifyKeyFormatInt) -> Result<String, SdkError>
{
	let key = export_verify_key(key);

	key.to_string().map_err(|_e| SdkError::JsonToStringFailed)
}

pub(crate) fn import_sym_key(key_string: &str) -> Result<SymKeyFormatInt, SdkError>
{
	let key_format = SymKeyFormat::from_string(key_string).map_err(|_| SdkError::ImportSymmetricKeyFailed)?;

	import_sym_key_from_format(&key_format)
}

pub(crate) fn import_sym_key_from_format(key: &SymKeyFormat) -> Result<SymKeyFormatInt, SdkError>
{
	match key {
		SymKeyFormat::Aes {
			key,
			key_id,
		} => {
			//to bytes via base64
			let bytes = Base64::decode_vec(key.as_str()).map_err(|_| SdkError::ImportSymmetricKeyFailed)?;

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

pub(crate) fn export_sym_key(key: SymKeyFormatInt) -> SymKeyFormat
{
	match key.key {
		SymKey::Aes(k) => {
			let sym_key = Base64::encode_string(&k);

			SymKeyFormat::Aes {
				key_id: key.key_id,
				key: sym_key,
			}
		},
	}
}

pub(crate) fn export_sym_key_to_string(key: SymKeyFormatInt) -> Result<String, SdkError>
{
	let key = export_sym_key(key);

	key.to_string().map_err(|_e| SdkError::JsonToStringFailed)
}

pub(crate) fn export_hmac_key(key: HmacKeyFormatInt) -> HmacFormat
{
	match key.key {
		HmacKey::HmacSha256(k) => {
			let hmac_key = Base64::encode_string(&k);

			HmacFormat::HmacSha256 {
				key: hmac_key,
				key_id: key.key_id,
			}
		},
	}
}

pub(crate) fn export_hmac_key_to_string(key: HmacKeyFormatInt) -> Result<String, SdkError>
{
	let key = export_hmac_key(key);

	key.to_string().map_err(|_e| SdkError::JsonToStringFailed)
}

pub(crate) fn import_hmac_key(key_string: &str) -> Result<HmacKeyFormatInt, SdkError>
{
	let key_format: HmacFormat = from_str(key_string).map_err(|_| SdkError::ImportSymmetricKeyFailed)?;

	import_hmac_key_from_format(&key_format)
}

pub(crate) fn import_hmac_key_from_format(key: &HmacFormat) -> Result<HmacKeyFormatInt, SdkError>
{
	match key {
		HmacFormat::HmacSha256 {
			key,
			key_id,
		} => {
			let bytes = Base64::decode_vec(key).map_err(|_| SdkError::ImportSymmetricKeyFailed)?;

			let key = bytes
				.try_into()
				.map_err(|_| SdkError::ImportSymmetricKeyFailed)?;

			Ok(HmacKeyFormatInt {
				key: HmacKey::HmacSha256(key),
				key_id: key_id.clone(),
			})
		},
	}
}
