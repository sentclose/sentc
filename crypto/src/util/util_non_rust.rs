use alloc::string::String;

use base64ct::{Base64, Encoding};
use sendclose_crypto_core::{Error, Pk, SignK, Sk, SymKey, VerifyK};
use serde::{Deserialize, Serialize};
use serde_json::{from_slice, to_string};

#[derive(Serialize, Deserialize)]
pub enum PrivateKeyFormat
{
	Ecies
	{
		key: String, key_id: String
	},
}

impl PrivateKeyFormat
{
	pub fn from_string(v: &[u8]) -> serde_json::Result<Self>
	{
		from_slice::<Self>(v)
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
		key: String, key_id: String
	},
}

impl PublicKeyFormat
{
	pub fn from_string(v: &[u8]) -> serde_json::Result<Self>
	{
		from_slice::<Self>(v)
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
		key: String, key_id: String
	},
}

impl SignKeyFormat
{
	pub fn from_string(v: &[u8]) -> serde_json::Result<Self>
	{
		from_slice::<Self>(v)
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
		key: String, key_id: String
	},
}

impl VerifyKeyFormat
{
	pub fn from_string(v: &[u8]) -> serde_json::Result<Self>
	{
		from_slice::<Self>(v)
	}

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
pub struct KeyData
{
	pub private_key: PrivateKeyFormat,
	pub public_key: PublicKeyFormat,
	pub sign_key: SignKeyFormat,
	pub verify_key: VerifyKeyFormat,
}

impl KeyData
{
	pub fn from_string(v: &[u8]) -> serde_json::Result<Self>
	{
		from_slice::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}

#[derive(Serialize, Deserialize)]
pub enum SymKeyFormat
{
	Aes
	{
		key: String, key_id: String
	},
}

impl SymKeyFormat
{
	pub fn from_string(v: &[u8]) -> serde_json::Result<Self>
	{
		from_slice::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}

pub(crate) fn import_private_key(private_key_string: &str) -> Result<(Sk, String), Error>
{
	let private_key_format = PrivateKeyFormat::from_string(private_key_string.as_bytes()).map_err(|_| Error::ImportingPrivateKeyFailed)?;

	import_private_key_from_format(&private_key_format)
}

pub(crate) fn import_private_key_from_format(key: &PrivateKeyFormat) -> Result<(Sk, String), Error>
{
	match key {
		PrivateKeyFormat::Ecies {
			key_id,
			key,
		} => {
			//to bytes via base64
			let bytes = Base64::decode_vec(key.as_str()).map_err(|_| Error::ImportingPrivateKeyFailed)?;

			let private_key: [u8; 32] = bytes
				.try_into()
				.map_err(|_| Error::ImportingPrivateKeyFailed)?;

			Ok((Sk::Ecies(private_key), key_id.clone()))
		},
	}
}

pub(crate) fn import_public_key(public_key_string: &str) -> Result<(Pk, String), Error>
{
	let public_key_format = PublicKeyFormat::from_string(public_key_string.as_bytes()).map_err(|_| Error::ImportPublicKeyFailed)?;

	import_public_key_from_format(&public_key_format)
}

pub(crate) fn import_public_key_from_format(key: &PublicKeyFormat) -> Result<(Pk, String), Error>
{
	match key {
		PublicKeyFormat::Ecies {
			key_id,
			key,
		} => {
			let bytes = Base64::decode_vec(key.as_str()).map_err(|_| Error::ImportPublicKeyFailed)?;

			let key = bytes.try_into().map_err(|_| Error::ImportPublicKeyFailed)?;

			Ok((Pk::Ecies(key), key_id.clone()))
		},
	}
}

pub(crate) fn import_sign_key(sign_key_string: &str) -> Result<(SignK, String), Error>
{
	let sign_key_format = SignKeyFormat::from_string(sign_key_string.as_bytes()).map_err(|_| Error::ImportingSignKeyFailed)?;

	import_sign_key_from_format(&sign_key_format)
}

pub(crate) fn import_sign_key_from_format(key: &SignKeyFormat) -> Result<(SignK, String), Error>
{
	match key {
		SignKeyFormat::Ed25519 {
			key_id,
			key,
		} => {
			//to bytes via base64
			let bytes = Base64::decode_vec(key.as_str()).map_err(|_| Error::ImportingSignKeyFailed)?;

			let sign_key: [u8; 32] = bytes
				.try_into()
				.map_err(|_| Error::ImportingSignKeyFailed)?;

			Ok((SignK::Ed25519(sign_key), key_id.clone()))
		},
	}
}

pub(crate) fn export_private_key(private_key: Sk, key_id: String) -> PrivateKeyFormat
{
	match private_key {
		Sk::Ecies(k) => {
			let private_key_string = Base64::encode_string(&k);

			PrivateKeyFormat::Ecies {
				key_id,
				key: private_key_string,
			}
		},
	}
}

pub(crate) fn export_public_key(public_key: Pk, key_id: String) -> PublicKeyFormat
{
	match public_key {
		Pk::Ecies(k) => {
			let public_key_string = Base64::encode_string(&k);

			PublicKeyFormat::Ecies {
				key_id,
				key: public_key_string,
			}
		},
	}
}

pub(crate) fn export_sign_key(sign_key: SignK, key_id: String) -> SignKeyFormat
{
	match sign_key {
		SignK::Ed25519(k) => {
			let sign_key_string = Base64::encode_string(&k);

			SignKeyFormat::Ed25519 {
				key_id,
				key: sign_key_string,
			}
		},
	}
}

pub(crate) fn export_verify_key(verify_key: VerifyK, key_id: String) -> VerifyKeyFormat
{
	match verify_key {
		VerifyK::Ed25519(k) => {
			let verify_key_string = Base64::encode_string(&k);

			VerifyKeyFormat::Ed25519 {
				key_id,
				key: verify_key_string,
			}
		},
	}
}

pub(crate) fn import_sym_key(key_string: &str) -> Result<(SymKey, String), Error>
{
	let key_format = SymKeyFormat::from_string(key_string.as_bytes()).map_err(|_| Error::ImportSymmetricKeyFailed)?;

	import_sym_key_from_format(&key_format)
}

pub(crate) fn import_sym_key_from_format(key: &SymKeyFormat) -> Result<(SymKey, String), Error>
{
	match key {
		SymKeyFormat::Aes {
			key,
			key_id,
		} => {
			//to bytes via base64
			let bytes = Base64::decode_vec(key.as_str()).map_err(|_| Error::ImportSymmetricKeyFailed)?;

			let key = bytes
				.try_into()
				.map_err(|_| Error::ImportSymmetricKeyFailed)?;

			Ok((SymKey::Aes(key), key_id.clone()))
		},
	}
}

pub(crate) fn export_sym_key(key: SymKey, key_id: String) -> SymKeyFormat
{
	match key {
		SymKey::Aes(k) => {
			let sym_key = Base64::encode_string(&k);

			SymKeyFormat::Aes {
				key_id,
				key: sym_key,
			}
		},
	}
}
