use std::str::FromStr;

use openssl::base64::{decode_block, encode_block};
use sentc_crypto_common::{EncryptionKeyPairId, SignKeyPairId, SymKeyId};
use sentc_crypto_core::cryptomat::SignK;
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

#[cfg(feature = "full")]
pub use self::crypto::{HmacKey, SortableKey};
use crate::core::asym::{RsaPk, RsaSk};
use crate::core::sign::{Ed25519FIPSSignK, Ed25519FIPSVerifyK};
use crate::core::sym::Aes256GcmKey;
use crate::util::export::{
	export_raw_public_key_to_pem,
	export_raw_verify_key_to_pem,
	import_public_key_from_pem_with_alg,
	import_sig_from_string,
	import_verify_key_from_pem_with_alg,
	sig_to_string,
};

#[cfg(feature = "full")]
mod crypto;
mod export;

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

impl<'a> From<&'a SymmetricKey> for SymKeyFormatExport
{
	fn from(value: &'a SymmetricKey) -> Self
	{
		let key = encode_block(value.key.as_ref());

		Self {
			key,
			key_id: value.key_id.clone(),
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
	pub key: RsaSk,
	pub key_id: EncryptionKeyPairId,
}

static_key_pair_self!(SecretKey, RsaSk, PublicKey, export_raw_public_key_to_pem);
static_key_composer_self!(
	SecretKey,
	RsaSk,
	PublicKey,
	RsaPk,
	import_public_key_from_pem_with_alg
);
wrapper_impl!(SkWrapper, SecretKey, RsaSk);
to_string_try_impl!(SecretKey, SecretKeyFormatExport);
from_string_impl!(SecretKey, SecretKeyFormatExport);

#[derive(Serialize, Deserialize)]
pub struct SecretKeyFormatExport
{
	key: String,
	key_id: EncryptionKeyPairId,
}

impl TryFrom<SecretKey> for SecretKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_from(value: SecretKey) -> Result<Self, Self::Error>
	{
		let key = encode_block(&value.key.export()?);

		Ok(Self {
			key,
			key_id: value.key_id,
		})
	}
}

impl<'a> TryFrom<&'a SecretKey> for SecretKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_from(value: &'a SecretKey) -> Result<Self, Self::Error>
	{
		let key = encode_block(&value.key.export()?);

		Ok(Self {
			key,
			key_id: value.key_id.clone(),
		})
	}
}

impl TryInto<SecretKey> for SecretKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<SecretKey, Self::Error>
	{
		let bytes = decode_block(&self.key).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;

		Ok(SecretKey {
			key_id: self.key_id,
			key: RsaSk::try_from(bytes)?,
		})
	}
}

//__________________________________________________________________________________________________

#[derive(Clone)]
pub struct PublicKey
{
	pub key: RsaPk,
	pub key_id: EncryptionKeyPairId,
}

impl PublicKey
{
	pub fn to_string_ref(&self) -> Result<String, SdkUtilError>
	{
		serde_json::to_string(&TryInto::<PublicKeyFormatExport>::try_into(self)?).map_err(|_e| SdkUtilError::JsonToStringFailed)
	}
}

wrapper_impl!(PkWrapper, PublicKey, RsaPk);
to_string_try_impl!(PublicKey, PublicKeyFormatExport);
from_string_impl!(PublicKey, PublicKeyFormatExport);
pk_user_pk!(PublicKey, import_public_key_from_pem_with_alg);

#[derive(Serialize, Deserialize)]
pub struct PublicKeyFormatExport
{
	key: String,
	key_id: EncryptionKeyPairId,
}

impl TryFrom<PublicKey> for PublicKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_from(value: PublicKey) -> Result<Self, Self::Error>
	{
		let key = encode_block(&value.key.export()?);

		Ok(Self {
			key,
			key_id: value.key_id,
		})
	}
}

impl<'a> TryFrom<&'a PublicKey> for PublicKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_from(value: &'a PublicKey) -> Result<Self, Self::Error>
	{
		let key = encode_block(&value.key.export()?);

		Ok(Self {
			key,
			key_id: value.key_id.clone(),
		})
	}
}

impl TryInto<PublicKey> for PublicKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<PublicKey, Self::Error>
	{
		let bytes = decode_block(&self.key).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;

		Ok(PublicKey {
			key_id: self.key_id,
			key: RsaPk::try_from(bytes)?,
		})
	}
}

//__________________________________________________________________________________________________

pub struct SignKey
{
	pub key: Ed25519FIPSSignK,
	pub key_id: String,
}

wrapper_impl!(SignKWrapper, SignKey, Ed25519FIPSSignK);
to_string_try_impl!(SignKey, SignKeyFormatExport);
from_string_impl!(SignKey, SignKeyFormatExport);
sign_key_pair_self!(SignKey, Ed25519FIPSSignK, export_raw_verify_key_to_pem, sig_to_string);
sign_key_composer_self!(
	SignKey,
	Ed25519FIPSSignK,
	VerifyKey,
	Ed25519FIPSVerifyK,
	import_verify_key_from_pem_with_alg,
	import_sig_from_string,
	sig_to_string
);

#[derive(Serialize, Deserialize)]
pub struct SignKeyFormatExport
{
	key: String,
	key_id: SignKeyPairId,
}

impl TryFrom<SignKey> for SignKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_from(value: SignKey) -> Result<Self, Self::Error>
	{
		let key = encode_block(&value.key.export()?);

		Ok(Self {
			key,
			key_id: value.key_id,
		})
	}
}

impl<'a> TryFrom<&'a SignKey> for SignKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_from(value: &'a SignKey) -> Result<Self, Self::Error>
	{
		let key = encode_block(&value.key.export()?);

		Ok(Self {
			key,
			key_id: value.key_id.clone(),
		})
	}
}

impl TryInto<SignKey> for SignKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<SignKey, Self::Error>
	{
		let bytes = decode_block(&self.key).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;

		Ok(SignKey {
			key_id: self.key_id,
			key: Ed25519FIPSSignK::import(&bytes)?,
		})
	}
}

//__________________________________________________________________________________________________

pub struct VerifyKey
{
	pub key: Ed25519FIPSVerifyK,
	pub key_id: SignKeyPairId,
}

wrapper_impl!(VerifyKWrapper, VerifyKey, Ed25519FIPSVerifyK);
to_string_try_impl!(VerifyKey, VerifyKeyFormatExport);
from_string_impl!(VerifyKey, VerifyKeyFormatExport);
vk_user_vk!(VerifyKey, import_verify_key_from_pem_with_alg);

#[derive(Serialize, Deserialize)]
pub struct VerifyKeyFormatExport
{
	key: String,
	key_id: SignKeyPairId,
}

impl TryFrom<VerifyKey> for VerifyKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_from(value: VerifyKey) -> Result<Self, Self::Error>
	{
		let key = encode_block(&value.key.export()?);

		Ok(Self {
			key,
			key_id: value.key_id,
		})
	}
}

impl<'a> TryFrom<&'a VerifyKey> for VerifyKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_from(value: &'a VerifyKey) -> Result<Self, Self::Error>
	{
		let key = encode_block(&value.key.export()?);

		Ok(Self {
			key,
			key_id: value.key_id.clone(),
		})
	}
}

impl TryInto<VerifyKey> for VerifyKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<VerifyKey, Self::Error>
	{
		let bytes = decode_block(&self.key).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;

		Ok(VerifyKey {
			key_id: self.key_id,
			key: Ed25519FIPSVerifyK::try_from(bytes)?,
		})
	}
}

//__________________________________________________________________________________________________
