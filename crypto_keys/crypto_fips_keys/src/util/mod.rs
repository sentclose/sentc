use std::str::FromStr;

use openssl::base64::{decode_block, encode_block};
use sentc_crypto_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto_common::{EncryptionKeyPairId, SignKeyPairId, SymKeyId};
use sentc_crypto_core::cryptomat::{SignK, SignKeyComposer, SignKeyPair, SkComposer, StaticKeyPair, SymKeyComposer, SymKeyGen, VerifyK};
use sentc_crypto_utils::cryptomat::{
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
use sentc_crypto_utils::{from_string_impl, to_string_impl, to_string_try_impl, wrapper_impl};
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

impl SymKeyGenWrapper for SymmetricKey
{
	type SymmetricKeyWrapper = Self;
	type KeyGen = Aes256GcmKey;

	fn from_inner(inner: <<Self as SymKeyGenWrapper>::KeyGen as SymKeyGen>::SymmetricKey, id: String) -> Self::SymmetricKeyWrapper
	{
		Self {
			key: inner,
			key_id: id,
		}
	}
}

impl SymKeyComposerWrapper for SymmetricKey
{
	type SymmetricKeyWrapper = Self;
	type Composer = Aes256GcmKey;

	fn from_inner(inner: <<Self as SymKeyComposerWrapper>::Composer as SymKeyComposer>::SymmetricKey, id: String) -> Self::SymmetricKeyWrapper
	{
		Self {
			key_id: id,
			key: inner,
		}
	}
}

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
	pub key: RsaSk,
	pub key_id: EncryptionKeyPairId,
}

impl StaticKeyPairWrapper for SecretKey
{
	type PkWrapper = PublicKey;
	type KeyGen = RsaSk;

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
	type InnerPk = RsaPk;
	type Composer = RsaSk;

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

impl TryInto<SecretKey> for SecretKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<SecretKey, Self::Error>
	{
		let bytes = decode_block(&self.key).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;

		Ok(SecretKey {
			key_id: self.key_id,
			key: RsaSk::import(&bytes)?,
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
			key: RsaPk::import(&bytes)?,
		})
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
	pub key: Ed25519FIPSSignK,
	pub key_id: String,
}

wrapper_impl!(SignKWrapper, SignKey, Ed25519FIPSSignK);
to_string_try_impl!(SignKey, SignKeyFormatExport);
from_string_impl!(SignKey, SignKeyFormatExport);

impl SignKeyPairWrapper for SignKey
{
	type KeyGen = Ed25519FIPSSignK;

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
	type InnerVk = Ed25519FIPSVerifyK;
	type Composer = Ed25519FIPSSignK;

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

impl TryInto<VerifyKey> for VerifyKeyFormatExport
{
	type Error = SdkUtilError;

	fn try_into(self) -> Result<VerifyKey, Self::Error>
	{
		let bytes = decode_block(&self.key).map_err(|_| SdkUtilError::ImportingPrivateKeyFailed)?;

		Ok(VerifyKey {
			key_id: self.key_id,
			key: Ed25519FIPSVerifyK::import(&bytes)?,
		})
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
