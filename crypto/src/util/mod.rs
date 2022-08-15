pub mod public;
#[cfg(feature = "server")]
pub mod server;
#[cfg(not(feature = "rust"))]
mod util_non_rust;

use alloc::string::String;
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use pem_rfc7468::LineEnding;
use sentc_crypto_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto_common::{EncryptionKeyPairId, SignKeyPairId, SymKeyId, UserId};
use sentc_crypto_core::{
	ClientRandomValue,
	DeriveAuthKeyForAuth,
	HashedAuthenticationKey,
	Pk,
	SignK,
	Sk,
	SymKey,
	VerifyK,
	ARGON_2_OUTPUT,
	ECIES_OUTPUT,
	ED25519_OUTPUT,
};

#[cfg(not(feature = "rust"))]
pub(crate) use self::util_non_rust::{
	export_private_key_to_string,
	export_public_key_to_string,
	export_sign_key_to_string,
	export_sym_key_to_string,
	export_verify_key_to_string,
	import_private_key,
	import_public_key,
	import_sign_key,
	import_sym_key,
	import_sym_key_from_format,
};
#[cfg(not(feature = "rust"))]
pub use self::util_non_rust::{KeyData, PrivateKeyFormat, PublicKeyFormat, SignKeyFormat, SymKeyFormat, UserData, VerifyKeyFormat};
//if rust feature is enabled export the internally functions as externally
#[cfg(feature = "rust")]
pub use self::{
	KeyDataInt as KeyData,
	PrivateKeyFormatInt as PrivateKeyFormat,
	PublicKeyFormatInt as PublicKeyFormat,
	SignKeyFormatInt as SignKeyFormat,
	SymKeyFormatInt as SymKeyFormat,
	UserDataInt as UserData,
	VerifyKeyFormatInt as VerifyKeyFormat,
};
use crate::SdkError;

pub struct SymKeyFormatInt
{
	pub key: SymKey,
	pub key_id: SymKeyId,
}

pub struct PrivateKeyFormatInt
{
	pub key: Sk,
	pub key_id: EncryptionKeyPairId,
}

pub struct PublicKeyFormatInt
{
	pub key: Pk,
	pub key_id: EncryptionKeyPairId,
}

pub struct SignKeyFormatInt
{
	pub key: SignK,
	pub key_id: SignKeyPairId,
}

pub struct VerifyKeyFormatInt
{
	pub key: VerifyK,
	pub key_id: SignKeyPairId,
}

/**
# key storage structure for the rust feature

It can be used with other rust programs.

The different to the internally DoneLoginOutput ist that,
the KeyFormat is sued for each where, were the key id is saved too
 */
pub struct KeyDataInt
{
	pub private_key: PrivateKeyFormatInt,
	pub sign_key: SignKeyFormatInt,
	pub public_key: PublicKeyFormatInt,
	pub verify_key: VerifyKeyFormatInt,
	pub exported_public_key: UserPublicKeyData,
	pub exported_verify_key: UserVerifyKeyData,
}

pub struct UserDataInt
{
	pub keys: KeyDataInt,
	pub jwt: String,
	pub refresh_token: String,
	pub user_id: UserId,
}

pub(crate) fn export_key_to_pem(key: &[u8]) -> Result<String, SdkError>
{
	//export should not panic because we are creating the keys
	let key = pem_rfc7468::encode_string("PUBLIC KEY", LineEnding::default(), key).map_err(|_| SdkError::ExportingPublicKeyFailed)?;

	Ok(key)
}

pub(crate) fn import_key_from_pem(pem: &str) -> Result<Vec<u8>, SdkError>
{
	let (_type_label, data) = pem_rfc7468::decode_vec(pem.as_bytes()).map_err(|_| SdkError::ImportingKeyFromPemFailed)?;

	Ok(data)
}

pub(crate) fn export_raw_public_key_to_pem(key: &Pk) -> Result<String, SdkError>
{
	match key {
		//match against the public key variants
		Pk::Ecies(k) => export_key_to_pem(k),
	}
}

pub(crate) fn export_raw_verify_key_to_pem(key: &VerifyK) -> Result<String, SdkError>
{
	match key {
		VerifyK::Ed25519(k) => export_key_to_pem(k),
	}
}

pub(crate) fn hashed_authentication_key_to_string(hashed_authentication_key_bytes: &HashedAuthenticationKey) -> String
{
	match hashed_authentication_key_bytes {
		HashedAuthenticationKey::Argon2(h) => Base64::encode_string(h),
	}
}

pub(crate) fn derive_auth_key_for_auth_to_string(derive_auth_key_for_auth: &DeriveAuthKeyForAuth) -> String
{
	match derive_auth_key_for_auth {
		DeriveAuthKeyForAuth::Argon2(h) => Base64::encode_string(h),
	}
}

pub(crate) fn client_random_value_to_string(client_random_value: &ClientRandomValue) -> String
{
	match client_random_value {
		ClientRandomValue::Argon2(v) => Base64::encode_string(v),
	}
}

pub(crate) fn client_random_value_from_string(client_random_value: &str, alg: &str) -> Result<ClientRandomValue, SdkError>
{
	//normally not needed only when the client needs to create the rand value, e.g- for key update.
	match alg {
		ARGON_2_OUTPUT => {
			let v = Base64::decode_vec(client_random_value).map_err(|_| SdkError::DecodeRandomValueFailed)?;
			let v = v
				.try_into()
				.map_err(|_| SdkError::DecodeRandomValueFailed)?;

			Ok(ClientRandomValue::Argon2(v))
		},
		_ => Err(SdkError::AlgNotFound),
	}
}

pub(crate) fn import_public_key_from_pem_with_alg(public_key: &str, alg: &str) -> Result<Pk, SdkError>
{
	let public_key = import_key_from_pem(public_key)?;

	match alg {
		ECIES_OUTPUT => {
			let public_key = public_key
				.try_into()
				.map_err(|_| SdkError::DecodePublicKeyFailed)?;
			Ok(Pk::Ecies(public_key))
		},
		_ => Err(SdkError::AlgNotFound),
	}
}

pub(crate) fn import_verify_key_from_pem_with_alg(verify_key: &str, alg: &str) -> Result<VerifyK, SdkError>
{
	let verify_key = import_key_from_pem(verify_key)?;

	match alg {
		ED25519_OUTPUT => {
			let verify_key = verify_key
				.try_into()
				.map_err(|_| SdkError::DecodePublicKeyFailed)?;
			Ok(VerifyK::Ed25519(verify_key))
		},
		_ => Err(SdkError::AlgNotFound),
	}
}
