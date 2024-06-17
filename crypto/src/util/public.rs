#[cfg(feature = "export")]
use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::user::{UserPublicKeyData, UserPublicKeyDataServerOutput, UserVerifyKeyData, UserVerifyKeyDataServerOutput};
#[cfg(feature = "export")]
use sentc_crypto_common::{EncryptionKeyPairId, SignKeyPairId};
use sentc_crypto_core::cryptomat::{ClientRandomValue, ClientRandomValueComposer};
use sentc_crypto_utils::client_random_value_from_string;
use serde::Deserialize;

use crate::error::SdkError;

pub fn handle_server_response<'de, T: Deserialize<'de>>(res: &'de str) -> Result<T, SdkError>
{
	Ok(sentc_crypto_utils::handle_server_response(res)?)
}

/**
Getting the result of a simple server response.
 */
pub fn handle_general_server_response(res: &str) -> Result<(), SdkError>
{
	Ok(sentc_crypto_utils::handle_general_server_response(res)?)
}

pub fn generate_salt_from_base64<C: ClientRandomValueComposer>(client_random_value: &str, alg: &str, add_str: &str) -> Result<Vec<u8>, SdkError>
{
	let client_random_value = client_random_value_from_string::<C>(client_random_value, alg)?;

	Ok(client_random_value.generate_salt(add_str))
}

pub fn import_public_key_from_string_into_format(public_key: &str) -> Result<UserPublicKeyData, SdkError>
{
	let out: UserPublicKeyDataServerOutput = handle_server_response(public_key)?;

	let public_key = UserPublicKeyData {
		public_key_pem: out.public_key,
		public_key_alg: out.public_key_alg,
		public_key_id: out.public_key_id,
		public_key_sig: out.public_key_sig,
		public_key_sig_key_id: out.public_key_sig_key_id,
	};

	Ok(public_key)
}

pub fn import_verify_key_from_string_into_format(verify_key: &str) -> Result<UserVerifyKeyData, SdkError>
{
	let out: UserVerifyKeyDataServerOutput = handle_server_response(verify_key)?;

	let verify_key = UserVerifyKeyData {
		verify_key_pem: out.verify_key,
		verify_key_alg: out.verify_key_alg,
		verify_key_id: out.verify_key_id,
	};

	Ok(verify_key)
}

#[cfg(feature = "export")]
pub fn import_public_key_from_string_into_export_string(public_key: &str) -> Result<(String, EncryptionKeyPairId, Option<SignKeyPairId>), String>
{
	let public_key = import_public_key_from_string_into_format(public_key)?;

	Ok((
		public_key
			.to_string()
			.map_err(|_| SdkError::JsonToStringFailed)?,
		public_key.public_key_id,
		public_key.public_key_sig_key_id,
	))
}

#[cfg(feature = "export")]
pub fn import_verify_key_from_string_into_export_string(verify_key: &str) -> Result<(String, SignKeyPairId), String>
{
	let public_key = import_verify_key_from_string_into_format(verify_key)?;

	Ok((
		public_key
			.to_string()
			.map_err(|_| SdkError::JsonToStringFailed)?,
		public_key.verify_key_id,
	))
}
