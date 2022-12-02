#[cfg(not(feature = "rust"))]
use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::server_default::ServerSuccessOutput;
use sentc_crypto_common::user::{UserPublicKeyData, UserPublicKeyDataServerOutput, UserVerifyKeyData, UserVerifyKeyDataServerOutput};
use sentc_crypto_common::ServerOutput;
#[cfg(not(feature = "rust"))]
use sentc_crypto_common::{EncryptionKeyPairId, SignKeyPairId};
use sentc_crypto_core::generate_salt;
pub use sentc_crypto_core::{HashedAuthenticationKey, ARGON_2_OUTPUT};
use serde::Deserialize;

use crate::error::SdkError;
use crate::util::client_random_value_from_string;

pub fn handle_server_response<'de, T: Deserialize<'de>>(res: &'de str) -> Result<T, SdkError>
{
	let server_output = ServerOutput::<T>::from_string(res).map_err(SdkError::JsonParseFailed)?;

	if !server_output.status {
		let err_code = match server_output.err_code {
			Some(c) => c,
			None => return Err(SdkError::JsonParse),
		};

		let err_msg = match server_output.err_msg {
			Some(m) => m,
			None => return Err(SdkError::JsonParse),
		};

		return Err(SdkError::ServerErr(err_code, err_msg));
	}

	match server_output.result {
		Some(r) => Ok(r),
		None => Err(SdkError::JsonParse),
	}
}

/**
Getting the result of a simple server response.
 */
pub fn handle_general_server_response(res: &str) -> Result<(), SdkError>
{
	handle_server_response::<ServerSuccessOutput>(res)?;

	Ok(())
}

pub fn generate_salt_from_base64(client_random_value: &str, alg: &str, add_str: &str) -> Result<Vec<u8>, SdkError>
{
	let client_random_value = client_random_value_from_string(client_random_value, alg)?;

	Ok(generate_salt(client_random_value, add_str))
}

pub fn import_public_key_from_string_into_format(public_key: &str) -> Result<UserPublicKeyData, SdkError>
{
	let out: UserPublicKeyDataServerOutput = handle_server_response(public_key)?;

	let public_key = UserPublicKeyData {
		public_key_pem: out.public_key,
		public_key_alg: out.public_key_alg,
		public_key_id: out.public_key_id,
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

#[cfg(not(feature = "rust"))]
pub fn import_public_key_from_string_into_export_string(public_key: &str) -> Result<(String, EncryptionKeyPairId), String>
{
	let public_key = import_public_key_from_string_into_format(public_key)?;

	Ok((
		public_key
			.to_string()
			.map_err(|_| SdkError::JsonToStringFailed)?,
		public_key.public_key_id,
	))
}

#[cfg(not(feature = "rust"))]
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
