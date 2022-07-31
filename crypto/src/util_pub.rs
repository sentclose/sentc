use alloc::string::String;
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use sentc_crypto_common::server_default::ServerSuccessOutput;
use sentc_crypto_common::ServerOutput;
use sentc_crypto_core::{generate_salt, hash_auth_key};
pub use sentc_crypto_core::{HashedAuthenticationKey, ARGON_2_OUTPUT};
use serde::{Deserialize, Serialize};

use crate::error::SdkError;
use crate::util::{client_random_value_from_string, derive_auth_key_from_base64, hashed_authentication_key_from_base64};

pub fn handle_server_response<'de, T: Serialize + Deserialize<'de>>(res: &'de str) -> Result<T, SdkError>
{
	let server_output = ServerOutput::<T>::from_string(res).map_err(|_| SdkError::JsonParseFailed)?;

	if !server_output.status {
		let err_code = match server_output.err_code {
			Some(c) => c,
			None => return Err(SdkError::JsonParseFailed),
		};

		let err_msg = match server_output.err_msg {
			Some(m) => m,
			None => return Err(SdkError::JsonParseFailed),
		};

		return Err(SdkError::ServerErr(err_code, err_msg));
	}

	match server_output.result {
		Some(r) => Ok(r),
		None => Err(SdkError::JsonParseFailed),
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

/**
# Generates a salt

from a base64 encoded client random value

returns the salt as base64 encoded
*/
pub fn generate_salt_from_base64_to_string(client_random_value: &str, alg: &str, add_str: &str) -> Result<String, SdkError>
{
	let salt = generate_salt_from_base64(client_random_value, alg, add_str)?;

	Ok(Base64::encode_string(&salt))
}

/**
# Get the client and server hashed auth keys in the internal format

1. hash the client auth key (which comes from the client to the server)
2. import both hashed auth keys into the internal format and return them to compare them

This is used on the server in done login
*/
pub fn get_auth_keys_from_base64(
	client_auth_key: &str,
	server_hashed_auth_key: &str,
	alg: &str,
) -> Result<(HashedAuthenticationKey, HashedAuthenticationKey), SdkError>
{
	let client_auth_key = derive_auth_key_from_base64(client_auth_key, alg)?;
	let server_hashed_auth_key = hashed_authentication_key_from_base64(server_hashed_auth_key, alg)?;

	//hash the client key
	let hashed_client_key = hash_auth_key(&client_auth_key)?;

	Ok((server_hashed_auth_key, hashed_client_key))
}
