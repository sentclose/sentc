use alloc::string::String;
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use sentc_crypto_common::ServerOutput;
pub use sentc_crypto_core::ARGON_2_OUTPUT;
use sentc_crypto_core::{generate_salt, ClientRandomValue};
use serde::{Deserialize, Serialize};

use crate::error::SdkError;

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

pub fn client_random_value_to_string(client_random_value: &ClientRandomValue) -> String
{
	match client_random_value {
		ClientRandomValue::Argon2(v) => Base64::encode_string(v),
	}
}

pub fn client_random_value_from_string(client_random_value: &str, alg: &str) -> Result<ClientRandomValue, SdkError>
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

pub fn generate_salt_from_base64(client_random_value: &str, alg: &str, add_str: &str) -> Result<Vec<u8>, SdkError>
{
	let client_random_value = client_random_value_from_string(client_random_value, alg)?;

	Ok(generate_salt(client_random_value, add_str))
}
