#[cfg(not(feature = "rust"))]
use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::server_default::ServerSuccessOutput;
use sentc_crypto_common::ServerOutput;
use sentc_crypto_core::generate_salt;
pub use sentc_crypto_core::{HashedAuthenticationKey, ARGON_2_OUTPUT};
use serde::{Deserialize, Serialize};

#[cfg(not(feature = "rust"))]
use crate::err_to_msg;
use crate::error::SdkError;
use crate::util::client_random_value_from_string;

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
#[cfg(feature = "rust")]
pub fn handle_general_server_response(res: &str) -> Result<(), SdkError>
{
	handle_server_response::<ServerSuccessOutput>(res)?;

	Ok(())
}

#[cfg(not(feature = "rust"))]
pub fn handle_general_server_response(res: &str) -> Result<(), String>
{
	handle_server_response::<ServerSuccessOutput>(res).map_err(|e| err_to_msg(e))?;

	Ok(())
}

pub fn generate_salt_from_base64(client_random_value: &str, alg: &str, add_str: &str) -> Result<Vec<u8>, SdkError>
{
	let client_random_value = client_random_value_from_string(client_random_value, alg)?;

	Ok(generate_salt(client_random_value, add_str))
}
