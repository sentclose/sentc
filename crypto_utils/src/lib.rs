#![no_std]
#![allow(clippy::type_complexity)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use sentc_crypto_common::server_default::ServerSuccessOutput;
use sentc_crypto_common::ServerOutput;
use sentc_crypto_core::cryptomat::{ClientRandomValue, ClientRandomValueComposer, DeriveAuthKeyForAuth, HashedAuthenticationKey};
use serde::{Deserialize, Serialize};

use crate::error::SdkUtilError;

pub mod cryptomat;
pub mod error;
#[cfg(all(feature = "crypto_full", any(feature = "rustls", feature = "wasm")))]
pub mod full;
pub mod group;
#[cfg(any(feature = "rustls", feature = "wasm"))]
pub mod http;
pub mod jwt;
pub mod user;

pub fn handle_server_response<'de, T: Deserialize<'de>>(res: &'de str) -> Result<T, SdkUtilError>
{
	let server_output = ServerOutput::<T>::from_string(res)?;

	if !server_output.status {
		let err_code = match server_output.err_code {
			Some(c) => c,
			None => return Err(SdkUtilError::JsonParse),
		};

		let err_msg = match server_output.err_msg {
			Some(m) => m,
			None => return Err(SdkUtilError::JsonParse),
		};

		return Err(SdkUtilError::ServerErr(err_code, err_msg));
	}

	match server_output.result {
		Some(r) => Ok(r),
		None => Err(SdkUtilError::JsonParse),
	}
}

/**
Getting the result of a simple server response.
 */
pub fn handle_general_server_response(res: &str) -> Result<(), SdkUtilError>
{
	handle_server_response::<ServerSuccessOutput>(res)?;

	Ok(())
}

pub fn client_random_value_to_string(client_random_value: &impl ClientRandomValue) -> String
{
	let out = client_random_value.prepare_export();

	Base64::encode_string(out)
}

pub fn hashed_authentication_key_to_string(hashed_authentication_key_bytes: &impl HashedAuthenticationKey) -> String
{
	let out = hashed_authentication_key_bytes.prepare_export();

	Base64::encode_string(out)
}

pub fn derive_auth_key_for_auth_to_string(derive_auth_key_for_auth: &impl DeriveAuthKeyForAuth) -> String
{
	let out = derive_auth_key_for_auth.prepare_export();

	Base64::encode_string(out)
}

pub fn client_random_value_from_string<C: ClientRandomValueComposer>(client_random_value: &str, alg: &str) -> Result<C::Value, SdkUtilError>
{
	let v = Base64::decode_vec(client_random_value).map_err(|_| SdkUtilError::DecodeRandomValueFailed)?;
	//normally not needed only when the client needs to create the rand value, e.g- for key update.
	Ok(C::from_bytes(v, alg)?)
}

/**
Get the head and the data.

This can not only be used internally, to get the used key_id
 */
#[cfg(feature = "encryption")]
pub fn split_head_and_encrypted_data<'a, T: Deserialize<'a>>(data_with_head: &'a [u8]) -> Result<(T, &[u8]), SdkUtilError>
{
	let mut i = 0usize;
	for data_itr in data_with_head {
		if *data_itr == 0u8 {
			//the mark to split the head from the data
			//found the ii where to split head from data
			break;
		}

		i += 1;
	}

	let head = serde_json::from_slice(&data_with_head[..i])?;

	//ignore the zero byte
	Ok((head, &data_with_head[i + 1..]))
}

#[cfg(feature = "encryption")]
pub fn put_head_and_encrypted_data<T: Serialize>(head: &T, encrypted: &[u8]) -> Result<Vec<u8>, SdkUtilError>
{
	let head = serde_json::to_string(head).map_err(|_| SdkUtilError::JsonToStringFailed)?;

	let mut out = Vec::with_capacity(head.len() + 1 + encrypted.len());

	out.extend_from_slice(head.as_bytes());
	out.extend_from_slice(&[0u8]);
	out.extend_from_slice(encrypted);

	Ok(out)
}
