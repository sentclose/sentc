use alloc::string::String;

use base64ct::{Base64, Encoding};
use sendclose_crypto_common::group::KeyRotationInput;
use sendclose_crypto_core::{Error, SymKey};
use serde::{Deserialize, Serialize};
use serde_json::{from_slice, to_string};

use crate::err_to_msg;
use crate::group::{done_key_rotation_internally, key_rotation_internally, prepare_create_internally};
use crate::user::{import_private_key, import_public_key};

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

pub fn prepare_create(creators_public_key: String) -> String
{
	let (creators_public_key, creator_public_key_id) = match import_public_key(creators_public_key) {
		Ok(k) => k,
		Err(e) => return err_to_msg(e),
	};

	match prepare_create_internally(&creators_public_key, creator_public_key_id) {
		Ok(v) => v,
		Err(e) => err_to_msg(e),
	}
}

pub fn key_rotation(previous_group_key: String, invoker_public_key: String) -> String
{
	//the ids comes from the storage of the current impl from the sdk, the group key id comes from get group
	let (previous_group_key, previous_group_key_id) = match import_sym_key(previous_group_key) {
		Ok(k) => k,
		Err(e) => return err_to_msg(e),
	};

	let (invoker_public_key, invoker_public_key_id) = match import_public_key(invoker_public_key) {
		Ok(k) => k,
		Err(e) => return err_to_msg(e),
	};

	match key_rotation_internally(&previous_group_key, &invoker_public_key, previous_group_key_id, invoker_public_key_id) {
		Ok(v) => v,
		Err(e) => err_to_msg(e),
	}
}

pub fn done_key_rotation(private_key: String, public_key: String, previous_group_key: String, server_output: String) -> String
{
	let (previous_group_key, _) = match import_sym_key(previous_group_key) {
		Ok(k) => k,
		Err(e) => return err_to_msg(e),
	};

	let (private_key, _) = match import_private_key(private_key) {
		Ok(k) => k,
		Err(e) => return err_to_msg(e),
	};

	let (public_key, public_key_id) = match import_public_key(public_key) {
		Ok(k) => k,
		Err(e) => return err_to_msg(e),
	};

	let server_output = match KeyRotationInput::from_string(server_output.as_bytes()).map_err(|_| Error::KeyRotationServerOutputWrong) {
		Ok(k) => k,
		Err(e) => return err_to_msg(e),
	};

	match done_key_rotation_internally(&private_key, &public_key, &previous_group_key, &server_output, public_key_id) {
		Ok(v) => v,
		Err(e) => err_to_msg(e),
	}
}

pub(crate) fn import_sym_key(key_string: String) -> Result<(SymKey, String), Error>
{
	let key_format = SymKeyFormat::from_string(key_string.as_bytes()).map_err(|_| Error::ImportSymmetricKeyFailed)?;

	match key_format {
		SymKeyFormat::Aes {
			key,
			key_id,
		} => {
			//to bytes via base64
			let bytes = Base64::decode_vec(key.as_str()).map_err(|_| Error::ImportSymmetricKeyFailed)?;

			let key = bytes
				.try_into()
				.map_err(|_| Error::ImportSymmetricKeyFailed)?;

			Ok((SymKey::Aes(key), key_id))
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
