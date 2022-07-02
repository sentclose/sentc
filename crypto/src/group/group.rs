use base64ct::{Base64, Encoding};
use sendclose_crypto_common::SymKeyFormat;
use sendclose_crypto_core::{Error, SymKey};

use crate::err_to_msg;
use crate::group::{key_rotation_internally, prepare_create_internally};
use crate::user::user::import_public_key;

pub fn prepare_create(creators_public_key: String, creator_public_key_id: String) -> String
{
	let creators_public_key = match import_public_key(creators_public_key) {
		Ok(k) => k,
		Err(e) => return err_to_msg(e),
	};

	match prepare_create_internally(&creators_public_key, creator_public_key_id) {
		Ok(v) => v,
		Err(e) => err_to_msg(e),
	}
}

pub fn key_rotation(previous_group_key: String, invoker_public_key: String, previous_group_key_id: String, invoker_public_key_id: String) -> String
{
	//the ids comes from the storage of the current impl from the sdk, the group key id comes from get group
	let previous_group_key = match import_sym_key(previous_group_key) {
		Ok(k) => k,
		Err(e) => return err_to_msg(e),
	};

	let invoker_public_key = match import_public_key(invoker_public_key) {
		Ok(k) => k,
		Err(e) => return err_to_msg(e),
	};

	match key_rotation_internally(&previous_group_key, &invoker_public_key, previous_group_key_id, invoker_public_key_id) {
		Ok(v) => v,
		Err(e) => err_to_msg(e),
	}
}

pub(crate) fn import_sym_key(key_string: String) -> Result<SymKey, Error>
{
	let key_format = SymKeyFormat::from_string(key_string.as_bytes()).map_err(|_| Error::ImportSymmetricKeyFailed)?;

	match key_format {
		SymKeyFormat::Aes(k) => {
			//to bytes via base64
			let bytes = Base64::decode_vec(k.as_str()).map_err(|_| Error::ImportSymmetricKeyFailed)?;

			let key = bytes
				.try_into()
				.map_err(|_| Error::ImportSymmetricKeyFailed)?;

			Ok(SymKey::Aes(key))
		},
	}
}

pub(crate) fn export_sym_key(key: SymKey) -> SymKeyFormat
{
	match key {
		SymKey::Aes(k) => {
			let sym_key = Base64::encode_string(&k);

			SymKeyFormat::Aes(sym_key)
		},
	}
}
