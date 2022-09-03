#[cfg(not(feature = "rust"))]
mod file;
#[cfg(feature = "rust")]
mod file_rust;

use alloc::string::String;

use sentc_crypto_common::file::{BelongsToType, FileNameUpdate, FileRegisterInput, FileRegisterOutput};
use sentc_crypto_common::{FileId, FileSessionId};

#[cfg(not(feature = "rust"))]
pub use self::file::{done_register_file, prepare_file_name_update, prepare_register_file};
#[cfg(feature = "rust")]
pub use self::file_rust::{done_register_file, prepare_file_name_update, prepare_register_file};
use crate::util::public::handle_server_response;
use crate::util::SymKeyFormatInt;
use crate::{crypto, SdkError};

fn prepare_register_file_internally(
	key: &SymKeyFormatInt,
	belongs_to_id: Option<String>,
	belongs_to_type: BelongsToType,
	file_name: Option<String>,
) -> Result<String, SdkError>
{
	let key_id = key.key_id.clone();

	// this check is already done in the backend too
	let (belongs_to_type, belongs_to_id) = match belongs_to_type {
		BelongsToType::None => (belongs_to_type, None),
		_ => {
			//check if the id is set

			if belongs_to_id.is_none() {
				(BelongsToType::None, None)
			} else {
				(belongs_to_type, belongs_to_id)
			}
		},
	};

	let encrypted_file_name = match file_name {
		None => None,
		Some(f) => {
			//encrypt the filename with the sym key
			Some(crypto::encrypt_string_symmetric_internally(key, &f, None)?)
		},
	};

	serde_json::to_string(&FileRegisterInput {
		key_id,
		belongs_to_id,
		belongs_to_type,
		encrypted_file_name,
	})
	.map_err(|_e| SdkError::JsonToStringFailed)
}

fn done_register_file_internally(server_output: &str) -> Result<(FileId, FileSessionId), SdkError>
{
	let out: FileRegisterOutput = handle_server_response(server_output)?;

	Ok((out.file_id, out.session_id))
}

fn prepare_file_name_update_internally(key: &SymKeyFormatInt, file_name: Option<String>) -> Result<String, SdkError>
{
	let encrypted_file_name = match file_name {
		None => None,
		Some(f) => {
			//encrypt the filename with the sym key
			Some(crypto::encrypt_string_symmetric_internally(key, &f, None)?)
		},
	};

	serde_json::to_string(&FileNameUpdate {
		encrypted_file_name,
	})
	.map_err(|_e| SdkError::JsonToStringFailed)
}
