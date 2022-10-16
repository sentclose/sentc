use alloc::string::String;

use sentc_crypto_common::file::BelongsToType;
use sentc_crypto_common::{FileId, FileSessionId};

use crate::file::{done_register_file_internally, prepare_file_name_update_internally, prepare_register_file_internally};
use crate::{SdkError, SymKeyFormat};

pub fn prepare_register_file(
	master_key_id: String,
	key: &SymKeyFormat,
	belongs_to_id: Option<String>,
	belongs_to_type: BelongsToType,
	file_name: Option<String>,
) -> Result<(String, Option<String>), SdkError>
{
	prepare_register_file_internally(master_key_id, &key, belongs_to_id, belongs_to_type, file_name)
}

pub fn done_register_file(server_output: &str) -> Result<(FileId, FileSessionId), SdkError>
{
	done_register_file_internally(server_output)
}

pub fn prepare_file_name_update(key: &SymKeyFormat, file_name: Option<String>) -> Result<String, SdkError>
{
	prepare_file_name_update_internally(key, file_name)
}
