use alloc::string::String;

use sentc_crypto_common::file::BelongsToType;
use sentc_crypto_common::{FileId, FileSessionId};

use crate::file::{done_register_file_internally, prepare_register_file_internally};
use crate::{SdkError, SymKeyFormat};

pub fn prepare_register_file(key: &SymKeyFormat, belongs_to_id: Option<String>, belongs_to_type: BelongsToType) -> Result<String, SdkError>
{
	prepare_register_file_internally(&key, belongs_to_id, belongs_to_type)
}

pub fn done_register_file(server_output: &str) -> Result<(FileId, FileSessionId), SdkError>
{
	done_register_file_internally(server_output)
}
