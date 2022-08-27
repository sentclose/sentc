use alloc::string::String;

use crate::{SdkError, SymKeyFormat};

pub fn prepare_register_file(key: &SymKeyFormat) -> Result<String, SdkError>
{
	prepare_register_file_internally(&key)
}

pub fn done_register_file(server_output: &str) -> Result<String, SdkError>
{
	done_register_file_internally(server_output)
}
