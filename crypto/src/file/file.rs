use alloc::string::String;

use crate::file::{done_register_file_internally, prepare_register_file_internally};
use crate::util::import_sym_key;

pub fn prepare_register_file(key: &str) -> Result<String, String>
{
	let key = import_sym_key(key)?;

	Ok(prepare_register_file_internally(&key)?)
}

pub fn done_register_file(server_output: &str) -> Result<String, String>
{
	Ok(done_register_file_internally(server_output)?)
}
