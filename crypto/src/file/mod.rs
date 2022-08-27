#[cfg(not(feature = "rust"))]
mod file;
#[cfg(feature = "rust")]
mod file_rust;

use alloc::string::String;

use sentc_crypto_common::file::{FileRegisterInput, FileRegisterOutput};
use sentc_crypto_common::FileSessionId;

#[cfg(not(feature = "rust"))]
pub use self::file::{done_register_file, prepare_register_file};
#[cfg(feature = "rust")]
pub use self::file_rust::{done_register_file, prepare_register_file};
use crate::util::public::handle_server_response;
use crate::util::SymKeyFormatInt;
use crate::SdkError;

fn prepare_register_file_internally(key: &SymKeyFormatInt) -> Result<String, SdkError>
{
	let key_id = key.key_id.clone();

	serde_json::to_string(&FileRegisterInput {
		key_id,
	})
	.map_err(|_e| SdkError::JsonToStringFailed)
}

fn done_register_file_internally(server_output: &str) -> Result<FileSessionId, SdkError>
{
	let out: FileRegisterOutput = handle_server_response(server_output)?;

	Ok(out.session_id)
}
