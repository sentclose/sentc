use alloc::string::{String, ToString};
use alloc::vec::Vec;

use sentc_crypto_common::file::BelongsToType;

use crate::crypto::{prepare_sign_key, prepare_verify_key};
use crate::file::{
	decrypt_file_part_internally,
	decrypt_file_part_start_internally,
	done_register_file_internally,
	encrypt_file_part_internally,
	encrypt_file_part_start_internally,
	prepare_file_name_update_internally,
	prepare_register_file_internally,
};
use crate::util::{export_core_sym_key_to_string, import_core_sym_key, import_sym_key};
use crate::SdkError;

pub fn prepare_register_file(
	master_key_id: String,
	key: &str,
	encrypted_content_key: String,
	belongs_to_id: Option<String>,
	belongs_to_type: &str,
	file_name: Option<String>,
) -> Result<(String, Option<String>), String>
{
	let key = import_sym_key(key)?;

	let belongs_to_type: BelongsToType = serde_json::from_str(belongs_to_type).map_err(SdkError::JsonParseFailed)?;

	let (server_input, encrypted_file_name) = prepare_register_file_internally(
		master_key_id,
		&key,
		encrypted_content_key,
		belongs_to_id,
		belongs_to_type,
		file_name,
	)?;

	Ok((server_input, encrypted_file_name))
}

pub fn done_register_file(server_output: &str) -> Result<(String, String), String>
{
	Ok(done_register_file_internally(server_output)?)
}

pub fn prepare_file_name_update(key: &str, file_name: &str) -> Result<String, String>
{
	let key = import_sym_key(key)?;

	let file_name = match file_name {
		"" => None,
		_ => Some(file_name.to_string()),
	};

	Ok(prepare_file_name_update_internally(&key, file_name)?)
}

pub fn encrypt_file_part_start(key: &str, part: &[u8], sign_key: Option<&str>) -> Result<(Vec<u8>, String), String>
{
	let sign_key = prepare_sign_key(sign_key)?;

	let key = import_sym_key(key)?;

	let (encrypted_part, file_key) = match sign_key {
		None => encrypt_file_part_start_internally(&key, part, None)?,
		Some(k) => encrypt_file_part_start_internally(&key, part, Some(&k))?,
	};

	let exported_file_key = export_core_sym_key_to_string(file_key)?;

	Ok((encrypted_part, exported_file_key))
}

pub fn encrypt_file_part(pre_content_key: &str, part: &[u8], sign_key: Option<&str>) -> Result<(Vec<u8>, String), String>
{
	let sign_key = prepare_sign_key(sign_key)?;

	let key = import_core_sym_key(pre_content_key)?;

	let (encrypted_part, file_key) = match sign_key {
		None => encrypt_file_part_internally(&key, part, None)?,
		Some(k) => encrypt_file_part_internally(&key, part, Some(&k))?,
	};

	let exported_file_key = export_core_sym_key_to_string(file_key)?;

	Ok((encrypted_part, exported_file_key))
}

pub fn decrypt_file_part_start(key: &str, part: &[u8], verify_key: Option<&str>) -> Result<(Vec<u8>, String), String>
{
	let verify_key = prepare_verify_key(verify_key)?;
	let key = import_sym_key(key)?;

	let (decrypted, next_key) = match verify_key {
		None => decrypt_file_part_start_internally(&key, part, None)?,
		Some(k) => decrypt_file_part_start_internally(&key, part, Some(&k))?,
	};

	let exported_file_key = export_core_sym_key_to_string(next_key)?;

	Ok((decrypted, exported_file_key))
}

pub fn decrypt_file_part(pre_content_key: &str, part: &[u8], verify_key: Option<&str>) -> Result<(Vec<u8>, String), String>
{
	let verify_key = prepare_verify_key(verify_key)?;

	let key = import_core_sym_key(pre_content_key)?;

	let (decrypted, next_key) = match verify_key {
		None => decrypt_file_part_internally(&key, part, None)?,
		Some(k) => decrypt_file_part_internally(&key, part, Some(&k))?,
	};

	let exported_file_key = export_core_sym_key_to_string(next_key)?;

	Ok((decrypted, exported_file_key))
}
