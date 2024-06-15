use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::file::BelongsToType;
use sentc_crypto_core::SymmetricKey as CoreSymKey;
use sentc_crypto_utils::keys::{SignKey, SymmetricKey, VerifyKey};

use crate::crypto::{prepare_sign_key, prepare_verify_key};
use crate::util::{export_core_sym_key_to_string, import_core_sym_key};
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
	let belongs_to_type: BelongsToType = serde_json::from_str(belongs_to_type).map_err(SdkError::JsonParseFailed)?;

	let key: SymmetricKey = key.parse()?;

	let (server_input, encrypted_file_name) = super::file::prepare_register_file(
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
	Ok(super::file::done_register_file(server_output)?)
}

pub fn prepare_file_name_update(key: &str, file_name: Option<String>) -> Result<String, String>
{
	let key: SymmetricKey = key.parse()?;
	Ok(super::file::prepare_file_name_update(&key, file_name)?)
}

pub fn encrypt_file_part_start(key: &str, part: &[u8], sign_key: Option<&str>) -> Result<(Vec<u8>, String), String>
{
	let sign_key = prepare_sign_key(sign_key)?;

	let key: SymmetricKey = key.parse()?;

	let (encrypted_part, file_key) = match sign_key {
		None => super::file::encrypt_file_part_start::<CoreSymKey>(&key, part, None::<&SignKey>)?,
		Some(k) => super::file::encrypt_file_part_start::<CoreSymKey>(&key, part, Some(&k))?,
	};

	let exported_file_key = export_core_sym_key_to_string(file_key)?;

	Ok((encrypted_part, exported_file_key))
}

pub fn encrypt_file_part(pre_content_key: &str, part: &[u8], sign_key: Option<&str>) -> Result<(Vec<u8>, String), String>
{
	let sign_key = prepare_sign_key(sign_key)?;

	let key = import_core_sym_key(pre_content_key)?;

	let (encrypted_part, file_key) = match sign_key {
		None => super::file::encrypt_file_part::<CoreSymKey>(&key, part, None::<&SignKey>)?,
		Some(k) => super::file::encrypt_file_part::<CoreSymKey>(&key, part, Some(&k))?,
	};

	let exported_file_key = export_core_sym_key_to_string(file_key)?;

	Ok((encrypted_part, exported_file_key))
}

pub fn decrypt_file_part_start(key: &str, part: &[u8], verify_key: Option<&str>) -> Result<(Vec<u8>, String), String>
{
	let verify_key = prepare_verify_key(verify_key)?;
	let key: SymmetricKey = key.parse()?;

	let (decrypted, next_key) = match verify_key {
		None => super::file::decrypt_file_part_start::<VerifyKey, CoreSymKey>(&key, part, None)?,
		Some(k) => super::file::decrypt_file_part_start::<VerifyKey, CoreSymKey>(&key, part, Some(&k))?,
	};

	let exported_file_key = export_core_sym_key_to_string(next_key)?;

	Ok((decrypted, exported_file_key))
}

pub fn decrypt_file_part(pre_content_key: &str, part: &[u8], verify_key: Option<&str>) -> Result<(Vec<u8>, String), String>
{
	let verify_key = prepare_verify_key(verify_key)?;

	let key = import_core_sym_key(pre_content_key)?;

	let (decrypted, next_key) = match verify_key {
		None => super::file::decrypt_file_part::<VerifyKey, CoreSymKey>(&key, part, None)?,
		Some(k) => super::file::decrypt_file_part::<VerifyKey, CoreSymKey>(&key, part, Some(&k))?,
	};

	let exported_file_key = export_core_sym_key_to_string(next_key)?;

	Ok((decrypted, exported_file_key))
}
