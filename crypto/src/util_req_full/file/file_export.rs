use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_std_keys::util::SymmetricKey;

use crate::crypto::{prepare_sign_key, prepare_verify_key};
use crate::util::{export_core_sym_key_to_string, import_core_sym_key};
use crate::StdFileEncryptor;

pub async fn download_and_decrypt_file_part_start(
	base_url: String,
	url_prefix: Option<String>,
	auth_token: &str,
	part_id: &str,
	content_key: &str,
	verify_key_data: Option<&str>,
) -> Result<(Vec<u8>, String), String>
{
	let verify_key = prepare_verify_key(verify_key_data)?;
	let key: SymmetricKey = content_key.parse()?;

	let (decrypted, next_key) =
		StdFileEncryptor::download_and_decrypt_file_part_start(base_url, url_prefix, auth_token, part_id, &key, verify_key.as_ref()).await?;

	let exported_file_key = export_core_sym_key_to_string(next_key)?;

	Ok((decrypted, exported_file_key))
}

pub async fn download_and_decrypt_file_part(
	base_url: String,
	url_prefix: Option<String>,
	auth_token: &str,
	part_id: &str,
	pre_key: &str,
	verify_key_data: Option<&str>,
) -> Result<(Vec<u8>, String), String>
{
	let verify_key = prepare_verify_key(verify_key_data)?;
	let key = import_core_sym_key(pre_key)?;

	let (decrypted, next_key) =
		StdFileEncryptor::download_and_decrypt_file_part(base_url, url_prefix, auth_token, part_id, &key, verify_key.as_ref()).await?;

	let exported_file_key = export_core_sym_key_to_string(next_key)?;

	Ok((decrypted, exported_file_key))
}

//__________________________________________________________________________________________________

#[allow(clippy::too_many_arguments)]
pub async fn upload_part_start(
	base_url: String,
	url_prefix: Option<String>,
	auth_token: &str,
	jwt: &str,
	session_id: &str,
	end: bool,
	sequence: i32,
	content_key: &str,
	sign_key: Option<&str>,
	part: &[u8],
) -> Result<String, String>
{
	let sign_key = prepare_sign_key(sign_key)?;
	let key: SymmetricKey = content_key.parse()?;

	let next_file_key = StdFileEncryptor::upload_part_start(
		base_url,
		url_prefix,
		auth_token,
		jwt,
		session_id,
		end,
		sequence,
		&key,
		sign_key.as_ref(),
		part,
	)
	.await?;

	Ok(export_core_sym_key_to_string(next_file_key)?)
}

#[allow(clippy::too_many_arguments)]
pub async fn upload_part(
	base_url: String,
	url_prefix: Option<String>,
	auth_token: &str,
	jwt: &str,
	session_id: &str,
	end: bool,
	sequence: i32,
	content_key: &str,
	sign_key: Option<&str>,
	part: &[u8],
) -> Result<String, String>
{
	let sign_key = prepare_sign_key(sign_key)?;
	let key = import_core_sym_key(content_key)?;

	let next_file_key = StdFileEncryptor::upload_part(
		base_url,
		url_prefix,
		auth_token,
		jwt,
		session_id,
		end,
		sequence,
		&key,
		sign_key.as_ref(),
		part,
	)
	.await?;

	Ok(export_core_sym_key_to_string(next_file_key)?)
}
