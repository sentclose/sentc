#[cfg(feature = "export")]
mod file_export;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[cfg(feature = "export")]
pub use file_export::*;
use sentc_crypto_common::file::{FileData, FilePartListItem};
use sentc_crypto_common::user::UserVerifyKeyData;
use sentc_crypto_core::cryptomat::{SymKey, SymKeyComposer, SymKeyGen};
use sentc_crypto_utils::cryptomat::{SignKWrapper, SymKeyWrapper, VerifyKFromUserKeyWrapper};
use sentc_crypto_utils::http::{make_req, make_req_buffer, make_req_buffer_body, HttpMethod};
use sentc_crypto_utils::{handle_general_server_response, handle_server_response};

use crate::file::FileEncryptor;
use crate::SdkError;

impl<S: SymKeyGen, SC: SymKeyComposer, VC: VerifyKFromUserKeyWrapper> FileEncryptor<S, SC, VC>
{
	pub async fn download_and_decrypt_file_part_start(
		base_url: String,
		url_prefix: Option<String>,
		auth_token: &str,
		part_id: &str,
		content_key: &impl SymKeyWrapper,
		verify_key_data: Option<&UserVerifyKeyData>,
	) -> Result<(Vec<u8>, SC::SymmetricKey), SdkError>
	{
		let url_prefix = match url_prefix {
			Some(p) => p,
			None => base_url + "/api/v1/file/part",
		};

		let url = url_prefix + "/" + part_id;

		let res = make_req_buffer(HttpMethod::GET, &url, auth_token, None, None, None).await?;

		//decrypt the part
		Self::decrypt_file_part_start(content_key, &res, verify_key_data)
	}

	pub async fn download_and_decrypt_file_part(
		base_url: String,
		url_prefix: Option<String>,
		auth_token: &str,
		part_id: &str,
		pre_key: &impl SymKey,
		verify_key_data: Option<&UserVerifyKeyData>,
	) -> Result<(Vec<u8>, SC::SymmetricKey), SdkError>
	{
		let url_prefix = match url_prefix {
			Some(p) => p,
			None => base_url + "/api/v1/file/part",
		};

		let url = url_prefix + "/" + part_id;

		let res = make_req_buffer(HttpMethod::GET, &url, auth_token, None, None, None).await?;

		//decrypt the part
		Self::decrypt_file_part(pre_key, &res, verify_key_data)
	}

	//______________________________________________________________________________________________

	#[allow(clippy::too_many_arguments)]
	pub async fn upload_part_start(
		base_url: String,
		url_prefix: Option<String>,
		auth_token: &str,
		jwt: &str,
		session_id: &str,
		end: bool,
		sequence: i32,
		content_key: &impl SymKeyWrapper,
		sign_key: Option<&impl SignKWrapper>,
		part: &[u8],
	) -> Result<S::SymmetricKey, SdkError>
	{
		let url_prefix = match url_prefix {
			Some(p) => p,
			None => base_url + "/api/v1/file/part",
		};

		let (encrypted, next_file_key) = Self::encrypt_file_part_start(content_key, part, sign_key)?;

		let url = url_prefix + "/" + session_id + "/" + sequence.to_string().as_str() + "/" + end.to_string().as_str();

		let res = make_req_buffer_body(HttpMethod::POST, &url, auth_token, encrypted, Some(jwt), None).await?;

		handle_general_server_response(&res)?;

		Ok(next_file_key)
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
		content_key: &impl SymKey,
		sign_key: Option<&impl SignKWrapper>,
		part: &[u8],
	) -> Result<S::SymmetricKey, SdkError>
	{
		let url_prefix = match url_prefix {
			Some(p) => p,
			None => base_url + "/api/v1/file/part",
		};

		let (encrypted, next_file_key) = Self::encrypt_file_part(content_key, part, sign_key)?;

		let url = url_prefix + "/" + session_id + "/" + sequence.to_string().as_str() + "/" + end.to_string().as_str();

		let res = make_req_buffer_body(HttpMethod::POST, &url, auth_token, encrypted, Some(jwt), None).await?;

		handle_general_server_response(&res)?;

		Ok(next_file_key)
	}
}

//__________________________________________________________________________________________________

#[cfg(feature = "export")]
type FileRes = Result<FileData, String>;
#[cfg(not(feature = "export"))]
type FileRes = Result<FileData, SdkError>;

pub async fn download_file_meta(
	base_url: String,
	auth_token: &str,
	file_id: &str,
	jwt: Option<&str>,
	group_id: Option<&str>,
	group_as_member: Option<&str>,
) -> FileRes
{
	let url = match group_id {
		Some(id) => base_url + "/api/v1/group/" + id + "/file/" + file_id,
		None => base_url + "/api/v1/file/" + file_id,
	};

	let res = make_req(HttpMethod::GET, &url, auth_token, None, jwt, group_as_member).await?;

	let file_data: FileData = handle_server_response(&res)?;

	Ok(file_data)
}

#[cfg(feature = "export")]
type FilePartRes = Result<Vec<FilePartListItem>, String>;
#[cfg(not(feature = "export"))]
type FilePartRes = Result<Vec<FilePartListItem>, SdkError>;

pub async fn download_part_list(base_url: String, auth_token: &str, file_id: &str, last_sequence: &str) -> FilePartRes
{
	let url = base_url + "/api/v1/file/" + file_id + "/part_fetch/" + last_sequence;

	let res = make_req(HttpMethod::GET, &url, auth_token, None, None, None).await?;

	let file_parts: Vec<FilePartListItem> = handle_server_response(&res)?;

	Ok(file_parts)
}

#[cfg(feature = "export")]
type FileRegRes = Result<(String, String, Option<String>), String>;
#[cfg(not(feature = "export"))]
type FileRegRes = Result<(String, String, Option<String>), SdkError>;

#[allow(clippy::too_many_arguments)]
pub async fn register_file(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	master_key_id: String,
	#[cfg(feature = "export")] content_key: &str,
	#[cfg(not(feature = "export"))] content_key: &impl SymKeyWrapper,
	encrypted_content_key: String,
	belongs_to_id: Option<String>,
	#[cfg(feature = "export")] belongs_to_type: &str,
	#[cfg(not(feature = "export"))] belongs_to_type: sentc_crypto_common::file::BelongsToType,
	file_name: Option<String>,
	group_id: Option<&str>,
	group_as_member: Option<&str>,
) -> FileRegRes
{
	let (input, encrypted_file_name) = crate::file::prepare_register_file(
		master_key_id,
		content_key,
		encrypted_content_key,
		belongs_to_id,
		belongs_to_type,
		file_name,
	)?;

	let url = match group_id {
		Some(id) => base_url + "/api/v1/group/" + id + "/file",
		None => base_url + "/api/v1/file",
	};

	let res = make_req(
		HttpMethod::POST,
		&url,
		auth_token,
		Some(input),
		Some(jwt),
		group_as_member,
	)
	.await?;

	let (file_id, session_id) = crate::file::done_register_file(&res)?;

	Ok((file_id, session_id, encrypted_file_name))
}

#[cfg(feature = "export")]
type VoidRes = Result<(), String>;
#[cfg(not(feature = "export"))]
type VoidRes = Result<(), SdkError>;

pub async fn update_file_name(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	file_id: &str,
	#[cfg(feature = "export")] content_key: &str,
	#[cfg(not(feature = "export"))] content_key: &impl SymKeyWrapper,
	file_name: Option<String>,
) -> VoidRes
{
	let input = crate::file::prepare_file_name_update(content_key, file_name)?;

	let url = base_url + "/api/v1/file/" + file_id;

	let res = make_req(HttpMethod::PUT, &url, auth_token, Some(input), Some(jwt), None).await?;

	Ok(handle_general_server_response(&res)?)
}

pub async fn delete_file(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	file_id: &str,
	group_id: Option<&str>,
	group_as_member: Option<&str>,
) -> VoidRes
{
	let url = match group_id {
		Some(id) => base_url + "/api/v1/group/" + id + "/file/" + file_id,
		None => base_url + "/api/v1/file/" + file_id,
	};

	let res = make_req(HttpMethod::DELETE, &url, auth_token, None, Some(jwt), group_as_member).await?;

	Ok(handle_general_server_response(&res)?)
}
