use alloc::string::{String, ToString};
use alloc::vec::Vec;

use sentc_crypto::util::public::{handle_general_server_response, handle_server_response};
use sentc_crypto_common::file::{FileData, FilePartListItem};

use crate::util::{make_req, make_req_buffer, make_req_buffer_body, HttpMethod};

#[cfg(not(feature = "rust"))]
mod non_rust;
#[cfg(feature = "rust")]
mod rust;

#[cfg(not(feature = "rust"))]
pub use self::non_rust::{ByteRes, FilePartRes, FileRegRes, FileRes, KeyRes, VoidRes};
#[cfg(feature = "rust")]
pub use self::rust::{ByteRes, FilePartRes, FileRegRes, FileRes, KeyRes, VoidRes};

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

	let res = make_req(HttpMethod::GET, url.as_str(), auth_token, None, jwt, group_as_member).await?;

	let file_data: FileData = handle_server_response(res.as_str())?;

	Ok(file_data)
}

pub async fn download_part_list(base_url: String, auth_token: &str, file_id: &str, last_sequence: &str) -> FilePartRes
{
	let url = base_url + "/api/v1/file/" + file_id + "/part_fetch/" + last_sequence;

	let res = make_req(HttpMethod::GET, url.as_str(), auth_token, None, None, None).await?;

	let file_parts: Vec<FilePartListItem> = handle_server_response(res.as_str())?;

	Ok(file_parts)
}

#[allow(clippy::needless_question_mark)]
pub async fn download_and_decrypt_file_part_start(
	base_url: String,
	url_prefix: Option<String>,
	auth_token: &str,
	part_id: &str,
	#[cfg(not(feature = "rust"))] content_key: &str,
	#[cfg(feature = "rust")] content_key: &sentc_crypto::entities::keys::SymKeyFormatInt,
	#[cfg(not(feature = "rust"))] verify_key_data: Option<&str>,
	#[cfg(feature = "rust")] verify_key_data: Option<&sentc_crypto_common::user::UserVerifyKeyData>,
) -> ByteRes
{
	let url_prefix = match url_prefix {
		Some(p) => p,
		None => base_url + "/api/v1/file/part",
	};

	let url = url_prefix + "/" + part_id;

	let res = make_req_buffer(HttpMethod::GET, url.as_str(), auth_token, None, None, None).await?;

	//decrypt the part
	Ok(sentc_crypto::file::decrypt_file_part_start(
		content_key,
		&res,
		verify_key_data,
	)?)
}

#[allow(clippy::needless_question_mark)]
pub async fn download_and_decrypt_file_part(
	base_url: String,
	url_prefix: Option<String>,
	auth_token: &str,
	part_id: &str,
	#[cfg(not(feature = "rust"))] pre_key: &str,
	#[cfg(feature = "rust")] pre_key: &sentc_crypto::sdk_core::SymKey,
	#[cfg(not(feature = "rust"))] verify_key_data: Option<&str>,
	#[cfg(feature = "rust")] verify_key_data: Option<&sentc_crypto_common::user::UserVerifyKeyData>,
) -> ByteRes
{
	let url_prefix = match url_prefix {
		Some(p) => p,
		None => base_url + "/api/v1/file/part",
	};

	let url = url_prefix + "/" + part_id;

	let res = make_req_buffer(HttpMethod::GET, url.as_str(), auth_token, None, None, None).await?;

	//decrypt the part
	Ok(sentc_crypto::file::decrypt_file_part(pre_key, &res, verify_key_data)?)
}

//__________________________________________________________________________________________________

pub async fn register_file(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	master_key_id: String,
	#[cfg(not(feature = "rust"))] content_key: &str,
	#[cfg(feature = "rust")] content_key: &sentc_crypto::entities::keys::SymKeyFormatInt,
	encrypted_content_key: String,
	belongs_to_id: Option<String>,
	#[cfg(not(feature = "rust"))] belongs_to_type: &str,
	#[cfg(feature = "rust")] belongs_to_type: sentc_crypto_common::file::BelongsToType,
	file_name: Option<String>,
	group_id: Option<&str>,
	group_as_member: Option<&str>,
) -> FileRegRes
{
	let (input, encrypted_file_name) = sentc_crypto::file::prepare_register_file(
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
		url.as_str(),
		auth_token,
		Some(input),
		Some(jwt),
		group_as_member,
	)
	.await?;

	let (file_id, session_id) = sentc_crypto::file::done_register_file(res.as_str())?;

	Ok((file_id, session_id, encrypted_file_name))
}

pub async fn upload_part_start(
	base_url: String,
	url_prefix: Option<String>,
	auth_token: &str,
	jwt: &str,
	session_id: &str,
	end: bool,
	sequence: i32,
	#[cfg(not(feature = "rust"))] content_key: &str,
	#[cfg(feature = "rust")] content_key: &sentc_crypto::entities::keys::SymKeyFormatInt,
	#[cfg(not(feature = "rust"))] sign_key: Option<&str>,
	#[cfg(feature = "rust")] sign_key: Option<&sentc_crypto::entities::keys::SignKeyFormatInt>,
	part: &[u8],
) -> KeyRes
{
	let url_prefix = match url_prefix {
		Some(p) => p,
		None => base_url + "/api/v1/file/part",
	};

	let (encrypted, next_file_key) = sentc_crypto::file::encrypt_file_part_start(content_key, part, sign_key)?;

	let url = url_prefix + "/" + session_id + "/" + sequence.to_string().as_str() + "/" + end.to_string().as_str();

	let res = make_req_buffer_body(HttpMethod::POST, url.as_str(), auth_token, encrypted, Some(jwt), None).await?;

	handle_general_server_response(res.as_str())?;

	Ok(next_file_key)
}

pub async fn upload_part(
	base_url: String,
	url_prefix: Option<String>,
	auth_token: &str,
	jwt: &str,
	session_id: &str,
	end: bool,
	sequence: i32,
	#[cfg(not(feature = "rust"))] content_key: &str,
	#[cfg(feature = "rust")] content_key: &sentc_crypto::sdk_core::SymKey,
	#[cfg(not(feature = "rust"))] sign_key: Option<&str>,
	#[cfg(feature = "rust")] sign_key: Option<&sentc_crypto::entities::keys::SignKeyFormatInt>,
	part: &[u8],
) -> KeyRes
{
	let url_prefix = match url_prefix {
		Some(p) => p,
		None => base_url + "/api/v1/file/part",
	};

	let (encrypted, next_file_key) = sentc_crypto::file::encrypt_file_part(content_key, part, sign_key)?;

	let url = url_prefix + "/" + session_id + "/" + sequence.to_string().as_str() + "/" + end.to_string().as_str();

	let res = make_req_buffer_body(HttpMethod::POST, url.as_str(), auth_token, encrypted, Some(jwt), None).await?;

	handle_general_server_response(res.as_str())?;

	Ok(next_file_key)
}

pub async fn update_file_name(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	file_id: &str,
	#[cfg(not(feature = "rust"))] content_key: &str,
	#[cfg(feature = "rust")] content_key: &sentc_crypto::entities::keys::SymKeyFormatInt,
	file_name: Option<String>,
) -> VoidRes
{
	let input = sentc_crypto::file::prepare_file_name_update(content_key, file_name)?;

	let url = base_url + "/api/v1/file/" + file_id;

	let res = make_req(
		HttpMethod::PUT,
		url.as_str(),
		auth_token,
		Some(input),
		Some(jwt),
		None,
	)
	.await?;

	Ok(handle_general_server_response(res.as_str())?)
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

	let res = make_req(
		HttpMethod::DELETE,
		url.as_str(),
		auth_token,
		None,
		Some(jwt),
		group_as_member,
	)
	.await?;

	Ok(handle_general_server_response(res.as_str())?)
}
