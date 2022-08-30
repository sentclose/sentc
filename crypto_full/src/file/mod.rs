use alloc::string::{String, ToString};

use sentc_crypto::util::public::{handle_general_server_response, handle_server_response};
use sentc_crypto_common::file::FileData;

use crate::util::{make_req, make_req_buffer, make_req_buffer_body, HttpMethod};

#[cfg(not(feature = "rust"))]
mod non_rust;
#[cfg(feature = "rust")]
mod rust;

#[cfg(not(feature = "rust"))]
pub use self::non_rust::{ByteRes, FileRegRes, FileRes, VoidRes};
#[cfg(feature = "rust")]
pub use self::rust::{ByteRes, FileRegRes, FileRes, VoidRes};

pub async fn download_file_meta(base_url: String, auth_token: &str, jwt: &str, file_id: &str) -> FileRes
{
	let url = base_url + "/api/v1/file/" + file_id;

	let res = make_req(HttpMethod::GET, url.as_str(), auth_token, None, Some(jwt)).await?;

	let file_data: FileData = handle_server_response(res.as_str())?;

	Ok(file_data)
}

pub async fn download_and_decrypt_file_part(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	part_id: &str,
	#[cfg(not(feature = "rust"))] content_key: &str,
	#[cfg(feature = "rust")] content_key: &sentc_crypto::util::SymKeyFormat,
	#[cfg(not(feature = "rust"))] verify_key_data: &str,
	#[cfg(feature = "rust")] verify_key_data: Option<&sentc_crypto_common::user::UserVerifyKeyData>,
) -> ByteRes
{
	let url = base_url + "/api/v1/file/part/" + part_id;

	let res = make_req_buffer(HttpMethod::GET, url.as_str(), auth_token, None, Some(jwt)).await?;

	//decrypt the part
	let decrypted = sentc_crypto::crypto::decrypt_symmetric(content_key, &res, verify_key_data)?;

	Ok(decrypted)
}

//__________________________________________________________________________________________________

pub async fn register_file(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	#[cfg(not(feature = "rust"))] content_key: &str,
	#[cfg(feature = "rust")] content_key: &sentc_crypto::util::SymKeyFormat,
	#[cfg(not(feature = "rust"))] belongs_to_id: &str,
	#[cfg(feature = "rust")] belongs_to_id: Option<String>,
	#[cfg(not(feature = "rust"))] belongs_to_type: &str,
	#[cfg(feature = "rust")] belongs_to_type: sentc_crypto_common::file::BelongsToType,
) -> FileRegRes
{
	let input = sentc_crypto::file::prepare_register_file(content_key, belongs_to_id, belongs_to_type)?;

	let url = base_url + "/api/v1/file/";

	let res = make_req(HttpMethod::POST, url.as_str(), auth_token, Some(input), Some(jwt)).await?;

	let out = sentc_crypto::file::done_register_file(res.as_str())?;

	Ok(out)
}

pub async fn upload_part(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	session_id: &str,
	end: bool,
	sequence: i32,
	#[cfg(not(feature = "rust"))] content_key: &str,
	#[cfg(feature = "rust")] content_key: &sentc_crypto::util::SymKeyFormat,
	#[cfg(not(feature = "rust"))] sign_key: &str,
	#[cfg(feature = "rust")] sign_key: Option<&sentc_crypto::util::SignKeyFormat>,
	part: &[u8],
) -> VoidRes
{
	let encrypted = sentc_crypto::crypto::encrypt_symmetric(content_key, part, sign_key)?;

	let url = base_url + "/api/v1/file/part/" + session_id + "/seq/" + sequence.to_string().as_str() + "/end/" + end.to_string().as_str();

	let res = make_req_buffer_body(HttpMethod::POST, url.as_str(), auth_token, encrypted, Some(jwt)).await?;

	Ok(handle_general_server_response(res.as_str())?)
}
