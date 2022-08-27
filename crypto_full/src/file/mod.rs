use alloc::string::String;

use sentc_crypto::util::public::handle_server_response;
use sentc_crypto_common::file::FileData;

use crate::util::{make_req, make_req_buffer, HttpMethod};

#[cfg(not(feature = "rust"))]
mod non_rust;
#[cfg(feature = "rust")]
mod rust;

#[cfg(not(feature = "rust"))]
pub use self::non_rust::{ByteRes, FileRes};
#[cfg(feature = "rust")]
pub use self::rust::{ByteRes, FileRes};

pub async fn download_file_meta(base_url: String, auth_token: &str, jwt: &str, file_id: &str) -> FileRes
{
	let url = base_url + "/api/v1/file/meta/" + file_id;

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
	#[cfg(feature = "rust")] verify_key_data: &sentc_crypto_common::user::UserVerifyKeyData,
) -> ByteRes
{
	let url = base_url + "/api/v1/file/part/" + part_id;

	let res = make_req_buffer(HttpMethod::GET, url.as_str(), auth_token, None, Some(jwt)).await?;

	//decrypt the part
	let decrypted = sentc_crypto::crypto::decrypt_symmetric(content_key, &res, verify_key_data)?;

	Ok(decrypted)
}
