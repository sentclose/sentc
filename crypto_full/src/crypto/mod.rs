#[cfg(not(feature = "rust"))]
mod non_rust;
#[cfg(feature = "rust")]
mod rust;

use alloc::string::String;

use sentc_crypto::util::public::{handle_general_server_response, handle_server_response};
use sentc_crypto_common::crypto::GeneratedSymKeyHeadServerRegisterOutput;

#[cfg(not(feature = "rust"))]
pub(crate) use self::non_rust::{KeyRes, KeysRes, Res, VoidRes};
#[cfg(feature = "rust")]
pub(crate) use self::rust::{KeyRes, KeysRes, Res, VoidRes};
use crate::util::{make_non_auth_req, make_req, HttpMethod};

pub async fn register_sym_key(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	#[cfg(not(feature = "rust"))] master_key: &str,
	#[cfg(feature = "rust")] master_key: &sentc_crypto::util::SymKeyFormat,
) -> Res
{
	let url = base_url + "/api/v1/keys/sym_key";
	let key_data = sentc_crypto::crypto::prepare_register_sym_key(master_key)?;

	let res = make_req(HttpMethod::POST, url.as_str(), auth_token, Some(key_data), Some(jwt)).await?;

	let out: GeneratedSymKeyHeadServerRegisterOutput = handle_server_response(res.as_str())?;

	Ok(out.key_id)
}

pub async fn get_sym_key_by_id(
	base_url: String,
	auth_token: &str,
	key_id: &str,
	#[cfg(not(feature = "rust"))] master_key: &str,
	#[cfg(feature = "rust")] master_key: &sentc_crypto::util::SymKeyFormat,
) -> KeyRes
{
	let url = base_url + "api/v1/keys/sym_key/" + key_id;

	let res = make_non_auth_req(HttpMethod::GET, url.as_str(), auth_token, None).await?;

	let sym_key = sentc_crypto::crypto::done_fetch_sym_key(master_key, res.as_str())?;

	Ok(sym_key)
}

pub async fn get_keys_for_master_key(
	base_url: String,
	auth_token: &str,
	master_key_id: &str,
	last_fetched_time: &str,
	last_key_id: &str,
	#[cfg(not(feature = "rust"))] master_key: &str,
	#[cfg(feature = "rust")] master_key: &sentc_crypto::util::SymKeyFormat,
) -> KeysRes
{
	let url = base_url + "api/v1/keys/sym_key/" + master_key_id + "/" + last_fetched_time + "/" + last_key_id;

	let res = make_non_auth_req(HttpMethod::GET, url.as_str(), auth_token, None).await?;

	let sym_keys = sentc_crypto::crypto::done_fetch_sym_keys(master_key, res.as_str())?;

	Ok(sym_keys)
}

pub async fn delete_key(base_url: String, auth_token: &str, jwt: &str, key_id: &str) -> VoidRes
{
	let url = base_url + "api/v1/keys/sym_key/" + key_id;

	let res = make_req(HttpMethod::DELETE, url.as_str(), auth_token, None, Some(jwt)).await?;

	Ok(handle_general_server_response(res.as_str())?)
}