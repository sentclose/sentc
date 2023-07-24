#[cfg(not(feature = "rust"))]
mod non_rust;
#[cfg(feature = "rust")]
mod rust;

use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::content_searchable::ListSearchItem;
use sentc_crypto_common::crypto::GeneratedSymKeyHeadServerRegisterOutput;
use sentc_crypto_utils::http::{auth_req, make_req, non_auth_req, HttpMethod};
use sentc_crypto_utils::{handle_general_server_response, handle_server_response};

#[cfg(not(feature = "rust"))]
pub(crate) use self::non_rust::{GenKeyRes, KeyRes, KeysRes, SearchRes, VoidRes};
#[cfg(feature = "rust")]
pub(crate) use self::rust::{GenKeyRes, KeyRes, KeysRes, SearchRes, VoidRes};

pub async fn register_sym_key(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	#[cfg(not(feature = "rust"))] master_key: &str,
	#[cfg(feature = "rust")] master_key: &sentc_crypto::entities::keys::SymKeyFormatInt,
) -> GenKeyRes
{
	let url = base_url + "/api/v1/keys/sym_key";
	let (server_input, encoded_key) = sentc_crypto::crypto::prepare_register_sym_key(master_key)?;

	let res = auth_req(HttpMethod::POST, url.as_str(), auth_token, Some(server_input), jwt).await?;

	let out: GeneratedSymKeyHeadServerRegisterOutput = handle_server_response(res.as_str())?;
	let key_id = out.key_id;

	#[cfg(feature = "rust")]
	{
		let mut encoded_key = encoded_key;

		sentc_crypto::crypto::done_register_sym_key(&key_id, &mut encoded_key);

		Ok((key_id, encoded_key))
	}

	#[cfg(not(feature = "rust"))]
	{
		let key = sentc_crypto::crypto::done_register_sym_key(&key_id, &encoded_key)?;

		Ok((key_id, key))
	}
}

pub async fn get_sym_key_by_id(
	base_url: String,
	auth_token: &str,
	key_id: &str,
	#[cfg(not(feature = "rust"))] master_key: &str,
	#[cfg(feature = "rust")] master_key: &sentc_crypto::entities::keys::SymKeyFormatInt,
) -> KeyRes
{
	let url = base_url + "/api/v1/keys/sym_key/" + key_id;

	let res = non_auth_req(HttpMethod::GET, url.as_str(), auth_token, None).await?;

	let sym_key = sentc_crypto::crypto::done_fetch_sym_key(master_key, res.as_str(), false)?;

	Ok(sym_key)
}

pub async fn get_keys_for_master_key(
	base_url: String,
	auth_token: &str,
	master_key_id: &str,
	last_fetched_time: &str,
	last_key_id: &str,
	#[cfg(not(feature = "rust"))] master_key: &str,
	#[cfg(feature = "rust")] master_key: &sentc_crypto::entities::keys::SymKeyFormatInt,
) -> KeysRes
{
	let url = base_url + "/api/v1/keys/sym_key/" + master_key_id + "/" + last_fetched_time + "/" + last_key_id;

	let res = non_auth_req(HttpMethod::GET, url.as_str(), auth_token, None).await?;

	let sym_keys = sentc_crypto::crypto::done_fetch_sym_keys(master_key, res.as_str())?;

	Ok(sym_keys)
}

pub async fn delete_key(base_url: String, auth_token: &str, jwt: &str, key_id: &str) -> VoidRes
{
	let url = base_url + "/api/v1/keys/sym_key/" + key_id;

	let res = auth_req(HttpMethod::DELETE, url.as_str(), auth_token, None, jwt).await?;

	Ok(handle_general_server_response(res.as_str())?)
}

//__________________________________________________________________________________________________

pub async fn register_key_by_public_key(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	#[cfg(not(feature = "rust"))] public_key: &str,
	#[cfg(feature = "rust")] public_key: &sentc_crypto_common::user::UserPublicKeyData,
) -> GenKeyRes
{
	let url = base_url + "/api/v1/keys/sym_key";

	let (server_input, encoded_key) = sentc_crypto::crypto::prepare_register_sym_key_by_public_key(public_key)?;

	let res = auth_req(HttpMethod::POST, url.as_str(), auth_token, Some(server_input), jwt).await?;

	let out: GeneratedSymKeyHeadServerRegisterOutput = handle_server_response(res.as_str())?;
	let key_id = out.key_id;

	#[cfg(feature = "rust")]
	{
		let mut encoded_key = encoded_key;

		sentc_crypto::crypto::done_register_sym_key(&key_id, &mut encoded_key);

		Ok((key_id, encoded_key))
	}

	#[cfg(not(feature = "rust"))]
	{
		let key = sentc_crypto::crypto::done_register_sym_key(&key_id, &encoded_key)?;

		Ok((key_id, key))
	}
}

pub async fn get_sym_key_by_id_by_private_key(
	base_url: String,
	auth_token: &str,
	key_id: &str,
	#[cfg(not(feature = "rust"))] private_key: &str,
	#[cfg(feature = "rust")] private_key: &sentc_crypto::entities::keys::PrivateKeyFormatInt,
) -> KeyRes
{
	let url = base_url + "/api/v1/keys/sym_key/" + key_id;

	let res = non_auth_req(HttpMethod::GET, url.as_str(), auth_token, None).await?;

	let sym_key = sentc_crypto::crypto::done_fetch_sym_key_by_private_key(private_key, res.as_str(), false)?;

	Ok(sym_key)
}

//__________________________________________________________________________________________________
//searchable

pub async fn search(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	group_as_member: Option<&str>,
	cat_id: Option<&str>,
	#[cfg(not(feature = "rust"))] key: &str,
	#[cfg(feature = "rust")] key: &sentc_crypto::entities::keys::HmacKeyFormatInt,
	data: &str,
	last_fetched_time: &str,
	last_fetched_group_id: &str,
) -> SearchRes
{
	let search_str = sentc_crypto::crypto_searchable::search(key, data)?;

	let url = match cat_id {
		Some(c_id) => {
			base_url + "/api/v1/search/group/" + id + "/" + c_id + "/" + last_fetched_time + "/" + last_fetched_group_id + "?search=" + &search_str
		},
		None => base_url + "/api/v1/search/group/" + id + "/all/" + last_fetched_time + "/" + last_fetched_group_id + "?search=" + &search_str,
	};

	let res = make_req(
		HttpMethod::GET,
		url.as_str(),
		auth_token,
		None,
		Some(jwt),
		group_as_member,
	)
	.await?;

	let list: Vec<ListSearchItem> = handle_server_response(&res)?;

	Ok(list)
}
