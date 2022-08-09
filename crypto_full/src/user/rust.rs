use alloc::string::String;

use sentc_crypto::{user, KeyData};

use crate::error::SdkFullError;
use crate::util::{make_non_auth_req, HttpMethod};

pub async fn login(base_url: String, auth_token: &str, user_identifier: &str, password: &str) -> Result<KeyData, SdkFullError>
{
	let user_id_input = user::prepare_login_start(user_identifier)?;

	let url = base_url.clone() + "/api/v1/prepare_login";

	let res = make_non_auth_req(HttpMethod::POST, url.as_str(), auth_token, Some(user_id_input)).await?;

	//prepare the login, the auth key is already in the right json format for the server
	let (auth_key, master_key_encryption_key) = user::prepare_login(user_identifier, password, res.as_str())?;

	let url = base_url + "/api/v1/done_login";

	let server_out = make_non_auth_req(HttpMethod::POST, url.as_str(), auth_token, Some(auth_key)).await?;

	let keys = user::done_login(&master_key_encryption_key, server_out.as_str())?;

	Ok(keys)
}
