use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_utils::http::{auth_req, non_auth_req, HttpMethod};
use sentc_crypto_utils::{handle_general_server_response, handle_server_response};

#[cfg(not(feature = "rust"))]
mod non_rust;
#[cfg(feature = "rust")]
mod rust;

#[cfg(not(feature = "rust"))]
pub(crate) use self::non_rust::{BoolRes, DeviceListRes, InitRes, LoginRes, Res, VoidRes};
#[cfg(feature = "rust")]
pub(crate) use self::rust::{BoolRes, DeviceListRes, InitRes, LoginRes, Res, VoidRes};

//Register
pub async fn check_user_identifier_available(base_url: String, auth_token: &str, user_identifier: &str) -> BoolRes
{
	let server_input = sentc_crypto_light::user::prepare_check_user_identifier_available(user_identifier)?;

	let url = base_url + "/api/v1/exists";

	let res = non_auth_req(HttpMethod::POST, &url, auth_token, Some(server_input)).await?;
	let out = sentc_crypto_light::user::done_check_user_identifier_available(&res)?;

	Ok(out)
}

pub async fn register(base_url: String, auth_token: &str, user_identifier: &str, password: &str) -> Res
{
	let register_input = sentc_crypto_light::user::register(user_identifier, password)?;

	let url = base_url + "/api/v1/register_light";

	let res = non_auth_req(HttpMethod::POST, &url, auth_token, Some(register_input)).await?;

	let out = sentc_crypto_light::user::done_register(&res)?;

	Ok(out)
}

pub async fn register_device_start(base_url: String, auth_token: &str, device_identifier: &str, password: &str) -> Res
{
	let url = base_url + "/api/v1/user/prepare_register_device";

	let input = sentc_crypto_light::user::register(device_identifier, password)?;

	let res = non_auth_req(HttpMethod::POST, &url, auth_token, Some(input)).await?;

	//check the server output
	sentc_crypto_light::user::done_register_device_start(&res)?;

	Ok(res)
}

pub async fn register_device(base_url: String, auth_token: &str, jwt: &str, server_output: &str) -> VoidRes
{
	let url = base_url + "/api/v1/user/done_register_device_light";

	let input = sentc_crypto_light::user::prepare_register_device(server_output)?;

	let res = auth_req(HttpMethod::PUT, &url, auth_token, Some(input), jwt).await?;

	handle_general_server_response(&res)?;

	Ok(())
}

//__________________________________________________________________________________________________
//Login

pub async fn prepare_login_start(base_url: String, auth_token: &str, user_identifier: &str) -> Res
{
	let user_id_input = sentc_crypto_light::user::prepare_login_start(user_identifier)?;

	let url = base_url + "/api/v1/prepare_login";

	let res = non_auth_req(HttpMethod::POST, &url, auth_token, Some(user_id_input)).await?;

	Ok(res)
}

pub async fn done_login(base_url: String, auth_token: &str, user_identifier: &str, password: &str, prepare_login_server_output: &str) -> LoginRes
{
	let (auth_key, master_key_encryption_key) = sentc_crypto_light::user::prepare_login(user_identifier, password, prepare_login_server_output)?;

	let url = base_url + "/api/v1/done_login_light";

	let server_out = non_auth_req(HttpMethod::POST, &url, auth_token, Some(auth_key)).await?;

	let keys = sentc_crypto_light::user::done_login(&master_key_encryption_key, &server_out)?;

	Ok(keys)
}

pub async fn login(base_url: String, auth_token: &str, user_identifier: &str, password: &str) -> LoginRes
{
	let user_id_input = sentc_crypto_light::user::prepare_login_start(user_identifier)?;

	let url = base_url.clone() + "/api/v1/prepare_login";

	let res = non_auth_req(HttpMethod::POST, &url, auth_token, Some(user_id_input)).await?;

	//prepare the login, the auth key is already in the right json format for the server
	let (auth_key, master_key_encryption_key) = sentc_crypto_light::user::prepare_login(user_identifier, password, &res)?;

	let url = base_url + "/api/v1/done_login_light";

	let server_out = non_auth_req(HttpMethod::POST, &url, auth_token, Some(auth_key)).await?;

	let keys = sentc_crypto_light::user::done_login(&master_key_encryption_key, &server_out)?;

	Ok(keys)
}

pub async fn refresh_jwt(base_url: String, auth_token: &str, jwt: &str, refresh_token: String) -> Res
{
	let input = sentc_crypto_light::user::prepare_refresh_jwt(refresh_token)?;

	let url = base_url + "/api/v1/refresh";

	let res = auth_req(HttpMethod::PUT, &url, auth_token, Some(input), jwt).await?;

	let server_output: sentc_crypto_common::user::DoneLoginLightServerOutput = handle_server_response(&res)?;

	Ok(server_output.jwt)
}

pub async fn init_user(base_url: String, auth_token: &str, jwt: &str, refresh_token: String) -> InitRes
{
	let input = sentc_crypto_light::user::prepare_refresh_jwt(refresh_token)?;

	let url = base_url + "/api/v1/init";

	let res = auth_req(HttpMethod::POST, &url, auth_token, Some(input), jwt).await?;

	let server_output: sentc_crypto_common::user::UserInitServerOutput = handle_server_response(&res)?;

	Ok(server_output)
}

pub async fn get_user_devices(base_url: String, auth_token: &str, jwt: &str, last_fetched_time: &str, last_fetched_id: &str) -> DeviceListRes
{
	let url = base_url + "/api/v1/user/device/" + last_fetched_time + "/" + last_fetched_id;

	let res = auth_req(HttpMethod::GET, url.as_str(), auth_token, None, jwt).await?;

	let out: Vec<sentc_crypto_common::user::UserDeviceList> = handle_server_response(res.as_str())?;

	Ok(out)
}

//__________________________________________________________________________________________________

pub async fn change_password(base_url: String, auth_token: &str, user_identifier: &str, old_password: &str, new_password: &str) -> VoidRes
{
	//first make the prep login req to get the output
	let prep_login_out = prepare_login_start(base_url.clone(), auth_token, user_identifier).await?;

	let (auth_key, master_key_encryption_key) = sentc_crypto_light::user::prepare_login(user_identifier, old_password, &prep_login_out)?;

	//make done login req again to get a fresh jwt
	let url = base_url.clone() + "/api/v1/done_login_light";

	let done_login_out = non_auth_req(HttpMethod::POST, &url, auth_token, Some(auth_key)).await?;

	let keys = sentc_crypto_light::user::done_login(&master_key_encryption_key, &done_login_out)?;

	let change_pw_input = sentc_crypto_light::user::change_password(old_password, new_password, &prep_login_out, &done_login_out)?;

	let url = base_url + "/api/v1/user/update_pw";

	let res = auth_req(HttpMethod::PUT, &url, auth_token, Some(change_pw_input), &keys.jwt).await?;

	Ok(handle_general_server_response(&res)?)
}

/**
Resets the password of a device of a user.

This req can only be done with the secret token from your backend, not your frontend!
*/
pub async fn reset_password(base_url: String, auth_token: &str, user_identifier: &str, new_password: &str) -> VoidRes
{
	let url = base_url + "/api/v1/user/reset_pw_light";

	let input = sentc_crypto_light::user::register(user_identifier, new_password)?;

	let res = non_auth_req(HttpMethod::PUT, url.as_str(), auth_token, Some(input)).await?;

	Ok(handle_general_server_response(res.as_str())?)
}

pub async fn delete(base_url: String, auth_token: &str, user_identifier: &str, password: &str) -> VoidRes
{
	let prep_login_out = prepare_login_start(base_url.clone(), auth_token, user_identifier).await?;

	let (auth_key, master_key_encryption_key) = sentc_crypto_light::user::prepare_login(user_identifier, password, &prep_login_out)?;

	//make done login req again to get a fresh jwt
	let url = base_url.clone() + "/api/v1/done_login_light";

	let done_login_out = non_auth_req(HttpMethod::POST, &url, auth_token, Some(auth_key)).await?;

	let keys = sentc_crypto_light::user::done_login(&master_key_encryption_key, &done_login_out)?;

	let url = base_url + "/api/v1/user";

	let res = auth_req(HttpMethod::DELETE, &url, auth_token, None, &keys.jwt).await?;

	Ok(handle_general_server_response(&res)?)
}

/**
# Remove a device from the user group.

This can only be done when the actual device got a fresh jwt,
to make sure that no hacker can remove devices.
 */
pub async fn delete_device(base_url: String, auth_token: &str, device_identifier: &str, password: &str, device_id: &str) -> VoidRes
{
	let prep_login_out = prepare_login_start(base_url.clone(), auth_token, device_identifier).await?;

	let (auth_key, master_key_encryption_key) = sentc_crypto_light::user::prepare_login(device_identifier, password, &prep_login_out)?;

	//make done login req again to get a fresh jwt
	let url = base_url.clone() + "/api/v1/done_login_light";

	let done_login_out = non_auth_req(HttpMethod::POST, &url, auth_token, Some(auth_key)).await?;

	let keys = sentc_crypto_light::user::done_login(&master_key_encryption_key, &done_login_out)?;

	let url = base_url + "/api/v1/user/device/" + device_id;

	let res = auth_req(HttpMethod::DELETE, &url, auth_token, None, &keys.jwt).await?;

	Ok(handle_general_server_response(&res)?)
}

//__________________________________________________________________________________________________

pub async fn update(base_url: String, auth_token: &str, jwt: &str, user_identifier: String) -> VoidRes
{
	let url = base_url + "/api/v1/user";

	let input = sentc_crypto_light::user::prepare_user_identifier_update(user_identifier)?;

	let res = auth_req(HttpMethod::PUT, &url, auth_token, Some(input), jwt).await?;

	Ok(handle_general_server_response(&res)?)
}