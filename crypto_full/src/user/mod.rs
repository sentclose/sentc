#[cfg(not(feature = "rust"))]
mod non_rust;
#[cfg(feature = "rust")]
mod rust;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::future::Future;

use sentc_crypto::SdkError;
use sentc_crypto_common::user::{DoneLoginServerOutput, DoneLoginServerReturn};
use sentc_crypto_utils::http::{auth_req, non_auth_req, HttpMethod};
use sentc_crypto_utils::user::UserPreVerifyLogin;
use sentc_crypto_utils::{handle_general_server_response, handle_server_response};

#[cfg(not(feature = "rust"))]
pub(crate) use self::non_rust::{
	BoolRes,
	DeviceListRes,
	InitRes,
	LoginRes,
	PreLoginRes,
	Res,
	SessionRes,
	UserKeyFetchRes,
	UserPublicKeyRes,
	UserVerifyKeyRes,
	VoidRes,
};
#[cfg(not(feature = "rust"))]
pub use self::non_rust::{PreLoginOut, PrepareLoginOtpOutput};
#[cfg(feature = "rust")]
pub(crate) use self::rust::{
	BoolRes,
	DeviceListRes,
	InitRes,
	LoginRes,
	PreLoginRes,
	Res,
	SessionRes,
	UserKeyFetchRes,
	UserPublicKeyRes,
	UserVerifyKeyRes,
	VoidRes,
};
#[cfg(feature = "rust")]
pub use self::rust::{PreLoginOut, PrepareLoginOtpOutput};

//Register
pub async fn check_user_identifier_available(base_url: String, auth_token: &str, user_identifier: &str) -> BoolRes
{
	let server_input = sentc_crypto::user::prepare_check_user_identifier_available(user_identifier)?;

	let url = base_url + "/api/v1/exists";

	let res = non_auth_req(HttpMethod::POST, url.as_str(), auth_token, Some(server_input)).await?;
	let out = sentc_crypto::user::done_check_user_identifier_available(res.as_str())?;

	Ok(out)
}

pub async fn register(base_url: String, auth_token: &str, user_identifier: &str, password: &str) -> Res
{
	let register_input = sentc_crypto::user::register(user_identifier, password)?;

	let url = base_url + "/api/v1/register";

	let res = non_auth_req(HttpMethod::POST, url.as_str(), auth_token, Some(register_input)).await?;

	let out = sentc_crypto::user::done_register(res.as_str())?;

	Ok(out)
}

pub async fn register_device_start(base_url: String, auth_token: &str, device_identifier: &str, password: &str) -> Res
{
	let url = base_url + "/api/v1/user/prepare_register_device";

	let input = sentc_crypto::user::prepare_register_device_start(device_identifier, password)?;

	let res = non_auth_req(HttpMethod::POST, url.as_str(), auth_token, Some(input)).await?;

	//check the server output
	sentc_crypto::user::done_register_device_start(res.as_str())?;

	Ok(res)
}

pub async fn register_device(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	server_output: &str,
	key_count: i32,
	#[cfg(not(feature = "rust"))] user_keys: &str,
	#[cfg(feature = "rust")] user_keys: &[&sentc_crypto::entities::keys::SymKeyFormatInt],
) -> SessionRes
{
	let url = base_url + "/api/v1/user/done_register_device";

	let key_session = key_count > 50;

	let (input, exported_device_public_key) = sentc_crypto::user::prepare_register_device(server_output, user_keys, key_session)?;

	let res = auth_req(HttpMethod::PUT, url.as_str(), auth_token, Some(input), jwt).await?;

	let out: sentc_crypto_common::group::GroupAcceptJoinReqServerOutput = handle_server_response(res.as_str())?;

	Ok((out.session_id, exported_device_public_key))
}

pub fn device_key_session<'a>(
	base_url: String,
	auth_token: &'a str,
	jwt: &'a str,
	session_id: &'a str,
	#[cfg(not(feature = "rust"))] user_public_key: &'a str,
	#[cfg(feature = "rust")] user_public_key: &'a sentc_crypto_common::user::UserPublicKeyData,
	#[cfg(not(feature = "rust"))] group_keys: &'a str,
	#[cfg(feature = "rust")] group_keys: &'a [&'a sentc_crypto::entities::keys::SymKeyFormatInt],
) -> impl Future<Output = VoidRes> + 'a
{
	crate::group::insert_session_keys(
		base_url,
		auth_token,
		jwt,
		"",
		crate::group::SessionKind::UserGroup,
		session_id,
		user_public_key,
		group_keys,
		None,
	)
}

//__________________________________________________________________________________________________
//Login

async fn prepare_login_start(base_url: String, auth_token: &str, user_identifier: &str) -> Res
{
	let user_id_input = sentc_crypto::user::prepare_login_start(user_identifier)?;

	let url = base_url + "/api/v1/prepare_login";

	let res = non_auth_req(HttpMethod::POST, url.as_str(), auth_token, Some(user_id_input)).await?;

	Ok(res)
}

async fn done_login_internally(
	base_url: String,
	auth_token: &str,
	user_identifier: &str,
	password: &str,
	prepare_login_res: &str,
	mfa_token: Option<String>,
	mfa_recovery: Option<bool>,
) -> Result<(UserPreVerifyLogin, DoneLoginServerOutput), SdkError>
{
	let (input, auth_key, master_key) = sentc_crypto::user::prepare_login(user_identifier, password, prepare_login_res)?;

	let url = base_url.clone() + "/api/v1/done_login";
	let server_out = non_auth_req(HttpMethod::POST, url.as_str(), auth_token, Some(input)).await?;

	match sentc_crypto::user::check_done_login(&server_out)? {
		DoneLoginServerReturn::Direct(d) => {
			let out = sentc_crypto::user::done_login(&master_key, auth_key, user_identifier.to_string(), d.clone())?;

			Ok((out, d))
		},
		DoneLoginServerReturn::Otp => {
			//if user enables mfa it must be saved in the user data, so the token is needed before doing the req
			let mfa_token = mfa_token.ok_or(SdkError::JsonToStringFailed)?;
			let mfa_recovery = mfa_recovery.ok_or(SdkError::JsonToStringFailed)?;

			//use this with the token of the auth app but without the verify

			let url = base_url.clone() +
				if mfa_recovery {
					"/api/v1/validate_recovery_otp"
				} else {
					"/api/v1/validate_mfa"
				};

			let input = sentc_crypto::user::prepare_validate_mfa(auth_key.clone(), user_identifier.to_string(), mfa_token)?;

			let res = non_auth_req(HttpMethod::POST, url.as_str(), auth_token, Some(input)).await?;

			let d: DoneLoginServerOutput = handle_server_response(&res)?;

			let out = sentc_crypto::user::done_login(&master_key, auth_key, user_identifier.to_string(), d.clone())?;

			Ok((out, d))
		},
	}
}

async fn verify_login(base_url: String, auth_token: &str, pre_verify: UserPreVerifyLogin) -> LoginRes
{
	let url = base_url + "/api/v1/verify_login";
	let server_out = non_auth_req(HttpMethod::POST, url.as_str(), auth_token, Some(pre_verify.challenge)).await?;

	let keys = sentc_crypto::user::verify_login(
		&server_out,
		pre_verify.user_id,
		pre_verify.device_id,
		pre_verify.device_keys,
	)?;

	Ok(keys)
}

pub async fn login(base_url: String, auth_token: &str, user_identifier: &str, password: &str) -> PreLoginRes
{
	let user_id_input = sentc_crypto::user::prepare_login_start(user_identifier)?;

	let url = base_url.clone() + "/api/v1/prepare_login";
	let res = non_auth_req(HttpMethod::POST, url.as_str(), auth_token, Some(user_id_input)).await?;

	let (input, auth_key, master_key_encryption_key) = sentc_crypto::user::prepare_login(user_identifier, password, res.as_str())?;

	let url = base_url.clone() + "/api/v1/done_login";
	let server_out = non_auth_req(HttpMethod::POST, url.as_str(), auth_token, Some(input)).await?;

	match sentc_crypto::user::check_done_login(&server_out)? {
		DoneLoginServerReturn::Direct(d) => {
			//direct means user has not enabled mfa, so do verify
			let verify = sentc_crypto::user::done_login(&master_key_encryption_key, auth_key, user_identifier.to_string(), d)?;

			let out = verify_login(base_url, auth_token, verify).await?;

			Ok(PreLoginOut::Direct(out))
		},
		DoneLoginServerReturn::Otp => {
			//Otp means the user enables otp, so use done_otp_login fn with the user token before verify,
			// DoneLoginServerOutput is not returned at this point

			//export the data needed for this fn

			#[cfg(not(feature = "rust"))]
			{
				let master_key: sentc_crypto_utils::keys::MasterKeyFormat = master_key_encryption_key.into();

				Ok(PreLoginOut::Otp(PrepareLoginOtpOutput {
					master_key: master_key.to_string()?,
					auth_key,
				}))
			}

			#[cfg(feature = "rust")]
			{
				Ok(PreLoginOut::Otp(PrepareLoginOtpOutput {
					master_key: master_key_encryption_key,
					auth_key,
				}))
			}
		},
	}
}

pub async fn mfa_login(
	base_url: String,
	auth_token: &str,
	#[cfg(not(feature = "rust"))] master_key_encryption: &str,
	#[cfg(feature = "rust")] master_key_encryption: &sentc_crypto::sdk_core::DeriveMasterKeyForAuth,
	auth_key: String,
	user_identifier: String,
	token: String,
	recovery: bool,
) -> LoginRes
{
	//use this with the token of the auth app

	let url = base_url.clone() +
		if recovery {
			"/api/v1/validate_recovery_otp"
		} else {
			"/api/v1/validate_mfa"
		};

	let input = sentc_crypto::user::prepare_validate_mfa(auth_key.clone(), user_identifier.clone(), token)?;

	let res = non_auth_req(HttpMethod::POST, url.as_str(), auth_token, Some(input)).await?;

	let keys = sentc_crypto::user::done_validate_mfa(master_key_encryption, auth_key, user_identifier, &res)?;

	verify_login(base_url, auth_token, keys).await
}

pub async fn fetch_user_key(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	key_id: &str,
	#[cfg(not(feature = "rust"))] private_key: &str,
	#[cfg(feature = "rust")] private_key: &sentc_crypto::entities::keys::PrivateKeyFormatInt,
) -> UserKeyFetchRes
{
	let url = base_url + "/api/v1/user/user_keys/key/" + key_id;

	let server_out = auth_req(HttpMethod::GET, url.as_str(), auth_token, None, jwt).await?;

	let keys = sentc_crypto::user::done_key_fetch(private_key, server_out.as_str())?;

	Ok(keys)
}

pub async fn refresh_jwt(base_url: String, auth_token: &str, jwt: &str, refresh_token: String) -> Res
{
	let input = sentc_crypto::user::prepare_refresh_jwt(refresh_token)?;

	let url = base_url + "/api/v1/refresh";

	let res = auth_req(HttpMethod::PUT, url.as_str(), auth_token, Some(input), jwt).await?;

	let server_output: sentc_crypto_common::user::DoneLoginLightServerOutput = handle_server_response(res.as_str())?;

	Ok(server_output.jwt)
}

pub async fn init_user(base_url: String, auth_token: &str, jwt: &str, refresh_token: String) -> InitRes
{
	let input = sentc_crypto::user::prepare_refresh_jwt(refresh_token)?;

	let url = base_url + "/api/v1/init";

	let res = auth_req(HttpMethod::POST, url.as_str(), auth_token, Some(input), jwt).await?;

	let server_output: sentc_crypto_common::user::UserInitServerOutput = handle_server_response(res.as_str())?;

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

pub async fn change_password(
	base_url: String,
	auth_token: &str,
	user_identifier: &str,
	old_password: &str,
	new_password: &str,
	mfa_token: Option<String>,
	mfa_recovery: Option<bool>,
) -> VoidRes
{
	//first make the prep login req to get the output
	let prep_login_out = prepare_login_start(base_url.clone(), auth_token, user_identifier).await?;

	let (keys, done_login_out) = done_login_internally(
		base_url.clone(),
		auth_token,
		user_identifier,
		old_password,
		&prep_login_out,
		mfa_token,
		mfa_recovery,
	)
	.await?;

	let keys = verify_login(base_url.clone(), auth_token, keys).await?;

	let change_pw_input = sentc_crypto::user::change_password(old_password, new_password, &prep_login_out, done_login_out)?;

	let url = base_url + "/api/v1/user/update_pw";

	let res = auth_req(HttpMethod::PUT, &url, auth_token, Some(change_pw_input), &keys.jwt).await?;

	Ok(handle_general_server_response(&res)?)
}

pub async fn reset_password(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	new_password: &str,
	#[cfg(not(feature = "rust"))] decrypted_private_key: &str,
	#[cfg(not(feature = "rust"))] decrypted_sign_key: &str,
	#[cfg(feature = "rust")] decrypted_private_key: &sentc_crypto::entities::keys::PrivateKeyFormatInt,
	#[cfg(feature = "rust")] decrypted_sign_key: &sentc_crypto::entities::keys::SignKeyFormatInt,
) -> VoidRes
{
	let url = base_url + "/api/v1/user/reset_pw";

	let input = sentc_crypto::user::reset_password(new_password, decrypted_private_key, decrypted_sign_key)?;

	let res = auth_req(HttpMethod::PUT, url.as_str(), auth_token, Some(input), jwt).await?;

	Ok(handle_general_server_response(&res)?)
}

//__________________________________________________________________________________________________

pub async fn delete(
	base_url: String,
	auth_token: &str,
	user_identifier: &str,
	password: &str,
	mfa_token: Option<String>,
	mfa_recovery: Option<bool>,
) -> VoidRes
{
	let prep_login_out = prepare_login_start(base_url.clone(), auth_token, user_identifier).await?;

	let (keys, _done_login_out) = done_login_internally(
		base_url.clone(),
		auth_token,
		user_identifier,
		password,
		&prep_login_out,
		mfa_token,
		mfa_recovery,
	)
	.await?;

	let keys = verify_login(base_url.clone(), auth_token, keys).await?;

	let url = base_url + "/api/v1/user";

	let res = auth_req(HttpMethod::DELETE, &url, auth_token, None, &keys.jwt).await?;

	Ok(handle_general_server_response(&res)?)
}

/**
# Remove a device from the user group.

This can only be done when the actual device got a fresh jwt,
to make sure that no hacker can remove devices.
*/
pub async fn delete_device(
	base_url: String,
	auth_token: &str,
	device_identifier: &str,
	password: &str,
	device_id: &str,
	mfa_token: Option<String>,
	mfa_recovery: Option<bool>,
) -> VoidRes
{
	let prep_login_out = prepare_login_start(base_url.clone(), auth_token, device_identifier).await?;

	let (keys, _done_login_out) = done_login_internally(
		base_url.clone(),
		auth_token,
		device_identifier,
		password,
		&prep_login_out,
		mfa_token,
		mfa_recovery,
	)
	.await?;

	let keys = verify_login(base_url.clone(), auth_token, keys).await?;

	let url = base_url + "/api/v1/user/device/" + device_id;

	let res = auth_req(HttpMethod::DELETE, url.as_str(), auth_token, None, &keys.jwt).await?;

	Ok(handle_general_server_response(&res)?)
}

//__________________________________________________________________________________________________

pub async fn update(base_url: String, auth_token: &str, jwt: &str, user_identifier: String) -> VoidRes
{
	let url = base_url + "/api/v1/user";

	let input = sentc_crypto::user::prepare_user_identifier_update(user_identifier)?;

	let res = auth_req(HttpMethod::PUT, url.as_str(), auth_token, Some(input), jwt).await?;

	Ok(handle_general_server_response(&res)?)
}

//__________________________________________________________________________________________________

pub async fn fetch_user_public_key(base_url: String, auth_token: &str, user_id: &str) -> UserPublicKeyRes
{
	let url = base_url + "/api/v1/user/" + user_id + "/public_key";

	let res = non_auth_req(HttpMethod::GET, url.as_str(), auth_token, None).await?;

	#[cfg(feature = "rust")]
	let public_data = sentc_crypto::util::public::import_public_key_from_string_into_format(res.as_str())?;

	#[cfg(not(feature = "rust"))]
	let public_data = sentc_crypto::util::public::import_public_key_from_string_into_export_string(res.as_str())?;

	Ok(public_data)
}

pub async fn fetch_user_verify_key_by_id(base_url: String, auth_token: &str, user_id: &str, verify_key_id: &str) -> UserVerifyKeyRes
{
	let url = base_url + "/api/v1/user/" + user_id + "/verify_key/" + verify_key_id;

	let res = non_auth_req(HttpMethod::GET, url.as_str(), auth_token, None).await?;

	#[cfg(feature = "rust")]
	let public_data = sentc_crypto::util::public::import_verify_key_from_string_into_format(res.as_str())?;

	#[cfg(not(feature = "rust"))]
	let (public_data, _) = sentc_crypto::util::public::import_verify_key_from_string_into_export_string(res.as_str())?;

	Ok(public_data)
}

//__________________________________________________________________________________________________

pub fn key_rotation<'a>(
	base_url: String,
	auth_token: &'a str,
	jwt: &'a str,
	#[cfg(not(feature = "rust"))] device_public_key: &'a str,
	#[cfg(feature = "rust")] device_public_key: &'a sentc_crypto::entities::keys::PublicKeyFormatInt,
	#[cfg(not(feature = "rust"))] pre_user_key: &'a str,
	#[cfg(feature = "rust")] pre_user_key: &'a sentc_crypto::entities::keys::SymKeyFormatInt,
) -> impl Future<Output = Res> + 'a
{
	crate::group::key_rotation(
		base_url,
		auth_token,
		jwt,
		"",
		device_public_key,
		pre_user_key,
		true,
		Default::default(),
		Default::default(),
		None,
	)
}

pub fn prepare_done_key_rotation<'a>(base_url: String, auth_token: &'a str, jwt: &'a str) -> impl Future<Output = crate::group::KeyRotationRes> + 'a
{
	crate::group::prepare_done_key_rotation(base_url, auth_token, jwt, "", true, None)
}

pub fn done_key_rotation<'a>(
	base_url: String,
	auth_token: &'a str,
	jwt: &'a str,
	#[cfg(not(feature = "rust"))] server_output: &'a str,
	#[cfg(feature = "rust")] server_output: sentc_crypto_common::group::KeyRotationInput,
	#[cfg(not(feature = "rust"))] pre_user_key: &'a str,
	#[cfg(feature = "rust")] pre_user_key: &'a sentc_crypto::entities::keys::SymKeyFormatInt,
	#[cfg(not(feature = "rust"))] device_public_key: &'a str,
	#[cfg(feature = "rust")] device_public_key: &'a sentc_crypto::entities::keys::PublicKeyFormatInt,
	#[cfg(not(feature = "rust"))] device_private_key: &'a str,
	#[cfg(feature = "rust")] device_private_key: &'a sentc_crypto::entities::keys::PrivateKeyFormatInt,
) -> impl Future<Output = VoidRes> + 'a
{
	crate::group::done_key_rotation(
		base_url,
		auth_token,
		jwt,
		"",
		server_output,
		pre_user_key,
		device_public_key,
		device_private_key,
		true,
		Default::default(),
		None,
	)
}
