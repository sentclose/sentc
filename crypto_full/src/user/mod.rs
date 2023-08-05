#[cfg(not(feature = "rust"))]
mod non_rust;
#[cfg(feature = "rust")]
mod rust;

use alloc::string::String;
use core::future::Future;

use sentc_crypto_utils::http::{auth_req, non_auth_req, HttpMethod};
use sentc_crypto_utils::user::UserPreVerifyLogin;
use sentc_crypto_utils::{handle_general_server_response, handle_server_response};

#[cfg(not(feature = "rust"))]
pub(crate) use self::non_rust::{
	BoolRes,
	DeviceListRes,
	InitRes,
	LoginRes,
	OtpRecoveryKeyRes,
	PreLoginRes,
	RegisterOtpRes,
	RegisterRawOtpRes,
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
	OtpRecoveryKeyRes,
	PreLoginRes,
	RegisterOtpRes,
	RegisterRawOtpRes,
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
	let pre_login = sentc_crypto_utils::full::user::login(base_url.clone(), auth_token, user_identifier, password).await?;

	match pre_login {
		sentc_crypto_utils::full::user::PreLoginOut::Direct(d) => {
			let out = verify_login(base_url, auth_token, d).await?;

			Ok(PreLoginOut::Direct(out))
		},
		sentc_crypto_utils::full::user::PreLoginOut::Otp(d) => {
			//Otp means the user enables otp, so use done_otp_login fn with the user token before verify,
			// DoneLoginServerOutput is not returned at this point

			//export the data needed for this fn

			#[cfg(not(feature = "rust"))]
			{
				let master_key: sentc_crypto_utils::keys::MasterKeyFormat = d.master_key.into();

				Ok(PreLoginOut::Otp(PrepareLoginOtpOutput {
					master_key: master_key.to_string()?,
					auth_key: d.auth_key,
				}))
			}

			#[cfg(feature = "rust")]
			{
				Ok(PreLoginOut::Otp(PrepareLoginOtpOutput {
					master_key: d.master_key,
					auth_key: d.auth_key,
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
	#[cfg(not(feature = "rust"))]
	let keys = {
		let master_key_encryption: sentc_crypto_utils::keys::MasterKeyFormat = master_key_encryption.parse()?;

		sentc_crypto_utils::full::user::mfa_login(
			base_url.clone(),
			auth_token,
			&master_key_encryption.try_into()?,
			auth_key,
			user_identifier,
			token,
			recovery,
		)
		.await?
	};

	#[cfg(feature = "rust")]
	let keys = sentc_crypto_utils::full::user::mfa_login(
		base_url.clone(),
		auth_token,
		master_key_encryption,
		auth_key,
		user_identifier,
		token,
		recovery,
	)
	.await?;

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
	Ok(sentc_crypto_utils::full::user::refresh_jwt(base_url, auth_token, jwt, refresh_token).await?)
}

pub async fn init_user(base_url: String, auth_token: &str, jwt: &str, refresh_token: String) -> InitRes
{
	Ok(sentc_crypto_utils::full::user::init_user(base_url, auth_token, jwt, refresh_token).await?)
}

pub async fn get_user_devices(base_url: String, auth_token: &str, jwt: &str, last_fetched_time: &str, last_fetched_id: &str) -> DeviceListRes
{
	Ok(sentc_crypto_utils::full::user::get_user_devices(base_url, auth_token, jwt, last_fetched_time, last_fetched_id).await?)
}

pub async fn get_fresh_jwt(
	base_url: String,
	auth_token: &str,
	user_identifier: &str,
	password: &str,
	mfa_token: Option<String>,
	mfa_recovery: Option<bool>,
) -> Res
{
	let (_, keys, _) = sentc_crypto_utils::full::user::prepare_user_fresh_jwt(
		base_url.clone(),
		auth_token,
		user_identifier,
		password,
		mfa_token,
		mfa_recovery,
	)
	.await?;

	let keys = verify_login(base_url, auth_token, keys).await?;

	Ok(keys.jwt)
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
	let (prep_login_out, keys, done_login_out) = sentc_crypto_utils::full::user::prepare_user_fresh_jwt(
		base_url.clone(),
		auth_token,
		user_identifier,
		old_password,
		mfa_token,
		mfa_recovery,
	)
	.await?;

	let keys = verify_login(base_url.clone(), auth_token, keys).await?;

	Ok(sentc_crypto_utils::full::user::done_change_password(
		base_url,
		auth_token,
		old_password,
		new_password,
		&keys.jwt,
		&prep_login_out,
		done_login_out,
	)
	.await?)
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

pub async fn delete(base_url: String, auth_token: &str, fresh_jwt: &str) -> VoidRes
{
	Ok(sentc_crypto_utils::full::user::done_delete(base_url, auth_token, fresh_jwt).await?)
}

/**
# Remove a device from the user group.

This can only be done when the actual device got a fresh jwt,
to make sure that no hacker can remove devices.
*/
pub async fn delete_device(base_url: String, auth_token: &str, fresh_jwt: &str, device_id: &str) -> VoidRes
{
	Ok(sentc_crypto_utils::full::user::done_delete_device(base_url, auth_token, fresh_jwt, device_id).await?)
}

//__________________________________________________________________________________________________

pub async fn update(base_url: String, auth_token: &str, jwt: &str, user_identifier: String) -> VoidRes
{
	Ok(sentc_crypto_utils::full::user::update(base_url, auth_token, jwt, user_identifier).await?)
}

//__________________________________________________________________________________________________
//Otp

pub async fn register_raw_otp(base_url: String, auth_token: &str, fresh_jwt: &str) -> RegisterRawOtpRes
{
	Ok(sentc_crypto_utils::full::user::register_raw_otp(base_url, auth_token, fresh_jwt).await?)
}

pub async fn register_otp(base_url: String, auth_token: &str, issuer: &str, audience: &str, fresh_jwt: &str) -> RegisterOtpRes
{
	Ok(sentc_crypto_utils::full::user::register_otp(base_url, auth_token, fresh_jwt, issuer, audience).await?)
}

pub async fn get_otp_recover_keys(base_url: String, auth_token: &str, fresh_jwt: &str) -> OtpRecoveryKeyRes
{
	Ok(sentc_crypto_utils::full::user::get_otp_recover_keys(base_url, auth_token, fresh_jwt).await?)
}

pub async fn reset_raw_otp(base_url: String, auth_token: &str, fresh_jwt: &str) -> RegisterRawOtpRes
{
	Ok(sentc_crypto_utils::full::user::reset_raw_otp(base_url, auth_token, fresh_jwt).await?)
}

pub async fn reset_otp(base_url: String, auth_token: &str, issuer: &str, audience: &str, fresh_jwt: &str) -> RegisterOtpRes
{
	Ok(sentc_crypto_utils::full::user::reset_otp(base_url, auth_token, fresh_jwt, issuer, audience).await?)
}

pub async fn disable_otp(base_url: String, auth_token: &str, fresh_jwt: &str) -> VoidRes
{
	Ok(sentc_crypto_utils::full::user::disable_otp(base_url, auth_token, fresh_jwt).await?)
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
