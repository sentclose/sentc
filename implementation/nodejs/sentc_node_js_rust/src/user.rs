use napi::bindgen_prelude::*;
use sentc_crypto::util_req_full;

use crate::group::{GroupInviteReqList, GroupOutDataHmacKeys, KeyRotationInput};
//Jwt

#[napi(object)]
pub struct Claims
{
	pub aud: String,
	pub sub: String, //the app id
	pub exp: i64,
	pub iat: i64,
	pub fresh: bool, //define if this token was from refresh jwt or from login
}

impl From<sentc_crypto_common::user::Claims> for Claims
{
	fn from(claims: sentc_crypto_common::user::Claims) -> Self
	{
		Self {
			aud: claims.aud,
			sub: claims.sub,
			exp: claims.exp as i64,
			iat: claims.iat as i64,
			fresh: claims.fresh,
		}
	}
}

#[napi]
pub fn decode_jwt(jwt: String) -> Result<Claims>
{
	let claims = util_req_full::decode_jwt(&jwt).map_err(Error::from_reason)?;

	Ok(claims.into())
}

//==================================================================================================
//User

#[napi(object)]
pub struct GeneratedRegisterData
{
	pub identifier: String,
	pub password: String,
}

#[napi(object)]
pub struct DeviceKeyData
{
	pub private_key: String, //Base64 exported keys
	pub public_key: String,
	pub sign_key: String,
	pub verify_key: String,
	pub exported_public_key: String,
	pub exported_verify_key: String,
}

impl From<sentc_crypto::entities::user::DeviceKeyDataExport> for DeviceKeyData
{
	fn from(keys: sentc_crypto::entities::user::DeviceKeyDataExport) -> Self
	{
		Self {
			private_key: keys.private_key,
			public_key: keys.public_key,
			sign_key: keys.sign_key,
			verify_key: keys.verify_key,
			exported_public_key: keys.exported_public_key,
			exported_verify_key: keys.exported_verify_key,
		}
	}
}

#[napi(object)]
pub struct UserKeyData
{
	pub private_key: String,
	pub public_key: String,
	pub group_key: String,
	pub time: String,
	pub group_key_id: String,
	pub sign_key: String,
	pub verify_key: String,
	pub exported_public_key: String,
	pub exported_public_key_sig_key_id: Option<String>,
	pub exported_verify_key: String,
}

impl From<sentc_crypto::entities::user::UserKeyDataExport> for UserKeyData
{
	fn from(data: sentc_crypto::entities::user::UserKeyDataExport) -> Self
	{
		Self {
			private_key: data.private_key,
			public_key: data.public_key,
			group_key: data.group_key,
			time: data.time.to_string(),
			group_key_id: data.group_key_id,
			sign_key: data.sign_key,
			verify_key: data.verify_key,
			exported_public_key: data.exported_public_key,
			exported_public_key_sig_key_id: data.exported_public_key_sig_key_id,
			exported_verify_key: data.exported_verify_key,
		}
	}
}

#[napi(object)]
pub struct PrepareLoginOtpOutput
{
	pub master_key: String,
	pub auth_key: String,
}

impl From<util_req_full::user::PrepareLoginOtpOutput> for PrepareLoginOtpOutput
{
	fn from(value: util_req_full::user::PrepareLoginOtpOutput) -> Self
	{
		Self {
			master_key: value.master_key,
			auth_key: value.auth_key,
		}
	}
}

#[napi(object)]
pub struct UserLoginOut
{
	pub user_data: Option<UserData>,
	pub mfa: Option<PrepareLoginOtpOutput>,
}

impl From<util_req_full::user::PreLoginOutExport> for UserLoginOut
{
	fn from(value: util_req_full::user::PreLoginOutExport) -> Self
	{
		match value {
			util_req_full::user::PreLoginOutExport::Direct(d) => {
				Self {
					mfa: None,
					user_data: Some(d.into()),
				}
			},
			util_req_full::user::PreLoginOutExport::Otp(d) => {
				Self {
					user_data: None,
					mfa: Some(d.into()),
				}
			},
		}
	}
}

#[napi(object)]
pub struct UserData
{
	pub jwt: String,
	pub user_id: String,
	pub device_id: String,
	pub refresh_token: String,
	pub keys: DeviceKeyData,
	pub user_keys: Vec<UserKeyData>,
	pub hmac_keys: Vec<GroupOutDataHmacKeys>,
}

impl From<sentc_crypto::entities::user::UserDataExport> for UserData
{
	fn from(data: sentc_crypto::entities::user::UserDataExport) -> Self
	{
		Self {
			jwt: data.jwt,
			user_id: data.user_id,
			device_id: data.device_id,
			refresh_token: data.refresh_token,
			keys: data.device_keys.into(),
			user_keys: data
				.user_keys
				.into_iter()
				.map(|user_key| user_key.into())
				.collect(),
			hmac_keys: data
				.hmac_keys
				.into_iter()
				.map(|hmac_key| hmac_key.into())
				.collect(),
		}
	}
}

//__________________________________________________________________________________________________

/**
# Check if the identifier is available for this app
 */
#[napi]
pub async fn check_user_identifier_available(base_url: String, auth_token: String, user_identifier: String) -> Result<bool>
{
	util_req_full::user::check_user_identifier_available(base_url, &auth_token, &user_identifier)
		.await
		.map_err(Error::from_reason)
}

/**
# Check if the identifier is available

but without making a request
 */
#[napi]
pub fn prepare_check_user_identifier_available(user_identifier: String) -> Result<String>
{
	sentc_crypto::user::prepare_check_user_identifier_available(&user_identifier).map_err(Error::from_reason)
}

/**
# Validates the response if the identifier is available

but without making a request
 */
#[napi]
pub fn done_check_user_identifier_available(server_output: String) -> Result<bool>
{
	sentc_crypto::user::done_check_user_identifier_available(&server_output).map_err(Error::from_reason)
}

/**
Generates identifier and password for a user or device
*/
#[napi]
pub fn generate_user_register_data() -> Result<GeneratedRegisterData>
{
	let (identifier, password) = sentc_crypto::user::generate_user_register_data().map_err(Error::from_reason)?;

	Ok(GeneratedRegisterData {
		identifier,
		password,
	})
}

/**
# Get the user input from the user client

This is used when the register endpoint should only be called from the backend and not the clients.

For full-register see register()
 */
#[napi]
pub fn prepare_register(user_identifier: String, password: String) -> Result<String>
{
	sentc_crypto::user::register(&user_identifier, &password).map_err(Error::from_reason)
}

/**
# Validates the response of register

Returns the new user id
 */
#[napi]
pub fn done_register(server_output: String) -> Result<String>
{
	sentc_crypto::user::done_register(&server_output).map_err(Error::from_reason)
}

/**
# Register a new user for the app

Do the full req incl. req.
No checking about spamming and just return the user id.
 */
#[napi]
pub async fn register(base_url: String, auth_token: String, user_identifier: String, password: String) -> Result<String>
{
	util_req_full::user::register(base_url, &auth_token, &user_identifier, &password)
		.await
		.map_err(Error::from_reason)
}

#[napi]
pub fn prepare_register_device_start(device_identifier: String, password: String) -> Result<String>
{
	sentc_crypto::user::prepare_register_device_start(&device_identifier, &password).map_err(Error::from_reason)
}

#[napi]
pub fn done_register_device_start(server_output: String) -> Result<()>
{
	sentc_crypto::user::done_register_device_start(&server_output).map_err(Error::from_reason)
}

#[napi]
pub async fn register_device_start(base_url: String, auth_token: String, device_identifier: String, password: String) -> Result<String>
{
	util_req_full::user::register_device_start(base_url, &auth_token, &device_identifier, &password)
		.await
		.map_err(Error::from_reason)
}

#[napi(object)]
pub struct PreRegisterDeviceData
{
	pub input: String,
	pub exported_public_key: String,
}

#[napi(object)]
pub struct RegisterDeviceData
{
	pub session_id: String,
	pub exported_public_key: String,
}

#[napi]
pub fn prepare_register_device(server_output: String, user_keys: String, key_count: i32) -> Result<PreRegisterDeviceData>
{
	let key_session = key_count > 50;

	let (input, exported_public_key) =
		sentc_crypto::user::prepare_register_device(&server_output, &user_keys, key_session).map_err(Error::from_reason)?;

	Ok(PreRegisterDeviceData {
		input,
		exported_public_key,
	})
}

#[napi]
pub async fn register_device(
	base_url: String,
	auth_token: String,
	jwt: String,
	server_output: String,
	key_count: i32,
	user_keys: String,
) -> Result<RegisterDeviceData>
{
	let (out, exported_public_key) = util_req_full::user::register_device(base_url, &auth_token, &jwt, &server_output, key_count, &user_keys)
		.await
		.map_err(Error::from_reason)?;

	let session_id = out.unwrap_or_else(|| String::from(""));

	Ok(RegisterDeviceData {
		session_id,
		exported_public_key,
	})
}

#[napi]
pub async fn user_device_key_session_upload(
	base_url: String,
	auth_token: String,
	jwt: String,
	session_id: String,
	user_public_key: String,
	group_keys: String,
) -> Result<()>
{
	util_req_full::user::device_key_session(
		base_url,
		&auth_token,
		&jwt,
		&session_id,
		&user_public_key,
		&group_keys,
	)
	.await
	.map_err(Error::from_reason)
}

//__________________________________________________________________________________________________

/**
# Log in the user to this app

Does the login requests. 1. for auth, 2nd to get the keys.

If there is more data in the backend, then it is possible to call it via the jwt what is returned by the done login request.

The other backend can validate the jwt
 */
#[napi]
pub async fn login(base_url: String, auth_token: String, user_identifier: String, password: String) -> Result<UserLoginOut>
{
	let data = util_req_full::user::login(base_url, &auth_token, &user_identifier, &password)
		.await
		.map_err(Error::from_reason)?;

	Ok(data.into())
}

#[napi]
pub async fn mfa_login(
	base_url: String,
	auth_token: String,
	master_key_encryption: String,
	auth_key: String,
	user_identifier: String,
	token: String,
	recovery: bool,
) -> Result<UserData>
{
	let data = util_req_full::user::mfa_login(
		base_url,
		&auth_token,
		&master_key_encryption,
		auth_key,
		user_identifier,
		token,
		recovery,
	)
	.await
	.map_err(Error::from_reason)?;

	Ok(data.into())
}

#[napi]
pub fn done_fetch_user_key(private_key: String, server_output: String) -> Result<UserKeyData>
{
	let data = sentc_crypto::user::done_key_fetch(&private_key, &server_output).map_err(Error::from_reason)?;

	Ok(data.into())
}

#[napi]
pub async fn fetch_user_key(base_url: String, auth_token: String, jwt: String, key_id: String, private_key: String) -> Result<UserKeyData>
{
	let data = util_req_full::user::fetch_user_key(base_url, &auth_token, &jwt, &key_id, &private_key)
		.await
		.map_err(Error::from_reason)?;

	Ok(data.into())
}

#[napi]
pub async fn get_fresh_jwt(
	base_url: String,
	auth_token: String,
	user_identifier: String,
	password: String,
	mfa_token: Option<String>,
	mfa_recovery: Option<bool>,
) -> Result<String>
{
	util_req_full::user::get_fresh_jwt(
		base_url,
		&auth_token,
		&user_identifier,
		&password,
		mfa_token,
		mfa_recovery,
	)
	.await
	.map_err(Error::from_reason)
}

//__________________________________________________________________________________________________

#[napi(object)]
pub struct UserInitServerOutput
{
	pub jwt: String,
	pub invites: Vec<GroupInviteReqList>,
}

#[napi]
pub async fn refresh_jwt(base_url: String, auth_token: String, jwt: String, refresh_token: String) -> Result<String>
{
	util_req_full::user::refresh_jwt(base_url, &auth_token, &jwt, refresh_token)
		.await
		.map_err(Error::from_reason)
}

#[napi]
pub async fn init_user(base_url: String, auth_token: String, jwt: String, refresh_token: String) -> Result<UserInitServerOutput>
{
	let out = util_req_full::user::init_user(base_url, &auth_token, &jwt, refresh_token)
		.await
		.map_err(Error::from_reason)?;

	Ok(UserInitServerOutput {
		jwt: out.jwt,
		invites: out
			.invites
			.into_iter()
			.map(|invite| invite.into())
			.collect(),
	})
}

#[napi]
pub fn user_create_safety_number(verify_key_1: String, user_id_1: String, verify_key_2: Option<String>, user_id_2: Option<String>) -> Result<String>
{
	sentc_crypto::user::create_safety_number(
		&verify_key_1,
		&user_id_1,
		verify_key_2.as_deref(),
		user_id_2.as_deref(),
	)
	.map_err(Error::from_reason)
}

#[napi]
pub fn user_verify_user_public_key(verify_key: String, public_key: String) -> Result<bool>
{
	sentc_crypto::user::verify_user_public_key(&verify_key, &public_key).map_err(Error::from_reason)
}

//__________________________________________________________________________________________________

#[napi(object)]
pub struct UserDeviceList
{
	pub device_id: String,
	pub time: String,
	pub device_identifier: String,
}

impl From<sentc_crypto_common::user::UserDeviceList> for UserDeviceList
{
	fn from(list: sentc_crypto_common::user::UserDeviceList) -> Self
	{
		Self {
			device_id: list.device_id,
			time: list.time.to_string(),
			device_identifier: list.device_identifier,
		}
	}
}

#[napi]
pub async fn get_user_devices(
	base_url: String,
	auth_token: String,
	jwt: String,
	last_fetched_time: String,
	last_fetched_id: String,
) -> Result<Vec<UserDeviceList>>
{
	let out = util_req_full::user::get_user_devices(base_url, &auth_token, &jwt, &last_fetched_time, &last_fetched_id)
		.await
		.map_err(Error::from_reason)?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

#[napi]
pub async fn reset_password(
	base_url: String,
	auth_token: String,
	jwt: String,
	new_password: String,
	decrypted_private_key: String,
	decrypted_sign_key: String,
) -> Result<()>
{
	util_req_full::user::reset_password(
		base_url,
		&auth_token,
		&jwt,
		&new_password,
		&decrypted_private_key,
		&decrypted_sign_key,
	)
	.await
	.map_err(Error::from_reason)
}

#[napi]
pub async fn change_password(
	base_url: String,
	auth_token: String,
	user_identifier: String,
	old_password: String,
	new_password: String,
	mfa_token: Option<String>,
	mfa_recovery: Option<bool>,
) -> Result<()>
{
	util_req_full::user::change_password(
		base_url,
		&auth_token,
		&user_identifier,
		&old_password,
		&new_password,
		mfa_token,
		mfa_recovery,
	)
	.await
	.map_err(Error::from_reason)
}

#[napi]
pub async fn delete_user(base_url: String, auth_token: String, fresh_jwt: String) -> Result<()>
{
	util_req_full::user::delete(base_url, &auth_token, &fresh_jwt)
		.await
		.map_err(Error::from_reason)
}

#[napi]
pub async fn delete_device(base_url: String, auth_token: String, fresh_jwt: String, device_id: String) -> Result<()>
{
	util_req_full::user::delete_device(base_url, &auth_token, &fresh_jwt, &device_id)
		.await
		.map_err(Error::from_reason)
}

#[napi]
pub async fn update_user(base_url: String, auth_token: String, jwt: String, user_identifier: String) -> Result<()>
{
	util_req_full::user::update(base_url, &auth_token, &jwt, user_identifier)
		.await
		.map_err(Error::from_reason)
}

//__________________________________________________________________________________________________

#[napi(object)]
pub struct UserPublicKeyData
{
	pub public_key: String,
	pub public_key_id: String,
	pub public_key_sig_key_id: Option<String>,
}

#[napi]
pub async fn user_fetch_public_key(base_url: String, auth_token: String, user_id: String) -> Result<UserPublicKeyData>
{
	let (public_key, public_key_id, public_key_sig_key_id) = util_req_full::user::fetch_user_public_key(base_url, &auth_token, &user_id)
		.await
		.map_err(Error::from_reason)?;

	Ok(UserPublicKeyData {
		public_key,
		public_key_id,
		public_key_sig_key_id,
	})
}

#[napi]
pub async fn user_fetch_verify_key(base_url: String, auth_token: String, user_id: String, verify_key_id: String) -> Result<String>
{
	let key = util_req_full::user::fetch_user_verify_key_by_id(base_url, &auth_token, &user_id, &verify_key_id)
		.await
		.map_err(Error::from_reason)?;

	Ok(key)
}

//__________________________________________________________________________________________________

#[napi(object)]
pub struct KeyRotationGetOut
{
	pub pre_group_key_id: String,
	pub new_group_key_id: String,
	pub encrypted_eph_key_key_id: String,
	pub server_output: String,
}

impl From<util_req_full::group::KeyRotationGetOut> for KeyRotationGetOut
{
	fn from(item: util_req_full::group::KeyRotationGetOut) -> Self
	{
		Self {
			pre_group_key_id: item.pre_group_key_id,
			new_group_key_id: item.new_group_key_id,
			encrypted_eph_key_key_id: item.encrypted_eph_key_key_id,
			server_output: item.server_output,
		}
	}
}

#[napi]
pub async fn user_key_rotation(base_url: String, auth_token: String, jwt: String, public_device_key: String, pre_user_key: String) -> Result<String>
{
	util_req_full::user::key_rotation(base_url, &auth_token, &jwt, &public_device_key, &pre_user_key)
		.await
		.map_err(Error::from_reason)
}

#[napi]
pub async fn user_pre_done_key_rotation(base_url: String, auth_token: String, jwt: String) -> Result<Vec<KeyRotationGetOut>>
{
	let out = util_req_full::user::prepare_done_key_rotation(base_url, &auth_token, &jwt)
		.await
		.map_err(Error::from_reason)?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

#[napi]
pub fn user_get_done_key_rotation_server_input(server_output: String) -> Result<KeyRotationInput>
{
	let out = sentc_crypto::group::get_done_key_rotation_server_input(&server_output).map_err(Error::from_reason)?;

	Ok(out.into())
}

#[napi]
pub async fn user_finish_key_rotation(
	base_url: String,
	auth_token: String,
	jwt: String,
	server_output: String,
	pre_group_key: String,
	public_key: String,
	private_key: String,
) -> Result<()>
{
	util_req_full::user::done_key_rotation(
		base_url,
		&auth_token,
		&jwt,
		&server_output,
		&pre_group_key,
		&public_key,
		&private_key,
	)
	.await
	.map_err(Error::from_reason)
}

//__________________________________________________________________________________________________
//Otp

#[napi(object)]
pub struct OtpRegister
{
	pub secret: String, //base32 endowed secret
	pub alg: String,
	pub recover: Vec<String>,
}

impl From<sentc_crypto_common::user::OtpRegister> for OtpRegister
{
	fn from(value: sentc_crypto_common::user::OtpRegister) -> Self
	{
		Self {
			secret: value.secret,
			alg: value.alg,
			recover: value.recover,
		}
	}
}

#[napi(object)]
pub struct OtpRegisterUrl
{
	pub url: String,
	pub recover: Vec<String>,
}

#[napi(object)]
pub struct OtpRecoveryKeysOutput
{
	pub keys: Vec<String>,
}

impl From<sentc_crypto_common::user::OtpRecoveryKeysOutput> for OtpRecoveryKeysOutput
{
	fn from(value: sentc_crypto_common::user::OtpRecoveryKeysOutput) -> Self
	{
		Self {
			keys: value.keys,
		}
	}
}

#[napi]
pub async fn register_raw_otp(base_url: String, auth_token: String, jwt: String) -> Result<OtpRegister>
{
	let out = util_req_full::user::register_raw_otp(base_url, &auth_token, &jwt)
		.await
		.map_err(Error::from_reason)?;

	Ok(out.into())
}

#[napi]
pub async fn register_otp(base_url: String, auth_token: String, jwt: String, issuer: String, audience: String) -> Result<OtpRegisterUrl>
{
	let (url, recover) = util_req_full::user::register_otp(base_url, &auth_token, &issuer, &audience, &jwt)
		.await
		.map_err(Error::from_reason)?;

	Ok(OtpRegisterUrl {
		url,
		recover,
	})
}

#[napi]
pub async fn get_otp_recover_keys(base_url: String, auth_token: String, jwt: String) -> Result<OtpRecoveryKeysOutput>
{
	let out = util_req_full::user::get_otp_recover_keys(base_url, &auth_token, &jwt)
		.await
		.map_err(Error::from_reason)?;

	Ok(out.into())
}

#[napi]
pub async fn reset_raw_otp(base_url: String, auth_token: String, jwt: String) -> Result<OtpRegister>
{
	let out = util_req_full::user::reset_raw_otp(base_url, &auth_token, &jwt)
		.await
		.map_err(Error::from_reason)?;

	Ok(out.into())
}

#[napi]
pub async fn reset_otp(base_url: String, auth_token: String, jwt: String, issuer: String, audience: String) -> Result<OtpRegisterUrl>
{
	let (url, recover) = util_req_full::user::reset_otp(base_url, &auth_token, &jwt, &issuer, &audience)
		.await
		.map_err(Error::from_reason)?;

	Ok(OtpRegisterUrl {
		url,
		recover,
	})
}

#[napi]
pub async fn disable_otp(base_url: String, auth_token: String, jwt: String) -> Result<()>
{
	util_req_full::user::disable_otp(base_url, &auth_token, &jwt)
		.await
		.map_err(Error::from_reason)
}
