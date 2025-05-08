use sentc_crypto::util_req_full;

use crate::api::group::{GroupInviteReqList, GroupOutDataHmacKeys, KeyRotationInput};

//Jwt

pub struct Claims
{
	pub aud: String,
	pub sub: String, //the app id
	pub exp: usize,
	pub iat: usize,
	pub fresh: bool, //define if this token was from refresh jwt or from login
}

impl From<sentc_crypto_common::user::Claims> for Claims
{
	fn from(claims: sentc_crypto_common::user::Claims) -> Self
	{
		Self {
			aud: claims.aud,
			sub: claims.sub,
			exp: claims.exp,
			iat: claims.iat,
			fresh: claims.fresh,
		}
	}
}

#[flutter_rust_bridge::frb(sync)]
pub fn decode_jwt(jwt: String) -> Result<Claims, String>
{
	let claims = util_req_full::decode_jwt(&jwt)?;

	Ok(claims.into())
}

//==================================================================================================
//User

pub struct GeneratedRegisterData
{
	pub identifier: String,
	pub password: String,
}

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

pub struct UserLoginOut
{
	pub direct: Option<String>,
	pub master_key: Option<String>,
	pub auth_key: Option<String>,
}

impl From<util_req_full::user::PreLoginOutExport> for UserLoginOut
{
	fn from(value: util_req_full::user::PreLoginOutExport) -> Self
	{
		match value {
			util_req_full::user::PreLoginOutExport::Direct(d) => {
				Self {
					direct: Some(serde_json::to_string(&d).unwrap()),
					master_key: None,
					auth_key: None,
				}
			},
			util_req_full::user::PreLoginOutExport::Otp(d) => {
				Self {
					direct: None,
					master_key: Some(d.master_key),
					auth_key: Some(d.auth_key),
				}
			},
		}
	}
}

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
pub async fn check_user_identifier_available(base_url: String, auth_token: &str, user_identifier: &str) -> Result<bool, String>
{
	util_req_full::user::check_user_identifier_available(base_url, auth_token, user_identifier).await
}

/**
# Check if the identifier is available

but without making a request
 */
#[flutter_rust_bridge::frb(sync)]
pub fn prepare_check_user_identifier_available(user_identifier: &str) -> Result<String, String>
{
	sentc_crypto::user::prepare_check_user_identifier_available(user_identifier)
}

/**
# Validates the response if the identifier is available

but without making a request
 */
#[flutter_rust_bridge::frb(sync)]
pub fn done_check_user_identifier_available(server_output: &str) -> Result<bool, String>
{
	sentc_crypto::user::done_check_user_identifier_available(server_output)
}

/**
Generates identifier and password for a user or device
*/
pub fn generate_user_register_data() -> Result<GeneratedRegisterData, String>
{
	let (identifier, password) = sentc_crypto::user::generate_user_register_data()?;

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
pub fn prepare_register(user_identifier: &str, password: &str) -> Result<String, String>
{
	sentc_crypto::user::register(user_identifier, password)
}

/**
# Validates the response of register

Returns the new user id
 */
#[flutter_rust_bridge::frb(sync)]
pub fn done_register(server_output: &str) -> Result<String, String>
{
	sentc_crypto::user::done_register(server_output)
}

/**
# Register a new user for the app

Do the full req incl. req.
No checking about spamming and just return the user id.
 */
pub async fn register(base_url: String, auth_token: &str, user_identifier: &str, password: &str) -> Result<String, String>
{
	util_req_full::user::register(base_url, auth_token, user_identifier, password).await
}

pub fn prepare_register_device_start(device_identifier: &str, password: &str) -> Result<String, String>
{
	sentc_crypto::user::prepare_register_device_start(device_identifier, password)
}

#[flutter_rust_bridge::frb(sync)]
pub fn done_register_device_start(server_output: &str) -> Result<(), String>
{
	sentc_crypto::user::done_register_device_start(server_output)
}

pub async fn register_device_start(base_url: String, auth_token: &str, device_identifier: &str, password: &str) -> Result<String, String>
{
	util_req_full::user::register_device_start(base_url, auth_token, device_identifier, password).await
}

pub struct PreRegisterDeviceData
{
	pub input: String,
	pub exported_public_key: String,
}

pub struct RegisterDeviceData
{
	pub session_id: String,
	pub exported_public_key: String,
}

pub fn prepare_register_device(server_output: &str, user_keys: &str, key_count: i32) -> Result<PreRegisterDeviceData, String>
{
	let key_session = key_count > 50;

	let (input, exported_public_key) = sentc_crypto::user::prepare_register_device(server_output, user_keys, key_session)?;

	Ok(PreRegisterDeviceData {
		input,
		exported_public_key,
	})
}

pub async fn register_device(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	server_output: &str,
	key_count: i32,
	user_keys: &str,
) -> Result<RegisterDeviceData, String>
{
	let (out, exported_public_key) = util_req_full::user::register_device(base_url, auth_token, jwt, server_output, key_count, user_keys).await?;

	let session_id = out.unwrap_or_else(|| String::from(""));

	Ok(RegisterDeviceData {
		session_id,
		exported_public_key,
	})
}

pub async fn user_device_key_session_upload(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	session_id: &str,
	user_public_key: &str,
	group_keys: &str,
) -> Result<(), String>
{
	util_req_full::user::device_key_session(base_url, auth_token, jwt, session_id, user_public_key, group_keys).await
}

//__________________________________________________________________________________________________

/**
# Log in the user to this app

Does the login requests. 1. for auth, 2nd to get the keys.

If there is more data in the backend, then it is possible to call it via the jwt what is returned by the done login request.

The other backend can validate the jwt
 */
pub async fn login(base_url: String, auth_token: &str, user_identifier: &str, password: &str) -> Result<UserLoginOut, String>
{
	let data = util_req_full::user::login(base_url, auth_token, user_identifier, password).await?;

	Ok(data.into())
}

pub fn extract_user_data(data: &str) -> Result<UserData, String>
{
	let out: sentc_crypto::entities::user::UserDataExport = serde_json::from_str(data).map_err(|err| err.to_string())?;

	Ok(out.into())
}

pub async fn mfa_login(
	base_url: String,
	auth_token: &str,
	master_key_encryption: &str,
	auth_key: String,
	user_identifier: String,
	token: String,
	recovery: bool,
) -> Result<UserData, String>
{
	let data = util_req_full::user::mfa_login(
		base_url,
		auth_token,
		master_key_encryption,
		auth_key,
		user_identifier,
		token,
		recovery,
	)
	.await?;

	Ok(data.into())
}

pub fn done_fetch_user_key(private_key: &str, server_output: &str) -> Result<UserKeyData, String>
{
	let data = sentc_crypto::user::done_key_fetch(private_key, server_output)?;

	Ok(data.into())
}

pub async fn fetch_user_key(base_url: String, auth_token: &str, jwt: &str, key_id: &str, private_key: &str) -> Result<UserKeyData, String>
{
	let data = util_req_full::user::fetch_user_key(base_url, auth_token, jwt, key_id, private_key).await?;

	Ok(data.into())
}

pub async fn get_fresh_jwt(
	base_url: String,
	auth_token: &str,
	user_identifier: &str,
	password: &str,
	mfa_token: Option<String>,
	mfa_recovery: Option<bool>,
) -> Result<String, String>
{
	util_req_full::user::get_fresh_jwt(
		base_url,
		auth_token,
		user_identifier,
		password,
		mfa_token,
		mfa_recovery,
	)
	.await
}

//__________________________________________________________________________________________________

pub struct UserInitServerOutput
{
	pub jwt: String,
	pub invites: Vec<GroupInviteReqList>,
}

pub async fn refresh_jwt(base_url: String, auth_token: String, jwt: &str, refresh_token: String) -> Result<String, String>
{
	util_req_full::user::refresh_jwt(base_url, auth_token.as_str(), jwt, refresh_token).await
}

pub async fn init_user(base_url: String, auth_token: &str, jwt: &str, refresh_token: String) -> Result<UserInitServerOutput, String>
{
	let out = util_req_full::user::init_user(base_url, auth_token, jwt, refresh_token).await?;

	Ok(UserInitServerOutput {
		jwt: out.jwt,
		invites: out
			.invites
			.into_iter()
			.map(|invite| invite.into())
			.collect(),
	})
}

pub fn user_create_safety_number(
	verify_key_1: &str,
	user_id_1: &str,
	verify_key_2: Option<String>,
	user_id_2: Option<String>,
) -> Result<String, String>
{
	sentc_crypto::user::create_safety_number(verify_key_1, user_id_1, verify_key_2.as_deref(), user_id_2.as_deref())
}

pub fn user_verify_user_public_key(verify_key: &str, public_key: &str) -> Result<bool, String>
{
	sentc_crypto::user::verify_user_public_key(verify_key, public_key)
}

//__________________________________________________________________________________________________

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

pub async fn get_user_devices(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	last_fetched_time: &str,
	last_fetched_id: &str,
) -> Result<Vec<UserDeviceList>, String>
{
	let out = util_req_full::user::get_user_devices(base_url, auth_token, jwt, last_fetched_time, last_fetched_id).await?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

pub async fn reset_password(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	new_password: &str,
	decrypted_private_key: &str,
	decrypted_sign_key: &str,
) -> Result<(), String>
{
	util_req_full::user::reset_password(
		base_url,
		auth_token,
		jwt,
		new_password,
		decrypted_private_key,
		decrypted_sign_key,
	)
	.await
}

pub async fn change_password(
	base_url: String,
	auth_token: &str,
	user_identifier: &str,
	old_password: &str,
	new_password: &str,
	mfa_token: Option<String>,
	mfa_recovery: Option<bool>,
) -> Result<(), String>
{
	util_req_full::user::change_password(
		base_url,
		auth_token,
		user_identifier,
		old_password,
		new_password,
		mfa_token,
		mfa_recovery,
	)
	.await
}

pub async fn delete_user(base_url: String, auth_token: &str, fresh_jwt: &str) -> Result<(), String>
{
	util_req_full::user::delete(base_url, auth_token, fresh_jwt).await
}

pub async fn delete_device(base_url: String, auth_token: &str, fresh_jwt: &str, device_id: &str) -> Result<(), String>
{
	util_req_full::user::delete_device(base_url, auth_token, fresh_jwt, device_id).await
}

pub async fn update_user(base_url: String, auth_token: &str, jwt: &str, user_identifier: String) -> Result<(), String>
{
	util_req_full::user::update(base_url, auth_token, jwt, user_identifier).await
}

//__________________________________________________________________________________________________

pub struct UserPublicKeyData
{
	pub public_key: String,
	pub public_key_id: String,
	pub public_key_sig_key_id: Option<String>,
}

pub async fn user_fetch_public_key(base_url: String, auth_token: &str, user_id: &str) -> Result<UserPublicKeyData, String>
{
	let (public_key, public_key_id, public_key_sig_key_id) = util_req_full::user::fetch_user_public_key(base_url, auth_token, user_id).await?;

	Ok(UserPublicKeyData {
		public_key,
		public_key_id,
		public_key_sig_key_id,
	})
}

pub async fn user_fetch_verify_key(base_url: String, auth_token: &str, user_id: &str, verify_key_id: &str) -> Result<String, String>
{
	let key = util_req_full::user::fetch_user_verify_key_by_id(base_url, auth_token, user_id, verify_key_id).await?;

	Ok(key)
}

//__________________________________________________________________________________________________

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

pub async fn user_key_rotation(base_url: String, auth_token: &str, jwt: &str, public_device_key: &str, pre_user_key: &str) -> Result<String, String>
{
	util_req_full::user::key_rotation(base_url, auth_token, jwt, public_device_key, pre_user_key).await
}

pub async fn user_pre_done_key_rotation(base_url: String, auth_token: &str, jwt: &str) -> Result<Vec<KeyRotationGetOut>, String>
{
	let out = util_req_full::user::prepare_done_key_rotation(base_url, auth_token, jwt).await?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

pub fn user_get_done_key_rotation_server_input(server_output: &str) -> Result<KeyRotationInput, String>
{
	let out = sentc_crypto::group::get_done_key_rotation_server_input(server_output)?;

	Ok(out.into())
}

pub async fn user_finish_key_rotation(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	server_output: &str,
	pre_group_key: &str,
	public_key: &str,
	private_key: &str,
) -> Result<(), String>
{
	util_req_full::user::done_key_rotation(
		base_url,
		auth_token,
		jwt,
		server_output,
		pre_group_key,
		public_key,
		private_key,
	)
	.await
}

//__________________________________________________________________________________________________
//Otp

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

pub struct OtpRegisterUrl
{
	pub url: String,
	pub recover: Vec<String>,
}

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

pub async fn register_raw_otp(base_url: String, auth_token: &str, jwt: &str) -> Result<OtpRegister, String>
{
	let out = util_req_full::user::register_raw_otp(base_url, auth_token, jwt).await?;

	Ok(out.into())
}

pub async fn register_otp(base_url: String, auth_token: &str, jwt: &str, issuer: &str, audience: &str) -> Result<OtpRegisterUrl, String>
{
	let (url, recover) = util_req_full::user::register_otp(base_url, auth_token, issuer, audience, jwt).await?;

	Ok(OtpRegisterUrl {
		url,
		recover,
	})
}

pub async fn get_otp_recover_keys(base_url: String, auth_token: &str, jwt: &str) -> Result<OtpRecoveryKeysOutput, String>
{
	let out = util_req_full::user::get_otp_recover_keys(base_url, auth_token, jwt).await?;

	Ok(out.into())
}

pub async fn reset_raw_otp(base_url: String, auth_token: &str, jwt: &str) -> Result<OtpRegister, String>
{
	let out = util_req_full::user::reset_raw_otp(base_url, auth_token, jwt).await?;

	Ok(out.into())
}

pub async fn reset_otp(base_url: String, auth_token: &str, jwt: &str, issuer: &str, audience: &str) -> Result<OtpRegisterUrl, String>
{
	let (url, recover) = util_req_full::user::reset_otp(base_url, auth_token, jwt, issuer, audience).await?;

	Ok(OtpRegisterUrl {
		url,
		recover,
	})
}

pub async fn disable_otp(base_url: String, auth_token: &str, jwt: &str) -> Result<(), String>
{
	util_req_full::user::disable_otp(base_url, auth_token, jwt).await
}
