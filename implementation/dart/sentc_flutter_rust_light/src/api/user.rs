//Jwt

use sentc_crypto_light::util_req_full;

use crate::api::group::GroupInviteReqList;

pub struct Claims
{
	pub aud: String,
	pub sub: String, //the app id
	pub exp: usize,
	pub iat: usize,
	pub fresh: bool, //was this token from refresh jwt or from login?
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

impl From<sentc_crypto_light::DeviceKeyDataExport> for DeviceKeyData
{
	fn from(keys: sentc_crypto_light::DeviceKeyDataExport) -> Self
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

pub struct UserDataExport
{
	pub jwt: String,
	pub user_id: String,
	pub device_id: String,
	pub refresh_token: String,
	pub device_keys: DeviceKeyData,
}

impl From<sentc_crypto_light::UserDataExport> for UserDataExport
{
	fn from(value: sentc_crypto_light::UserDataExport) -> Self
	{
		Self {
			jwt: value.jwt,
			user_id: value.user_id,
			device_id: value.device_id,
			refresh_token: value.refresh_token,
			device_keys: value.device_keys.into(),
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

impl From<util_req_full::user::PreLoginOut> for UserLoginOut
{
	fn from(value: util_req_full::user::PreLoginOut) -> Self
	{
		match value {
			util_req_full::user::PreLoginOut::Direct(d) => {
				Self {
					direct: Some(serde_json::to_string(&d).unwrap()),
					master_key: None,
					auth_key: None,
				}
			},
			util_req_full::user::PreLoginOut::Otp(d) => {
				Self {
					direct: None,
					master_key: Some(d.master_key),
					auth_key: Some(d.auth_key),
				}
			},
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
Generates identifier and password for a user or device
 */
pub fn generate_user_register_data() -> Result<GeneratedRegisterData, String>
{
	let (identifier, password) = sentc_crypto_light::user::generate_user_register_data()?;

	Ok(GeneratedRegisterData {
		identifier,
		password,
	})
}

/**
# Get the user input from the user client

This is used when the register endpoint should only be called from the backend and not the clients.

For the full register see register()
 */
pub fn prepare_register(user_identifier: &str, password: &str) -> Result<String, String>
{
	sentc_crypto_light::user::register(user_identifier, password)
}

/**
# Validates the response of register

Returns the new user id
 */
pub fn done_register(server_output: &str) -> Result<String, String>
{
	sentc_crypto_light::user::done_register(server_output)
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

pub async fn register_device_start(base_url: String, auth_token: &str, device_identifier: &str, password: &str) -> Result<String, String>
{
	util_req_full::user::register_device_start(base_url, auth_token, device_identifier, password).await
}

pub fn done_register_device_start(server_output: &str) -> Result<(), String>
{
	sentc_crypto_light::user::done_register_device_start(server_output)
}

pub async fn register_device(base_url: String, auth_token: &str, jwt: &str, server_output: &str) -> Result<(), String>
{
	util_req_full::user::register_device(base_url, auth_token, jwt, server_output).await
}

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

pub fn extract_user_data(data: &str) -> Result<UserDataExport, String>
{
	let out: sentc_crypto_light::UserDataExport = serde_json::from_str(data).map_err(|err| err.to_string())?;

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
) -> Result<UserDataExport, String>
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

pub async fn refresh_jwt(base_url: String, auth_token: &str, jwt: &str, refresh_token: String) -> Result<String, String>
{
	util_req_full::user::refresh_jwt(base_url, auth_token, jwt, refresh_token).await
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

//no pw reset because this is server side only

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
