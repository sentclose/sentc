use alloc::string::String;

use sentc_crypto_common::{DeviceId, UserId};
use sentc_crypto_light::util_req_full;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct GeneratedRegisterData
{
	identifier: String,
	password: String,
}

#[wasm_bindgen]
impl GeneratedRegisterData
{
	pub fn get_identifier(&self) -> String
	{
		self.identifier.clone()
	}

	pub fn get_password(&self) -> String
	{
		self.password.clone()
	}
}

#[wasm_bindgen]
pub struct DeviceKeyDataExport
{
	private_key: String, //Base64 exported keys
	public_key: String,
	sign_key: String,
	verify_key: String,
	exported_public_key: String,
	exported_verify_key: String,
}

impl From<sentc_crypto_light::DeviceKeyDataExport> for DeviceKeyDataExport
{
	fn from(value: sentc_crypto_light::DeviceKeyDataExport) -> Self
	{
		Self {
			private_key: value.private_key,
			public_key: value.public_key,
			sign_key: value.sign_key,
			verify_key: value.verify_key,
			exported_public_key: value.exported_public_key,
			exported_verify_key: value.exported_verify_key,
		}
	}
}

#[wasm_bindgen]
pub struct UserDataExport
{
	device_keys: DeviceKeyDataExport,
	jwt: String,
	refresh_token: String,
	user_id: UserId,
	device_id: DeviceId,
}

impl From<sentc_crypto_light::UserDataExport> for UserDataExport
{
	fn from(value: sentc_crypto_light::UserDataExport) -> Self
	{
		Self {
			device_keys: value.device_keys.into(),
			jwt: value.jwt,
			refresh_token: value.refresh_token,
			user_id: value.user_id,
			device_id: value.device_id,
		}
	}
}

#[wasm_bindgen]
impl UserDataExport
{
	pub fn get_device_private_key(&self) -> String
	{
		self.device_keys.private_key.clone()
	}

	pub fn get_device_public_key(&self) -> String
	{
		self.device_keys.public_key.clone()
	}

	pub fn get_device_sign_key(&self) -> String
	{
		self.device_keys.sign_key.clone()
	}

	pub fn get_device_verify_key(&self) -> String
	{
		self.device_keys.verify_key.clone()
	}

	pub fn get_device_exported_public_key(&self) -> String
	{
		self.device_keys.exported_public_key.clone()
	}

	pub fn get_device_exported_verify_key(&self) -> String
	{
		self.device_keys.exported_verify_key.clone()
	}

	pub fn get_jwt(&self) -> String
	{
		self.jwt.clone()
	}

	pub fn get_refresh_token(&self) -> String
	{
		self.refresh_token.clone()
	}

	pub fn get_id(&self) -> String
	{
		self.user_id.clone()
	}

	pub fn get_device_id(&self) -> String
	{
		self.device_id.clone()
	}
}

#[wasm_bindgen]
pub struct PrepareLoginOtpOutput
{
	master_key: String,
	auth_key: String,
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

#[wasm_bindgen]
pub struct UserLoginOut
{
	user_data: Option<UserDataExport>,

	mfa: Option<PrepareLoginOtpOutput>,
}

impl From<util_req_full::user::PreLoginOut> for UserLoginOut
{
	fn from(value: util_req_full::user::PreLoginOut) -> Self
	{
		match value {
			util_req_full::user::PreLoginOut::Direct(d) => {
				Self {
					mfa: None,
					user_data: Some(d.into()),
				}
			},
			util_req_full::user::PreLoginOut::Otp(d) => {
				Self {
					user_data: None,
					mfa: Some(d.into()),
				}
			},
		}
	}
}

#[wasm_bindgen]
impl UserLoginOut
{
	pub fn get_device_private_key(&self) -> Option<String>
	{
		self.user_data
			.as_ref()
			.map(|o| o.device_keys.private_key.clone())
	}

	pub fn get_device_public_key(&self) -> Option<String>
	{
		self.user_data
			.as_ref()
			.map(|o| o.device_keys.public_key.clone())
	}

	pub fn get_device_sign_key(&self) -> Option<String>
	{
		self.user_data
			.as_ref()
			.map(|o| o.device_keys.sign_key.clone())
	}

	pub fn get_device_verify_key(&self) -> Option<String>
	{
		self.user_data
			.as_ref()
			.map(|o| o.device_keys.verify_key.clone())
	}

	pub fn get_device_exported_public_key(&self) -> Option<String>
	{
		self.user_data
			.as_ref()
			.map(|o| o.device_keys.exported_public_key.clone())
	}

	pub fn get_device_exported_verify_key(&self) -> Option<String>
	{
		self.user_data
			.as_ref()
			.map(|o| o.device_keys.exported_verify_key.clone())
	}

	pub fn get_jwt(&self) -> Option<String>
	{
		self.user_data.as_ref().map(|o| o.jwt.clone())
	}

	pub fn get_refresh_token(&self) -> Option<String>
	{
		self.user_data.as_ref().map(|o| o.refresh_token.clone())
	}

	pub fn get_id(&self) -> Option<String>
	{
		self.user_data.as_ref().map(|o| o.user_id.clone())
	}

	pub fn get_device_id(&self) -> Option<String>
	{
		self.user_data.as_ref().map(|o| o.device_id.clone())
	}

	pub fn get_mfa_master_key(&self) -> Option<String>
	{
		self.mfa.as_ref().map(|o| o.master_key.clone())
	}

	pub fn get_mfa_auth_key(&self) -> Option<String>
	{
		self.mfa.as_ref().map(|o| o.auth_key.clone())
	}
}

#[wasm_bindgen]
pub struct UserInitServerOutput
{
	jwt: String,
	invites: JsValue,
}

#[wasm_bindgen]
impl UserInitServerOutput
{
	pub fn get_jwt(&self) -> String
	{
		self.jwt.clone()
	}

	pub fn get_invites(&self) -> JsValue
	{
		self.invites.clone()
	}
}

/**
# Check if the identifier is available

but without making a request
 */
#[wasm_bindgen]
pub fn prepare_check_user_identifier_available(user_identifier: &str) -> Result<String, JsValue>
{
	let out = sentc_crypto_light::user::prepare_check_user_identifier_available(user_identifier)?;

	Ok(out)
}

/**
# Validates the response if the identifier is available

but without making a request
 */
#[wasm_bindgen]
pub fn done_check_user_identifier_available(server_output: &str) -> Result<bool, JsValue>
{
	let out = sentc_crypto_light::user::done_check_user_identifier_available(server_output)?;

	Ok(out)
}

#[wasm_bindgen]
pub fn generate_user_register_data() -> Result<GeneratedRegisterData, JsValue>
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

For full register see register()
 */
#[wasm_bindgen]
pub fn prepare_register(user_identifier: &str, password: &str) -> Result<String, JsValue>
{
	Ok(sentc_crypto_light::user::register(user_identifier, password)?)
}

/**
# Validates the response of register

Returns the new user id
 */
#[wasm_bindgen]
pub fn done_register(server_output: &str) -> Result<String, JsValue>
{
	let out = sentc_crypto_light::user::done_register(server_output)?;

	Ok(out)
}

/**
# Register a new user for the app

Do the full req incl. req.
No checking about spamming and just return the user id.
 */
#[wasm_bindgen]
pub async fn register(base_url: String, auth_token: String, user_identifier: String, password: String) -> Result<String, JsValue>
{
	let out = util_req_full::user::register(base_url, &auth_token, &user_identifier, &password).await?;

	Ok(out)
}

#[wasm_bindgen]
pub fn done_register_device_start(server_output: &str) -> Result<(), JsValue>
{
	Ok(sentc_crypto_light::user::done_register_device_start(server_output)?)
}

#[wasm_bindgen]
pub async fn register_device_start(base_url: String, auth_token: String, device_identifier: String, password: String) -> Result<String, JsValue>
{
	let out = util_req_full::user::register_device_start(base_url, &auth_token, &device_identifier, &password).await?;

	Ok(out)
}

#[wasm_bindgen]
pub async fn register_device(base_url: String, auth_token: String, jwt: String, server_output: String) -> Result<(), JsValue>
{
	util_req_full::user::register_device(base_url, &auth_token, &jwt, &server_output).await?;

	Ok(())
}

/**
# Login the user to this app

Does the login requests. 1. for auth, 2nd to get the keys.

If there are more data in the backend, then it is possible to call it via the jwt what is returned by the done login request.

The other backend can validate the jwt
 */
#[wasm_bindgen]
pub async fn login(base_url: String, auth_token: String, user_identifier: String, password: String) -> Result<UserLoginOut, JsValue>
{
	let data = util_req_full::user::login(
		base_url,
		auth_token.as_str(),
		user_identifier.as_str(),
		password.as_str(),
	)
	.await?;

	Ok(data.into())
}

#[wasm_bindgen]
pub async fn mfa_login(
	base_url: String,
	auth_token: String,
	master_key_encryption: String,
	auth_key: String,
	user_identifier: String,
	token: String,
	recovery: bool,
) -> Result<UserDataExport, JsValue>
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
	.await?;

	Ok(data.into())
}

#[wasm_bindgen]
pub async fn get_fresh_jwt(
	base_url: String,
	auth_token: String,
	user_identifier: String,
	password: String,
	mfa_token: Option<String>,
	mfa_recovery: Option<bool>,
) -> Result<String, JsValue>
{
	Ok(util_req_full::user::get_fresh_jwt(
		base_url,
		&auth_token,
		&user_identifier,
		&password,
		mfa_token,
		mfa_recovery,
	)
	.await?)
}

#[wasm_bindgen]
pub async fn refresh_jwt(base_url: String, auth_token: String, jwt: String, refresh_token: String) -> Result<String, JsValue>
{
	let out = util_req_full::user::refresh_jwt(base_url, &auth_token, &jwt, refresh_token).await?;

	Ok(out)
}

#[wasm_bindgen]
pub async fn init_user(base_url: String, auth_token: String, jwt: String, refresh_token: String) -> Result<UserInitServerOutput, JsValue>
{
	let out = util_req_full::user::init_user(base_url, &auth_token, &jwt, refresh_token).await?;

	Ok(UserInitServerOutput {
		jwt: out.jwt,
		invites: JsValue::from_serde(&out.invites).unwrap(),
	})
}

//no pw reset because this is server side only

#[wasm_bindgen]
pub async fn change_password(
	base_url: String,
	auth_token: String,
	user_identifier: String,
	old_password: String,
	new_password: String,
	mfa_token: Option<String>,
	mfa_recovery: Option<bool>,
) -> Result<(), JsValue>
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
	.await?;

	Ok(())
}

#[wasm_bindgen]
pub async fn delete_user(base_url: String, auth_token: String, fresh_jwt: String) -> Result<(), JsValue>
{
	Ok(util_req_full::user::delete(base_url, &auth_token, &fresh_jwt).await?)
}

#[wasm_bindgen]
pub async fn delete_device(base_url: String, auth_token: String, fresh_jwt: String, device_id: String) -> Result<(), JsValue>
{
	Ok(util_req_full::user::delete_device(base_url, &auth_token, &fresh_jwt, &device_id).await?)
}

#[wasm_bindgen]
pub fn user_prepare_user_identifier_update(user_identifier: String) -> Result<String, JsValue>
{
	Ok(sentc_crypto_light::user::prepare_user_identifier_update(
		user_identifier,
	)?)
}
