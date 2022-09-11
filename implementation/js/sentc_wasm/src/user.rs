use alloc::string::String;

use sentc_crypto::user;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct DeviceKeyData
{
	private_key: String, //Base64 exported keys
	public_key: String,
	sign_key: String,
	verify_key: String,
	exported_public_key: String,
	exported_verify_key: String,
}

impl From<sentc_crypto::util::DeviceKeyData> for DeviceKeyData
{
	fn from(key: sentc_crypto::DeviceKeyData) -> Self
	{
		Self {
			private_key: key.private_key,
			public_key: key.public_key,
			sign_key: key.sign_key,
			verify_key: key.verify_key,
			exported_public_key: key.exported_public_key,
			exported_verify_key: key.exported_verify_key,
		}
	}
}

#[wasm_bindgen]
pub struct UserData
{
	device_keys: DeviceKeyData,
	user_keys: JsValue,

	jwt: String,
	refresh_token: String,
	user_id: String,
	device_id: String,
}

impl From<sentc_crypto::util::UserData> for UserData
{
	fn from(data: sentc_crypto::util::UserData) -> Self
	{
		Self {
			device_keys: data.device_keys.into(),
			user_keys: JsValue::from_serde(&data.user_keys).unwrap(),
			jwt: data.jwt,
			refresh_token: data.refresh_token,
			user_id: data.user_id,
			device_id: data.device_id,
		}
	}
}

#[wasm_bindgen]
impl UserData
{
	pub fn get_user_keys(&self) -> JsValue
	{
		self.user_keys.clone()
	}

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
pub struct UserPublicData
{
	public_key: String,
	public_key_id: String,
	verify_key: String,
	verify_key_id: String,
}

#[wasm_bindgen]
impl UserPublicData
{
	pub fn get_verify_key(&self) -> String
	{
		self.verify_key.clone()
	}

	pub fn get_public_key(&self) -> String
	{
		self.public_key.clone()
	}

	pub fn get_verify_key_id(&self) -> String
	{
		self.verify_key_id.clone()
	}

	pub fn get_public_key_id(&self) -> String
	{
		self.public_key_id.clone()
	}
}

#[wasm_bindgen]
pub struct UserPublicKeyData
{
	public_key: String,
	public_key_id: String,
}

#[wasm_bindgen]
impl UserPublicKeyData
{
	pub fn get_public_key(&self) -> String
	{
		self.public_key.clone()
	}

	pub fn get_public_key_id(&self) -> String
	{
		self.public_key_id.clone()
	}
}

#[wasm_bindgen]
pub struct UserVerifyKeyData
{
	verify_key: String,
	verify_key_id: String,
}

#[wasm_bindgen]
impl UserVerifyKeyData
{
	pub fn get_verify_key(&self) -> String
	{
		self.verify_key.clone()
	}

	pub fn get_verify_key_id(&self) -> String
	{
		self.verify_key_id.clone()
	}
}

#[wasm_bindgen]
pub struct PrepareLoginOutput
{
	auth_key: String,
	master_key_encryption_key: String,
}

#[wasm_bindgen]
impl PrepareLoginOutput
{
	pub fn get_auth_key(&self) -> String
	{
		self.auth_key.clone()
	}

	pub fn get_master_key_encryption_key(&self) -> String
	{
		self.master_key_encryption_key.clone()
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
# Check if the identifier is available for this app
*/
#[wasm_bindgen]
pub async fn check_user_identifier_available(base_url: String, auth_token: String, user_identifier: String) -> Result<bool, JsValue>
{
	let out = sentc_crypto_full::user::check_user_identifier_available(base_url, auth_token.as_str(), user_identifier.as_str()).await?;

	Ok(out)
}

/**
# Check if the identifier is available

but without making a request
*/
#[wasm_bindgen]
pub fn prepare_check_user_identifier_available(user_identifier: &str) -> Result<String, JsValue>
{
	let out = user::prepare_check_user_identifier_available(user_identifier)?;

	Ok(out)
}

/**
# Validates the response if the identifier is available

but without making a request
 */
#[wasm_bindgen]
pub fn done_check_user_identifier_available(server_output: &str) -> Result<bool, JsValue>
{
	let out = user::done_check_user_identifier_available(server_output)?;

	Ok(out)
}

/**
# Get the user input from the user client

This is used when the register endpoint should only be called from the backend and not the clients.

For full register see register()
*/
#[wasm_bindgen]
pub fn prepare_register(user_identifier: &str, password: &str) -> Result<String, JsValue>
{
	Ok(user::register(user_identifier, password)?)
}

/**
# Validates the response of register

Returns the new user id
*/
#[wasm_bindgen]
pub fn done_register(server_output: &str) -> Result<String, JsValue>
{
	let out = user::done_register(server_output)?;

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
	let out = sentc_crypto_full::user::register(
		base_url,
		auth_token.as_str(),
		user_identifier.as_str(),
		password.as_str(),
	)
	.await?;

	Ok(out)
}

#[wasm_bindgen]
pub fn prepare_register_device_start(device_identifier: &str, password: &str) -> Result<String, JsValue>
{
	Ok(user::prepare_register_device_start(device_identifier, password)?)
}

#[wasm_bindgen]
pub fn done_register_device_start(server_output: &str) -> Result<(), JsValue>
{
	Ok(user::done_register_device_start(server_output)?)
}

#[wasm_bindgen]
pub async fn register_device_start(base_url: String, auth_token: String, device_identifier: String, password: String) -> Result<String, JsValue>
{
	let out = sentc_crypto_full::user::register_device_start(
		base_url,
		auth_token.as_str(),
		device_identifier.as_str(),
		password.as_str(),
	)
	.await?;

	Ok(out)
}

#[wasm_bindgen]
pub fn prepare_register_device(server_output: &str, user_keys: &str, key_count: i32) -> Result<String, JsValue>
{
	let key_session = if key_count > 50 { true } else { false };

	let out = user::prepare_register_device(server_output, user_keys, key_session)?;

	Ok(out)
}

#[wasm_bindgen]
pub async fn register_device(
	base_url: String,
	auth_token: String,
	jwt: String,
	server_output: String,
	key_count: i32,
	user_keys: String,
) -> Result<String, JsValue>
{
	let out = sentc_crypto_full::user::register_device(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		server_output.as_str(),
		key_count,
		user_keys.as_str(),
	)
	.await?;

	match out {
		Some(id) => Ok(id),
		None => Ok(String::from("")),
	}
}

#[wasm_bindgen]
pub async fn prepare_login_start(base_url: String, auth_token: String, user_identifier: String) -> Result<String, JsValue>
{
	let out = sentc_crypto_full::user::prepare_login_start(base_url, auth_token.as_str(), user_identifier.as_str()).await?;

	Ok(out)
}

#[wasm_bindgen]
pub fn prepare_login(user_identifier: &str, password: &str, prepare_login_server_output: &str) -> Result<PrepareLoginOutput, JsValue>
{
	let (auth_key, master_key_encryption_key) = user::prepare_login(user_identifier, password, prepare_login_server_output)?;

	Ok(PrepareLoginOutput {
		auth_key,
		master_key_encryption_key,
	})
}

#[wasm_bindgen]
pub fn done_login(master_key_encryption_key: &str, done_login_server_output: &str) -> Result<UserData, JsValue>
{
	let data = user::done_login(master_key_encryption_key, done_login_server_output)?;

	Ok(data.into())
}

/**
# Login the user to this app

Does the login requests. 1. for auth, 2nd to get the keys.

If there are more data in the backend, then it is possible to call it via the jwt what is returned by the done login request.

The other backend can validate the jwt
*/
#[wasm_bindgen]
pub async fn login(base_url: String, auth_token: String, user_identifier: String, password: String) -> Result<UserData, JsValue>
{
	let data = sentc_crypto_full::user::login(
		base_url,
		auth_token.as_str(),
		user_identifier.as_str(),
		password.as_str(),
	)
	.await?;

	Ok(data.into())
}

#[wasm_bindgen]
pub fn done_fetch_user_key(private_key: &str, server_output: &str) -> Result<JsValue, JsValue>
{
	let data = user::done_key_fetch(private_key, server_output)?;

	Ok(JsValue::from_serde(&data).unwrap())
}

#[wasm_bindgen]
pub async fn fetch_user_key(base_url: String, auth_token: String, jwt: String, key_id: String, private_key: String) -> Result<JsValue, JsValue>
{
	let data = sentc_crypto_full::user::fetch_user_key(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		key_id.as_str(),
		private_key.as_str(),
	)
	.await?;

	Ok(JsValue::from_serde(&data).unwrap())
}

#[wasm_bindgen]
pub async fn refresh_jwt(base_url: String, auth_token: String, jwt: String, refresh_token: String) -> Result<String, JsValue>
{
	let out = sentc_crypto_full::user::refresh_jwt(base_url, auth_token.as_str(), jwt.as_str(), refresh_token.as_str()).await?;

	Ok(out)
}

#[wasm_bindgen]
pub async fn init_user(base_url: String, auth_token: String, jwt: String, refresh_token: String) -> Result<UserInitServerOutput, JsValue>
{
	let out = sentc_crypto_full::user::init_user(base_url, auth_token.as_str(), jwt.as_str(), refresh_token.as_str()).await?;

	Ok(UserInitServerOutput {
		jwt: out.jwt,
		invites: JsValue::from_serde(&out.invites).unwrap(),
	})
}

#[wasm_bindgen]
pub async fn reset_password(
	base_url: String,
	auth_token: String,
	jwt: String,
	new_password: String,
	decrypted_private_key: String,
	decrypted_sign_key: String,
) -> Result<(), JsValue>
{
	Ok(sentc_crypto_full::user::reset_password(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		new_password.as_str(),
		decrypted_private_key.as_str(),
		decrypted_sign_key.as_str(),
	)
	.await?)
}

#[wasm_bindgen]
pub async fn change_password(
	base_url: String,
	auth_token: String,
	user_identifier: String,
	old_password: String,
	new_password: String,
) -> Result<(), JsValue>
{
	sentc_crypto_full::user::change_password(
		base_url,
		auth_token.as_str(),
		user_identifier.as_str(),
		old_password.as_str(),
		new_password.as_str(),
	)
	.await?;

	Ok(())
}

#[wasm_bindgen]
pub async fn delete_user(base_url: String, auth_token: String, user_identifier: String, password: String) -> Result<(), JsValue>
{
	Ok(sentc_crypto_full::user::delete(
		base_url,
		auth_token.as_str(),
		user_identifier.as_str(),
		password.as_str(),
	)
	.await?)
}

#[wasm_bindgen]
pub async fn delete_device(
	base_url: String,
	auth_token: String,
	device_identifier: String,
	password: String,
	device_id: String,
) -> Result<(), JsValue>
{
	Ok(sentc_crypto_full::user::delete_device(
		base_url,
		auth_token.as_str(),
		device_identifier.as_str(),
		password.as_str(),
		device_id.as_str(),
	)
	.await?)
}

#[wasm_bindgen]
pub async fn update_user(base_url: String, auth_token: String, jwt: String, user_identifier: String) -> Result<(), JsValue>
{
	Ok(sentc_crypto_full::user::update(base_url, auth_token.as_str(), jwt.as_str(), user_identifier).await?)
}

//__________________________________________________________________________________________________

#[wasm_bindgen]
pub async fn user_fetch_public_data(base_url: String, auth_token: String, user_id: String) -> Result<UserPublicData, JsValue>
{
	let (public_key, public_key_id, verify_key, verify_key_id) =
		sentc_crypto_full::user::fetch_user_public_data(base_url, auth_token.as_str(), user_id.as_str()).await?;

	Ok(UserPublicData {
		public_key,
		public_key_id,
		verify_key,
		verify_key_id,
	})
}

#[wasm_bindgen]
pub async fn user_fetch_public_key(base_url: String, auth_token: String, user_id: String) -> Result<UserPublicKeyData, JsValue>
{
	let (public_key, public_key_id) = sentc_crypto_full::user::fetch_user_public_key(base_url, auth_token.as_str(), user_id.as_str()).await?;

	Ok(UserPublicKeyData {
		public_key,
		public_key_id,
	})
}

#[wasm_bindgen]
pub async fn user_fetch_verify_key(base_url: String, auth_token: String, user_id: String) -> Result<UserVerifyKeyData, JsValue>
{
	let (verify_key, verify_key_id) = sentc_crypto_full::user::fetch_user_verify_key(base_url, auth_token.as_str(), user_id.as_str()).await?;

	Ok(UserVerifyKeyData {
		verify_key,
		verify_key_id,
	})
}
