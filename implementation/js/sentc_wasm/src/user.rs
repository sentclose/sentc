use alloc::string::String;

use sentc_crypto::user;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct KeyData
{
	private_key: String, //Base64 exported keys
	public_key: String,
	sign_key: String,
	verify_key: String,
	exported_public_key: String,
	exported_verify_key: String,
}

impl From<sentc_crypto::util::KeyData> for KeyData
{
	fn from(key: sentc_crypto::KeyData) -> Self
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
	keys: KeyData,
	jwt: String,
	refresh_token: String,
	user_id: String,
}

impl From<sentc_crypto::util::UserData> for UserData
{
	fn from(data: sentc_crypto::util::UserData) -> Self
	{
		Self {
			jwt: data.jwt,
			refresh_token: data.refresh_token,
			user_id: data.user_id,
			keys: data.keys.into(),
		}
	}
}

#[wasm_bindgen]
impl UserData
{
	pub fn get_private_key(&self) -> String
	{
		self.keys.private_key.clone()
	}

	pub fn get_public_key(&self) -> String
	{
		self.keys.public_key.clone()
	}

	pub fn get_sign_key(&self) -> String
	{
		self.keys.sign_key.clone()
	}

	pub fn get_verify_key(&self) -> String
	{
		self.keys.verify_key.clone()
	}

	pub fn get_exported_public_key(&self) -> String
	{
		self.keys.exported_public_key.clone()
	}

	pub fn get_exported_verify_key(&self) -> String
	{
		self.keys.exported_verify_key.clone()
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
}

#[wasm_bindgen]
pub struct UserPublicData
{
	public_key: String,
	verify_key: String,
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
pub async fn update_user(base_url: String, auth_token: String, jwt: String, user_identifier: String) -> Result<String, JsValue>
{
	Ok(sentc_crypto_full::user::update(base_url, auth_token.as_str(), jwt.as_str(), user_identifier).await?)
}

//__________________________________________________________________________________________________

#[wasm_bindgen]
pub async fn user_fetch_public_data(base_url: String, auth_token: String, user_id: String) -> Result<UserPublicData, JsValue>
{
	let (public_key, verify_key) = sentc_crypto_full::user::fetch_user_public_data(base_url, auth_token.as_str(), user_id.as_str()).await?;

	Ok(UserPublicData {
		public_key,
		verify_key,
	})
}

#[wasm_bindgen]
pub async fn user_fetch_public_key(base_url: String, auth_token: String, user_id: String) -> Result<String, JsValue>
{
	Ok(sentc_crypto_full::user::fetch_user_public_key(base_url, auth_token.as_str(), user_id.as_str()).await?)
}

#[wasm_bindgen]
pub async fn user_fetch_verify_key(base_url: String, auth_token: String, user_id: String) -> Result<String, JsValue>
{
	Ok(sentc_crypto_full::user::fetch_user_verify_key(base_url, auth_token.as_str(), user_id.as_str()).await?)
}
