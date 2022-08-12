use alloc::string::String;

use sentc_crypto::{user, KeyData};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct DoneLoginData
{
	private_key: String, //Base64 exported keys
	public_key: String,
	sign_key: String,
	verify_key: String,
	jwt: String,
	user_id: String,
	exported_public_key: String,
	exported_verify_key: String,
}

impl From<KeyData> for DoneLoginData
{
	fn from(keys: KeyData) -> Self
	{
		Self {
			private_key: keys.private_key,
			public_key: keys.public_key,
			sign_key: keys.sign_key,
			verify_key: keys.verify_key,
			jwt: keys.jwt,
			user_id: keys.user_id,
			exported_public_key: keys.exported_public_key,
			exported_verify_key: keys.exported_verify_key,
		}
	}
}

#[wasm_bindgen]
impl DoneLoginData
{
	pub fn get_private_key(&self) -> String
	{
		self.private_key.clone()
	}

	pub fn get_public_key(&self) -> String
	{
		self.public_key.clone()
	}

	pub fn get_sign_key(&self) -> String
	{
		self.sign_key.clone()
	}

	pub fn get_verify_key(&self) -> String
	{
		self.verify_key.clone()
	}

	pub fn get_jwt(&self) -> String
	{
		self.jwt.clone()
	}

	pub fn get_id(&self) -> String
	{
		self.user_id.clone()
	}

	pub fn get_exported_public_key(&self) -> String
	{
		self.exported_public_key.clone()
	}

	pub fn get_exported_verify_key(&self) -> String
	{
		self.exported_verify_key.clone()
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
pub async fn login(base_url: String, auth_token: String, user_identifier: String, password: String) -> Result<DoneLoginData, JsValue>
{
	let keys = sentc_crypto_full::user::login(
		base_url,
		auth_token.as_str(),
		user_identifier.as_str(),
		password.as_str(),
	)
	.await?;

	Ok(keys.into())
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
pub async fn delete_user(base_url: String, auth_token: String, jwt: String) -> Result<(), JsValue>
{
	Ok(sentc_crypto_full::user::delete(base_url, auth_token.as_str(), jwt.as_str()).await?)
}

#[wasm_bindgen]
pub async fn update_user(base_url: String, auth_token: String, jwt: String, user_identifier: String) -> Result<String, JsValue>
{
	Ok(sentc_crypto_full::user::update(base_url, auth_token.as_str(), jwt.as_str(), user_identifier).await?)
}
