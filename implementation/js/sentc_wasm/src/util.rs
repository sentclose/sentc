use alloc::string::String;

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

#[wasm_bindgen]
pub struct Claims
{
	aud: String,
	sub: String, //the app id
	exp: usize,
	iat: usize,

	//sentc
	internal_user_id: String,
	group_id: String,
	device_id: String,
	device_identifier: String,
	fresh: bool, //was this token from refresh jwt or from login
}

#[wasm_bindgen]
impl Claims
{
	pub fn get_aud(&self) -> String
	{
		self.aud.clone()
	}

	pub fn get_sub(&self) -> String
	{
		self.sub.clone()
	}

	pub fn get_exp(&self) -> usize
	{
		self.exp
	}

	pub fn get_iat(&self) -> usize
	{
		self.iat
	}

	pub fn get_internal_user_id(&self) -> String
	{
		self.internal_user_id.clone()
	}

	pub fn get_device_id(&self) -> String
	{
		self.device_id.clone()
	}

	pub fn get_group_id(&self) -> String
	{
		self.group_id.clone()
	}

	pub fn get_device_identifier(&self) -> String
	{
		self.device_identifier.clone()
	}

	pub fn get_fresh(&self) -> bool
	{
		self.fresh
	}
}

impl From<sentc_crypto_full::jwt::Claims> for Claims
{
	fn from(claims: sentc_crypto_full::jwt::Claims) -> Self
	{
		Self {
			aud: claims.aud,
			sub: claims.sub,
			exp: claims.exp,
			iat: claims.iat,
			internal_user_id: claims.internal_user_id,
			group_id: claims.group_id,
			device_id: claims.device_id,
			device_identifier: claims.device_identifier,
			fresh: claims.fresh,
		}
	}
}

#[wasm_bindgen]
pub fn decode_jwt(jwt: &str) -> Result<Claims, JsValue>
{
	let claims = sentc_crypto_full::jwt::decode_jwt(jwt)?;

	Ok(claims.into())
}
