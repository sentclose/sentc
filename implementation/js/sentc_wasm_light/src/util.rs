use alloc::string::String;

use sentc_crypto_light::util_req_full;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

#[wasm_bindgen]
pub struct Claims
{
	aud: String,
	sub: String, //the app id
	exp: usize,
	iat: usize,
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

	pub fn get_fresh(&self) -> bool
	{
		self.fresh
	}
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

#[wasm_bindgen]
pub fn decode_jwt(jwt: &str) -> Result<Claims, JsValue>
{
	let claims = util_req_full::decode_jwt(jwt)?;

	Ok(claims.into())
}
