#![no_std]

pub mod user;

extern crate alloc;

use sentc_crypto_common::user::Claims;

#[cfg(feature = "rust")]
pub(crate) type JwtRes = Result<Claims, sentc_crypto_light::error::SdkLightError>;

#[cfg(not(feature = "rust"))]
pub(crate) type JwtRes = Result<Claims, alloc::string::String>;

#[allow(clippy::needless_question_mark)]
pub fn decode_jwt(token: &str) -> JwtRes
{
	Ok(sentc_crypto_utils::jwt::decode_jwt(token)?)
}
