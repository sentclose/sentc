pub mod group;
pub mod user;

use sentc_crypto_common::user::Claims;

#[cfg(feature = "rust")]
pub(crate) type JwtRes = Result<Claims, crate::error::SdkLightError>;

#[cfg(not(feature = "rust"))]
pub(crate) type JwtRes = Result<Claims, alloc::string::String>;

#[allow(clippy::needless_question_mark)]
pub fn decode_jwt(token: &str) -> JwtRes
{
	Ok(sentc_crypto_utils::jwt::decode_jwt(token)?)
}
