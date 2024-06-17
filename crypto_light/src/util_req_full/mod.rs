pub mod group;
pub mod user;

use sentc_crypto_common::user::Claims;

#[cfg(not(feature = "export"))]
pub(crate) type JwtRes = Result<Claims, crate::error::SdkLightError>;

#[cfg(feature = "export")]
pub(crate) type JwtRes = Result<Claims, alloc::string::String>;

#[allow(clippy::needless_question_mark)]
pub fn decode_jwt(token: &str) -> JwtRes
{
	Ok(sentc_crypto_utils::jwt::decode_jwt(token)?)
}
