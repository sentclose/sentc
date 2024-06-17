use sentc_crypto_common::user::Claims;

pub mod file;
pub mod group;
pub mod user;

enum SessionKind
{
	Invite,
	Join,
	UserGroup,
}

#[cfg(not(feature = "export"))]
pub(crate) type JwtRes = Result<Claims, crate::SdkError>;

#[cfg(feature = "export")]
pub(crate) type JwtRes = Result<Claims, alloc::string::String>;

#[allow(clippy::needless_question_mark)]
pub fn decode_jwt(token: &str) -> JwtRes
{
	Ok(sentc_crypto_utils::jwt::decode_jwt(token)?)
}
