#[cfg(not(feature = "rust"))]
use alloc::string::String;

use base64ct::Encoding;
pub use sentc_crypto_common::user::Claims;

use crate::error::SdkFullError;

//from the jsonwebtoken crate
macro_rules! expect_two {
	($iter:expr) => {{
		let mut i = $iter;
		match (i.next(), i.next(), i.next()) {
			(Some(first), Some(second), None) => (first, second),
			_ => return Err(SdkFullError::InvalidJwt),
		}
	}};
}

#[cfg(feature = "rust")]
pub(crate) type JwtRes = Result<Claims, SdkFullError>;

#[cfg(not(feature = "rust"))]
pub(crate) type JwtRes = Result<Claims, String>;

pub fn decode_jwt(token: &str) -> JwtRes
{
	Ok(decode_jwt_internally(token)?)
}

fn decode_jwt_internally(token: &str) -> Result<Claims, SdkFullError>
{
	let (_, message) = expect_two!(token.rsplitn(2, '.'));
	let (claims, _header) = expect_two!(message.rsplitn(2, '.'));

	let decoded = base64ct::Base64UrlUnpadded::decode_vec(claims).map_err(|_e| SdkFullError::InvalidJwtFormat)?;

	let claims: Claims = serde_json::from_slice(&decoded).map_err(|_e| SdkFullError::InvalidJwtFormat)?;

	Ok(claims)
}
