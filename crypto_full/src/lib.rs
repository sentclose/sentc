#![no_std]
#![allow(clippy::too_many_arguments)]

extern crate alloc;

use sentc_crypto_common::user::Claims;

pub mod content;
pub mod crypto;

pub mod file;
pub mod group;
pub mod user;

#[cfg(feature = "rust")]
pub(crate) type JwtRes = Result<Claims, sentc_crypto::SdkError>;

#[cfg(not(feature = "rust"))]
pub(crate) type JwtRes = Result<Claims, alloc::string::String>;

#[allow(clippy::needless_question_mark)]
pub fn decode_jwt(token: &str) -> JwtRes
{
	Ok(sentc_crypto_utils::jwt::decode_jwt(token)?)
}
