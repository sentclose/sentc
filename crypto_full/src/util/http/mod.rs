#[cfg(not(feature = "wasm"))]
mod http_reqwest;
#[cfg(feature = "wasm")]
mod http_wasm;

use alloc::string::String;
use core::future::Future;

#[cfg(not(feature = "wasm"))]
pub use self::http_reqwest::{make_req, make_req_buffer, make_req_buffer_body};
#[cfg(feature = "wasm")]
pub use self::http_wasm::{make_req, make_req_buffer, make_req_buffer_body};
use crate::error::SdkFullError;

pub fn make_non_auth_req<'a>(
	method: HttpMethod,
	url: &'a str,
	auth_token: &'a str,
	body: Option<String>,
) -> impl Future<Output = Result<String, SdkFullError>> + 'a
{
	make_req(method, url, auth_token, body, None)
}

pub enum HttpMethod
{
	GET,
	POST,
	PUT,
	PATCH,
	DELETE,
}
