#[cfg(feature = "rustls")]
mod http_reqwest;
#[cfg(feature = "wasm")]
mod http_wasm;

use alloc::string::{String, ToString};
use core::future::Future;

#[cfg(feature = "rustls")]
pub use http_reqwest::{make_req, make_req_buffer, make_req_buffer_body};
#[cfg(all(feature = "wasm", not(feature = "rustls")))]
pub use http_wasm::{make_req, make_req_buffer, make_req_buffer_body};

use crate::error::SdkUtilError;

pub fn auth_header(jwt: &str) -> String
{
	"Bearer ".to_string() + jwt
}

pub enum HttpMethod
{
	GET,
	POST,
	PUT,
	PATCH,
	DELETE,
}

pub fn non_auth_req<'a>(
	method: HttpMethod,
	url: &'a str,
	auth_token: &'a str,
	body: Option<String>,
) -> impl Future<Output = Result<String, SdkUtilError>> + 'a
{
	make_req(method, url, auth_token, body, None, None)
}

pub fn auth_req<'a>(
	method: HttpMethod,
	url: &'a str,
	auth_token: &'a str,
	body: Option<String>,
	jwt: &'a str,
) -> impl Future<Output = Result<String, SdkUtilError>> + 'a
{
	make_req(method, url, auth_token, body, Some(jwt), None)
}

pub fn normal_req<'a>(
	method: HttpMethod,
	url: &'a str,
	auth_token: &'a str,
	body: Option<String>,
	jwt: Option<&'a str>,
) -> impl Future<Output = Result<String, SdkUtilError>> + 'a
{
	make_req(method, url, auth_token, body, jwt, None)
}
