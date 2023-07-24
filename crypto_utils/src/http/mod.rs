#[cfg(not(feature = "wasm"))]
mod http_reqwest;
#[cfg(feature = "wasm")]
mod http_wasm;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::future::Future;

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

pub fn make_req<'a>(
	method: HttpMethod,
	url: &'a str,
	auth_token: &'a str,
	body: Option<String>,
	jwt: Option<&'a str>,
	group_as_member: Option<&'a str>,
) -> impl Future<Output = Result<String, SdkUtilError>> + 'a
{
	#[cfg(feature = "wasm")]
	return http_wasm::make_req(method, url, auth_token, body, jwt, group_as_member);

	#[cfg(not(feature = "wasm"))]
	return http_reqwest::make_req(method, url, auth_token, body, jwt, group_as_member);
}

pub fn make_req_buffer<'a>(
	method: HttpMethod,
	url: &'a str,
	auth_token: &'a str,
	body: Option<String>,
	jwt: Option<&'a str>,
	group_as_member: Option<&'a str>,
) -> impl Future<Output = Result<Vec<u8>, SdkUtilError>> + 'a
{
	#[cfg(feature = "wasm")]
	return http_wasm::make_req_buffer(method, url, auth_token, body, jwt, group_as_member);

	#[cfg(not(feature = "wasm"))]
	return http_reqwest::make_req_buffer(method, url, auth_token, body, jwt, group_as_member);
}

pub fn make_req_buffer_body<'a>(
	method: HttpMethod,
	url: &'a str,
	auth_token: &'a str,
	body: Vec<u8>,
	jwt: Option<&'a str>,
	group_as_member: Option<&'a str>,
) -> impl Future<Output = Result<String, SdkUtilError>> + 'a
{
	#[cfg(feature = "wasm")]
	return http_wasm::make_req_buffer_body(method, url, auth_token, body, jwt, group_as_member);

	#[cfg(not(feature = "wasm"))]
	return http_reqwest::make_req_buffer_body(method, url, auth_token, body, jwt, group_as_member);
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
