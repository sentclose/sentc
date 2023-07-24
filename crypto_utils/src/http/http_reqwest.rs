use alloc::string::{String, ToString};
use alloc::vec::Vec;

use reqwest::header::AUTHORIZATION;
use reqwest::Response;
use sentc_crypto_common::server_default::ServerSuccessOutput;

use crate::error::SdkUtilError;
use crate::handle_server_response;
use crate::http::{auth_header, HttpMethod};

pub(super) async fn make_req(
	method: HttpMethod,
	url: &str,
	auth_token: &str,
	body: Option<String>,
	jwt: Option<&str>,
	group_as_member: Option<&str>,
) -> Result<String, SdkUtilError>
{
	let res = make_req_raw(method, url, auth_token, body, jwt, group_as_member).await?;

	res.text().await.map_err(|_e| SdkUtilError::ResponseErrText)
}

pub(super) async fn make_req_buffer(
	method: HttpMethod,
	url: &str,
	auth_token: &str,
	body: Option<String>,
	jwt: Option<&str>,
	group_as_member: Option<&str>,
) -> Result<Vec<u8>, SdkUtilError>
{
	let res = make_req_raw(method, url, auth_token, body, jwt, group_as_member).await?;

	if res.status().as_u16() >= 400 {
		let text = res
			.text()
			.await
			.map_err(|_e| SdkUtilError::ResponseErrText)?;
		handle_server_response::<ServerSuccessOutput>(text.as_str())?;
		return Ok(Vec::new());
	}

	let buffer = res
		.bytes()
		.await
		.map_err(|_e| SdkUtilError::ResponseErrBytes)?
		.to_vec();

	Ok(buffer)
}

pub(super) async fn make_req_buffer_body(
	method: HttpMethod,
	url: &str,
	auth_token: &str,
	body: Vec<u8>,
	jwt: Option<&str>,
	group_as_member: Option<&str>,
) -> Result<String, SdkUtilError>
{
	let client = reqwest::Client::new();

	let builder = match method {
		HttpMethod::GET => client.get(url),
		HttpMethod::POST => client.post(url),
		HttpMethod::PUT => client.put(url),
		HttpMethod::PATCH => client.patch(url),
		HttpMethod::DELETE => client.delete(url),
	};

	let builder = builder.header("x-sentc-app-token", auth_token);

	let builder = match jwt {
		Some(j) => builder.header(AUTHORIZATION, auth_header(j)),
		None => builder,
	};

	let builder = match group_as_member {
		Some(id) => builder.header("x-sentc-group-access-id", id),
		None => builder,
	};

	let builder = builder.body(body);

	let res = builder
		.send()
		.await
		.map_err(|e| SdkUtilError::RequestErr(e.to_string()))?;

	res.text().await.map_err(|_e| SdkUtilError::ResponseErrText)
}

async fn make_req_raw(
	method: HttpMethod,
	url: &str,
	auth_token: &str,
	body: Option<String>,
	jwt: Option<&str>,
	group_as_member: Option<&str>,
) -> Result<Response, SdkUtilError>
{
	let client = reqwest::Client::new();

	let builder = match method {
		HttpMethod::GET => client.get(url),
		HttpMethod::POST => client.post(url),
		HttpMethod::PUT => client.put(url),
		HttpMethod::PATCH => client.patch(url),
		HttpMethod::DELETE => client.delete(url),
	};

	let builder = builder.header("x-sentc-app-token", auth_token);

	let builder = match jwt {
		Some(j) => builder.header(AUTHORIZATION, auth_header(j)),
		None => builder,
	};

	let builder = match group_as_member {
		Some(id) => builder.header("x-sentc-group-access-id", id),
		None => builder,
	};

	let builder = match body {
		None => builder,
		Some(b) => builder.body(b),
	};

	let res = builder
		.send()
		.await
		.map_err(|e| SdkUtilError::RequestErr(e.to_string()))?;

	Ok(res)
}
