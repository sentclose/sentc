pub mod jwt;

use alloc::format;
use alloc::string::String;
use core::future::Future;

use reqwest::header::AUTHORIZATION;

use crate::error::SdkFullError;

pub fn auth_header(jwt: &str) -> String
{
	format!("Bearer {}", jwt)
}

pub enum HttpMethod
{
	GET,
	POST,
	PUT,
	PATCH,
	DELETE,
}

pub fn make_non_auth_req<'a>(
	method: HttpMethod,
	url: &'a str,
	auth_token: &'a str,
	body: Option<String>,
) -> impl Future<Output = Result<String, SdkFullError>> + 'a
{
	make_req(method, url, auth_token, body, None)
}

pub async fn make_req(method: HttpMethod, url: &str, auth_token: &str, body: Option<String>, jwt: Option<&str>) -> Result<String, SdkFullError>
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

	let builder = match body {
		None => builder,
		Some(b) => builder.body(b),
	};

	let res = builder
		.fetch_mode_no_cors()
		.send()
		.await
		.map_err(|e| handle_req_err(e))?;

	res.text().await.map_err(|e| handle_req_err(e))
}

fn handle_req_err(error: reqwest::Error) -> SdkFullError
{
	//TODO handle the different err of reqwest

	SdkFullError::RequestErr
}
