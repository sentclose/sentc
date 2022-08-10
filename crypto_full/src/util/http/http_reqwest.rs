use alloc::string::String;

use reqwest::header::AUTHORIZATION;

use crate::error::SdkFullError;
use crate::util::{auth_header, HttpMethod};

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
