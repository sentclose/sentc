use alloc::string::{String, ToString};
use alloc::vec::Vec;

use js_sys::Uint8Array;
use sentc_crypto::util::public::handle_server_response;
use sentc_crypto_common::server_default::ServerSuccessOutput;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

use crate::error::SdkFullError;
use crate::util::{auth_header, HttpMethod};

pub async fn make_req(method: HttpMethod, url: &str, auth_token: &str, body: Option<String>, jwt: Option<&str>) -> Result<String, SdkFullError>
{
	let resp = make_req_raw(method, url, auth_token, body, jwt).await?;

	let text = JsFuture::from(resp.text().map_err(|_| SdkFullError::ResponseErrText)?)
		.await
		.map_err(|_| SdkFullError::ResponseErrText)?;

	match text.as_string() {
		Some(v) => Ok(v),
		None => return Err(SdkFullError::ResponseErrText),
	}
}

pub async fn make_req_buffer(
	method: HttpMethod,
	url: &str,
	auth_token: &str,
	body: Option<String>,
	jwt: Option<&str>,
) -> Result<Vec<u8>, SdkFullError>
{
	let resp = make_req_raw(method, url, auth_token, body, jwt).await?;

	let status = resp.status();

	if status >= 400 {
		//don't download part when there is an error
		let text = JsFuture::from(resp.text().map_err(|_| SdkFullError::ResponseErrText)?)
			.await
			.map_err(|_| SdkFullError::ResponseErrText)?;

		let text = match text.as_string() {
			Some(v) => v,
			None => return Err(SdkFullError::ResponseErrText),
		};

		//when status is 400 then there is an error and handle server response will return the error

		handle_server_response::<ServerSuccessOutput>(text.as_str())?;
		return Ok(Vec::new());
	}

	let buffer = JsFuture::from(
		resp.array_buffer()
			.map_err(|_| SdkFullError::ResponseErrBytes)?,
	)
	.await
	.map_err(|_| SdkFullError::ResponseErrBytes)?;

	let type_buf = Uint8Array::new(&buffer);
	let bytes: Vec<u8> = type_buf.to_vec();

	Ok(bytes)
}

pub async fn make_req_buffer_body(method: HttpMethod, url: &str, auth_token: &str, body: Vec<u8>, jwt: Option<&str>) -> Result<String, SdkFullError>
{
	let method = match method {
		HttpMethod::GET => "GET",
		HttpMethod::POST => "POST",
		HttpMethod::PUT => "PUT",
		HttpMethod::PATCH => "PATCH",
		HttpMethod::DELETE => "DELETE",
	};

	let mut opts = RequestInit::new();
	opts.method(method);
	opts.mode(RequestMode::Cors);

	let body = Uint8Array::from(body.as_ref());
	let body = JsValue::from(body);

	opts.body(Some(&body));

	let request: Request = Request::new_with_str_and_init(url, &opts).map_err(|_| SdkFullError::RequestErr("Can't create request".to_string()))?;

	match jwt {
		Some(j) => {
			request
				.headers()
				.set("Authorization", auth_header(j).as_str())
				.map_err(|_| SdkFullError::RequestErr("Can't set a header".to_string()))?;
		},
		None => {},
	}

	request
		.headers()
		.set("Content-Type", "application/json")
		.map_err(|_| SdkFullError::RequestErr("Can't set a header".to_string()))?;

	request
		.headers()
		.set("x-sentc-app-token", auth_token)
		.map_err(|_| SdkFullError::RequestErr("Can't set a header".to_string()))?;

	let window = web_sys::window().unwrap();
	let resp_value = JsFuture::from(window.fetch_with_request(&request))
		.await
		.map_err(|e| SdkFullError::RequestErr(e.as_string().unwrap_or("Request failed".to_string())))?;

	let resp: Response = resp_value
		.dyn_into()
		.map_err(|_| SdkFullError::ResponseErrText)?;

	let text = JsFuture::from(resp.text().map_err(|_| SdkFullError::ResponseErrText)?)
		.await
		.map_err(|_| SdkFullError::ResponseErrText)?;

	match text.as_string() {
		Some(v) => Ok(v),
		None => return Err(SdkFullError::ResponseErrText),
	}
}

async fn make_req_raw(method: HttpMethod, url: &str, auth_token: &str, body: Option<String>, jwt: Option<&str>) -> Result<Response, SdkFullError>
{
	let method = match method {
		HttpMethod::GET => "GET",
		HttpMethod::POST => "POST",
		HttpMethod::PUT => "PUT",
		HttpMethod::PATCH => "PATCH",
		HttpMethod::DELETE => "DELETE",
	};

	let mut opts = RequestInit::new();
	opts.method(method);
	opts.mode(RequestMode::Cors);

	match body {
		Some(b) => {
			opts.body(Some(&JsValue::from_str(b.as_str())));
		},
		None => {},
	}

	let request: Request = Request::new_with_str_and_init(url, &opts).map_err(|_| SdkFullError::RequestErr("Can't create request".to_string()))?;

	match jwt {
		Some(j) => {
			request
				.headers()
				.set("Authorization", auth_header(j).as_str())
				.map_err(|_| SdkFullError::RequestErr("Can't set a header".to_string()))?;
		},
		None => {},
	}

	request
		.headers()
		.set("Content-Type", "application/json")
		.map_err(|_| SdkFullError::RequestErr("Can't set a header".to_string()))?;

	request
		.headers()
		.set("x-sentc-app-token", auth_token)
		.map_err(|_| SdkFullError::RequestErr("Can't set a header".to_string()))?;

	let window = web_sys::window().unwrap();
	let resp_value = JsFuture::from(window.fetch_with_request(&request))
		.await
		.map_err(|e| SdkFullError::RequestErr(e.as_string().unwrap_or("Request failed".to_string())))?;

	let resp: Response = resp_value
		.dyn_into()
		.map_err(|e| SdkFullError::RequestErr(e.as_string().unwrap_or("Request failed".to_string())))?;

	return Ok(resp);
}
