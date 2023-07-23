use alloc::string::{String, ToString};
use alloc::vec::Vec;

use js_sys::Uint8Array;
use sentc_crypto_common::server_default::ServerSuccessOutput;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

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
	let resp = make_req_raw(method, url, auth_token, body, jwt, group_as_member).await?;

	let text = JsFuture::from(resp.text().map_err(|_| SdkUtilError::ResponseErrText)?)
		.await
		.map_err(|_| SdkUtilError::ResponseErrText)?;

	match text.as_string() {
		Some(v) => Ok(v),
		None => Err(SdkUtilError::ResponseErrText),
	}
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
	let resp = make_req_raw(method, url, auth_token, body, jwt, group_as_member).await?;

	let status = resp.status();

	if status >= 400 {
		//don't download part when there is an error
		let text = JsFuture::from(resp.text().map_err(|_| SdkUtilError::ResponseErrText)?)
			.await
			.map_err(|_| SdkUtilError::ResponseErrText)?;

		let text = match text.as_string() {
			Some(v) => v,
			None => return Err(SdkUtilError::ResponseErrText),
		};

		//when status is 400 then there is an error and handle server response will return the error

		handle_server_response::<ServerSuccessOutput>(text.as_str())?;
		return Ok(Vec::new());
	}

	let buffer = JsFuture::from(
		resp.array_buffer()
			.map_err(|_| SdkUtilError::ResponseErrBytes)?,
	)
	.await
	.map_err(|_| SdkUtilError::ResponseErrBytes)?;

	let type_buf = Uint8Array::new(&buffer);
	let bytes: Vec<u8> = type_buf.to_vec();

	Ok(bytes)
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

	let request: Request = Request::new_with_str_and_init(url, &opts).map_err(|_| SdkUtilError::RequestErr("Can't create request".to_string()))?;

	if let Some(j) = jwt {
		request
			.headers()
			.set("Authorization", auth_header(j).as_str())
			.map_err(|_| SdkUtilError::RequestErr("Can't set a header".to_string()))?;
	}

	if let Some(id) = group_as_member {
		request
			.headers()
			.set("x-sentc-group-access-id", id)
			.map_err(|_| SdkUtilError::RequestErr("Can't set a header".to_string()))?;
	}

	request
		.headers()
		.set("Content-Type", "application/json")
		.map_err(|_| SdkUtilError::RequestErr("Can't set a header".to_string()))?;

	request
		.headers()
		.set("x-sentc-app-token", auth_token)
		.map_err(|_| SdkUtilError::RequestErr("Can't set a header".to_string()))?;

	let window = web_sys::window().unwrap();
	let resp_value = JsFuture::from(window.fetch_with_request(&request))
		.await
		.map_err(|e| {
			SdkUtilError::RequestErr(
				e.as_string()
					.unwrap_or_else(|| "Request failed".to_string()),
			)
		})?;

	let resp: Response = resp_value
		.dyn_into()
		.map_err(|_| SdkUtilError::ResponseErrText)?;

	let text = JsFuture::from(resp.text().map_err(|_| SdkUtilError::ResponseErrText)?)
		.await
		.map_err(|_| SdkUtilError::ResponseErrText)?;

	match text.as_string() {
		Some(v) => Ok(v),
		None => Err(SdkUtilError::ResponseErrText),
	}
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

	if let Some(b) = body {
		opts.body(Some(&JsValue::from_str(b.as_str())));
	}

	let request: Request = Request::new_with_str_and_init(url, &opts).map_err(|_| SdkUtilError::RequestErr("Can't create request".to_string()))?;

	if let Some(j) = jwt {
		request
			.headers()
			.set("Authorization", auth_header(j).as_str())
			.map_err(|_| SdkUtilError::RequestErr("Can't set a header".to_string()))?;
	}

	if let Some(id) = group_as_member {
		request
			.headers()
			.set("x-sentc-group-access-id", id)
			.map_err(|_| SdkUtilError::RequestErr("Can't set a header".to_string()))?;
	}

	request
		.headers()
		.set("Content-Type", "application/json")
		.map_err(|_| SdkUtilError::RequestErr("Can't set a header".to_string()))?;

	request
		.headers()
		.set("x-sentc-app-token", auth_token)
		.map_err(|_| SdkUtilError::RequestErr("Can't set a header".to_string()))?;

	let window = web_sys::window().unwrap();
	let resp_value = JsFuture::from(window.fetch_with_request(&request))
		.await
		.map_err(|e| {
			SdkUtilError::RequestErr(
				e.as_string()
					.unwrap_or_else(|| "Request failed".to_string()),
			)
		})?;

	let resp: Response = resp_value.dyn_into().map_err(|e| {
		SdkUtilError::RequestErr(
			e.as_string()
				.unwrap_or_else(|| "Request failed".to_string()),
		)
	})?;

	Ok(resp)
}
