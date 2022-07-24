#![no_std]

pub mod crypto;
pub mod group;
pub mod test_fn;
pub mod user;

extern crate alloc;

use alloc::format;
use alloc::string::String;

use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, Response};

async fn make_req(url: &str, bearer_header: &str, req_opts: &RequestInit) -> Result<String, JsValue>
{
	let request = Request::new_with_str_and_init(url, req_opts)?;

	request
		.headers()
		.set("Authorization", format!("Bearer {}", bearer_header).as_str())?;

	request.headers().set("Content-Type", "application/json")?;

	let window = web_sys::window().unwrap();
	let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;

	let resp: Response = resp_value.dyn_into().unwrap();
	let text = JsFuture::from(resp.text()?).await?;

	match text.as_string() {
		Some(v) => Ok(v),
		None => return Err(JsValue::from_str("String parsing failed")),
	}
}
