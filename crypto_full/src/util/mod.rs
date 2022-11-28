mod http;
pub mod jwt;

use alloc::format;
use alloc::string::String;

pub fn auth_header(jwt: &str) -> String
{
	format!("Bearer {}", jwt)
}

pub use self::http::{auth_req, make_req, make_req_buffer, make_req_buffer_body, non_auth_req, normal_req, HttpMethod};
