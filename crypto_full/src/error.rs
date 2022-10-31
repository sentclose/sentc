use alloc::format;
use alloc::string::String;

use sentc_crypto::SdkError;

#[derive(Debug)]
pub enum SdkFullError
{
	Base(SdkError),
	RequestErr(String),
	ResponseErrText,
	ResponseErrBytes,
	InvalidJwt,
	InvalidJwtFormat,
}

impl From<SdkError> for SdkFullError
{
	fn from(e: SdkError) -> Self
	{
		SdkFullError::Base(e)
	}
}

impl From<SdkFullError> for String
{
	fn from(e: SdkFullError) -> Self
	{
		err_to_msg(e)
	}
}

pub fn err_to_msg(error: SdkFullError) -> String
{
	match error {
		SdkFullError::Base(base_error) => sentc_crypto::err_to_msg(base_error),
		SdkFullError::RequestErr(e) => out_error("client_1000", format!("Can't send the request: {}", e).as_str()),
		SdkFullError::ResponseErrText => out_error("client_1002", "Can't decode the response to text"),
		SdkFullError::ResponseErrBytes => out_error("client_1003", "Can't get bytes from response"),
		SdkFullError::InvalidJwt => out_error("client_1100", "Jwt is invalid"),
		SdkFullError::InvalidJwtFormat => out_error("client_1101", "Jwt has a wrong format"),
		//_ => out_error("client_0", "other"),
	}
}

pub(crate) fn out_error(code: &str, message: &str) -> String
{
	//create the error in json to communicate with the other implementations, so they can use their own error handling

	format!("{{\"status\": \"{}\", \"error_message\": \"{}\"}}", code, message)
}
