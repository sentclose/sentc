use alloc::format;
use alloc::string::String;

use sentc_crypto::SdkError;

#[derive(Debug)]
pub enum SdkFullError
{
	Base(SdkError),
	RequestErr,
	ResponseErr,
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
		SdkFullError::RequestErr => out_error("client_1000", "Request error"),
		SdkFullError::ResponseErr => out_error("client_1001", "Response error"),
		//_ => out_error("client_0", "other"),
	}
}

pub(crate) fn out_error(code: &str, message: &str) -> String
{
	//create the error in json to communicate with the other implementations, so they can use their own error handling

	format!("{{\"status\": {}, \"error_message\": \"{}\"}}", code, message)
}
