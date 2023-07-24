use alloc::format;
use alloc::string::String;

use sentc_crypto_core::Error;
use sentc_crypto_utils::error::{out_error, SdkUtilError};

#[derive(Debug)]
pub enum SdkLightError
{
	Util(SdkUtilError),
	JsonToStringFailed,
	JsonParseFailed(serde_json::Error),
	KeyDecryptFailed,
	GroupPermission,
	GroupRank,
}

/**
To convert the core error to sdk error
 */
impl From<Error> for SdkLightError
{
	fn from(e: Error) -> Self
	{
		SdkLightError::Util(SdkUtilError::Base(e))
	}
}

impl From<SdkUtilError> for SdkLightError
{
	fn from(value: SdkUtilError) -> Self
	{
		Self::Util(value)
	}
}

impl From<SdkLightError> for String
{
	fn from(e: SdkLightError) -> Self
	{
		err_to_msg(e)
	}
}

impl From<serde_json::Error> for SdkLightError
{
	fn from(value: serde_json::Error) -> Self
	{
		Self::JsonParseFailed(value)
	}
}

pub fn err_to_msg(error: SdkLightError) -> String
{
	match error {
		SdkLightError::Util(e) => sentc_crypto_utils::error::err_to_msg(e),
		SdkLightError::JsonToStringFailed => out_error("client_100", "Cannot create a string from this object"),
		SdkLightError::JsonParseFailed(err) => {
			format!("{{\"status\": {}, \"error_message\": \"{}\"}}", "client_101", err)
		},
		SdkLightError::KeyDecryptFailed => out_error("client_21", "Can't decrypt a key. Maybe the format is wrong"),

		//group error
		SdkLightError::GroupRank => {
			out_error(
				"client_200",
				"No valid group rank. Please choose between 1 (highest) and 4 (lowest)",
			)
		},
		SdkLightError::GroupPermission => out_error("client_201", "No permission to fulfill this action"),
	}
}
