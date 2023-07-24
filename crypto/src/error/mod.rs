use alloc::format;
use alloc::string::{String, ToString};

use sentc_crypto_core::Error;
use sentc_crypto_utils::error::{out_error, SdkUtilError};

#[derive(Debug)]
pub enum SdkError
{
	Util(SdkUtilError),

	JsonToStringFailed,
	JsonParseFailed(serde_json::Error),
	JsonParse,

	DecodeHashedAuthKey,
	DecodeEncryptedDataFailed,
	DecodeSymKeyFailed,

	SigFoundNotKey,
	VerifyFailed,
	KeyDecryptFailed,

	LoginServerOutputWrong,
	KeyRotationServerOutputWrong,
	KeyRotationEncryptError(String),

	AlgNotFound,

	GroupRank,
	GroupUserKickRank,
	GroupPermission,

	SearchableEncryptionDataTooLong,

	SearchableEncryptionDataNotFound,
}

/**
To convert the core error to sdk error
*/
impl From<Error> for SdkError
{
	fn from(e: Error) -> Self
	{
		SdkError::Util(SdkUtilError::Base(e))
	}
}

impl From<SdkUtilError> for SdkError
{
	fn from(value: SdkUtilError) -> Self
	{
		Self::Util(value)
	}
}

impl From<SdkError> for String
{
	fn from(e: SdkError) -> Self
	{
		err_to_msg(e)
	}
}

impl From<serde_json::Error> for SdkError
{
	fn from(value: serde_json::Error) -> Self
	{
		Self::JsonParseFailed(value)
	}
}

pub fn err_to_msg(error: SdkError) -> String
{
	match error {
		SdkError::Util(e) => sentc_crypto_utils::error::err_to_msg(e),

		SdkError::AlgNotFound => out_error("client_1", "The algorithms for this action was not found."),
		SdkError::JsonToStringFailed => out_error("client_100", "Cannot create a string from this object"),
		SdkError::JsonParse => out_error("client_102", "Cannot create an object from the input string"),
		SdkError::JsonParseFailed(err) => {
			format!("{{\"status\": {}, \"error_message\": \"{}\"}}", "client_101", err)
		},

		SdkError::DecodeHashedAuthKey => out_error("client_6", "Can't decode the hashed authentication key"),
		SdkError::DecodeSymKeyFailed => {
			out_error(
				"client_9",
				"Can't decode the symmetric key. Maybe the format is wrong",
			)
		},
		SdkError::DecodeEncryptedDataFailed => out_error("client_10", "Can't decode the encrypted data"),

		SdkError::SigFoundNotKey => {
			out_error(
				"client_20",
				"The verification key can't verify this signature. The signature was signed by another key pair.",
			)
		},
		SdkError::KeyDecryptFailed => out_error("client_21", "Can't decrypt a key. Maybe the format is wrong"),
		SdkError::VerifyFailed => out_error("client_22", "The verification failed. A wrong verify key was used"),

		//Login error
		SdkError::LoginServerOutputWrong => {
			out_error(
				"client_130",
				"Error in login. Missing user keys. Maybe the Key creation was wrong",
			)
		},

		//group error
		SdkError::GroupRank => {
			out_error(
				"client_200",
				"No valid group rank. Please choose between 1 (highest) and 4 (lowest)",
			)
		},
		SdkError::GroupPermission => out_error("client_201", "No permission to fulfill this action"),
		SdkError::GroupUserKickRank => out_error("client_202", "The user to delete has a higher rank"),
		SdkError::KeyRotationServerOutputWrong => out_error("client_203", "The key rotation data is wrong and can't be decoded."),

		SdkError::KeyRotationEncryptError(e) => {
			out_error(
				"client_204",
				&("Key rotation failed for this account with this error message: ".to_string() + &e),
			)
		},

		SdkError::SearchableEncryptionDataTooLong => {
			out_error(
				"client_300",
				"The input data is too long to hash. The maximal length is 200 characters.",
			)
		},

		SdkError::SearchableEncryptionDataNotFound => out_error("client_301", "No data found to hash. Empty Strings are not allowed."),
	}
}
