use alloc::format;
use alloc::string::{String, ToString};

use sentc_crypto_core::Error;

#[derive(Debug)]
pub enum SdkError
{
	Base(Error),
	JsonToStringFailed,
	JsonParseFailed(serde_json::Error),
	JsonParse,

	DecodeSaltFailed,
	DecodeRandomValueFailed,
	DecodeHashedAuthKey,
	DecodeAuthKey,
	DecodeEncryptedDataFailed,
	DecodePublicKeyFailed,
	DecodeSymKeyFailed,

	ImportingSignKeyFailed,
	ImportingPrivateKeyFailed,
	ImportSymmetricKeyFailed,
	ImportPublicKeyFailed,
	ImportVerifyKeyFailed,
	ImportingKeyFromPemFailed,

	ExportingPublicKeyFailed,

	DerivedKeyWrongFormat,

	SigFoundNotKey,
	VerifyFailed,
	KeyDecryptFailed,

	LoginServerOutputWrong,
	KeyRotationServerOutputWrong,

	AlgNotFound,

	GroupRank,
	GroupUserKickRank,
	GroupPermission,

	ServerErr(u32, String),
}

/**
To convert the core error to sdk error
*/
impl From<Error> for SdkError
{
	fn from(e: Error) -> Self
	{
		SdkError::Base(e)
	}
}

impl From<SdkError> for String
{
	fn from(e: SdkError) -> Self
	{
		err_to_msg(e)
	}
}

pub fn err_to_msg(error: SdkError) -> String
{
	match error {
		SdkError::Base(base_error) => {
			match base_error {
				Error::AlgNotFound => out_error("client_1", "The algorithms for this action was not found."),

				Error::DecodePrivateKeyFailed => out_error("client_3", "The private key has a wrong format."),
				Error::DecryptionFailedCiphertextShort => out_error("client_10", "cipher is too short."),
				Error::KeyCreationFailed => {
					out_error(
						"client_11",
						"Can't create a key. This normally happened when the used system has no mechanisms to create random numbers",
					)
				},
				Error::EncryptionFailed => out_error("client_12", "Can't encrypt symmetrically."),
				Error::EncryptionFailedRng => {
					out_error(
						"client_13",
						"Can't create random numbers. This normally happened when the used system has no mechanisms to create random numbers",
					)
				},
				Error::DecryptionFailed => {
					out_error(
						"client_14",
						"Can't decrypt the cipher. This happened when using a wrong key to decrypt",
					)
				},

				Error::PwHashFailed => {
					out_error(
						"client_20",
						"Can't hash the password. This happened when using a wrong algorithm or the output is wrong.",
					)
				},
				Error::PwSplitFailedLeft => out_error("client_21", "Can't hash the password. The input is too short"),
				Error::PwSplitFailedRight => out_error("client_21", "Can't hash the password. The input is too short"),
				Error::HashAuthKeyFailed => out_error("client_22", "Can't hash the password"),

				Error::KeyDecryptFailed => {
					out_error(
						"client_30",
						"Can't decrypt the key. Maybe a wrong master key was used.",
					)
				},
				Error::SignKeyCreateFailed => out_error("client_40", "Can't create a sign key from given bytes"),
				Error::InitSignFailed => out_error("client_41", "Can't create a sign"),
				Error::DataToSignTooShort => out_error("client_42", "This data doesn't contains a sign"),
				Error::InitVerifyFailed => out_error("client_43", "Can't verify the data"),
			}
		},
		SdkError::AlgNotFound => out_error("client_1", "The algorithms for this action was not found."),
		SdkError::JsonToStringFailed => out_error("client_100", "Cannot create a string from this object"),
		SdkError::JsonParse => out_error("client_102", "Cannot create an object from the input string"),
		SdkError::JsonParseFailed(err) => {
			format!("{{\"status\": {}, \"error_message\": \"{}\"}}", "client_101", err)
		},
		//key decode error (from base64 string to the enum
		SdkError::DerivedKeyWrongFormat => out_error("client_2", "The encrypted key has a wrong format."),
		//salt decode error (from base64 string to bytes)
		SdkError::DecodeSaltFailed => out_error("client_4", "The salt has a wrong format"),

		SdkError::DecodeRandomValueFailed => out_error("client_5", "Can't decode the client random value from registration"),
		SdkError::DecodeHashedAuthKey => out_error("client_6", "Can't decode the hashed authentication key"),
		SdkError::DecodeAuthKey => out_error("client_7", "Can't decode the authentication key"),
		SdkError::DecodePublicKeyFailed => out_error("client_8", "Can't decode the public key. Maybe the format is wrong"),
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

		//import error
		SdkError::ImportingSignKeyFailed => out_error("client_110", "Can't import the sign key"),
		SdkError::ImportingPrivateKeyFailed => out_error("client_111", "Can't import the private key"),
		SdkError::ImportSymmetricKeyFailed => out_error("client_112", "Can't import symmetric key"),
		SdkError::ImportPublicKeyFailed => out_error("client_113", "Can't import public key"),
		SdkError::ImportVerifyKeyFailed => out_error("client_114", "Can't import verify key"),
		SdkError::ImportingKeyFromPemFailed => out_error("client_115", "Can't import this key. It has a wrong format"),

		//exporting error
		SdkError::ExportingPublicKeyFailed => {
			out_error(
				"client_120",
				"Can't export the public key. It doesn't fit in a pem format",
			)
		},

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
		SdkError::ServerErr(code, msg) => {
			out_error(
				(String::from("server_") + code.to_string().as_str()).as_str(),
				msg.as_str(),
			)
		},
	}
}

pub(crate) fn out_error(code: &str, message: &str) -> String
{
	//create the error in json to communicate with the other implementations, so they can use their own error handling

	format!("{{\"status\": \"{}\", \"error_message\": \"{}\"}}", code, message)
}
