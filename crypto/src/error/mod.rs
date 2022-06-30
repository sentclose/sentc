#[derive(Debug)]
pub enum Error
{
	DecryptionFailedCiphertextShort,

	KeyCreationFailed,

	EncryptionFailed,
	EncryptionFailedRng,
	DecryptionFailed,

	PwHashFailed,
	PwSplitFailedLeft,
	PwSplitFailedRight,
	HashAuthKeyFailed,

	KeyDecryptFailed,

	SignKeyCreateFailed,
	InitSignFailed,
	DataToSignTooShort,
	InitVerifyFailed,

	AlgNotFound,
	DecodeSaltFailed,
	DerivedKeyWrongFormat,

	LoginServerOutputWrong,

	DecodePrivateKeyFailed,

	ImportingPrivateKeyFailed,
	ImportingSignKeyFailed,

	ExportingPublicKeyFailed,
	ImportingPublicKeyFailed,
}

pub fn err_to_msg(error: Error) -> String
{
	match error {
		Error::AlgNotFound => out_error(1, "The algorithms for this action was not found."),

		//key decode error (from base64 string to the enum
		Error::DerivedKeyWrongFormat => out_error(2, "The encrypted key has a wrong format."),
		Error::DecodePrivateKeyFailed => out_error(3, "The private key has a wrong format."),

		//salt decode error (from base64 string to bytes)
		Error::DecodeSaltFailed => out_error(4, "The salt has a wrong format"),
		_ => out_error(0, "other"),
	}
}

pub(crate) fn out_error(code: u32, message: &'static str) -> String
{
	//create the error in json to communicate with the other implementations, so they can use their own error handling

	format!("{{\"status\": {}, \"error_message\": \"{}\"}}", code, message)
}
