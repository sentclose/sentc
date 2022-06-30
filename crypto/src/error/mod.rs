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

	DecodePrivateKeyFailed,
}

pub(crate) fn out_error(code: u32, message: &'static str) -> String
{
	//create the error in json to communicate with the other implementations, so they can use their own error handling

	format!("{{\"status\": {}, \"error_message\": \"{}\"}}", code, message)
}
