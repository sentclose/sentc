use ope::OpeError;

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

	DecodePrivateKeyFailed,

	HmacAuthFailedLength,

	OpeRangeError,
	OpeHdgInvalidInputs,
	OpeStringToLarge,
}

impl From<OpeError> for Error
{
	fn from(value: OpeError) -> Self
	{
		match value {
			OpeError::OpeRange => Self::OpeRangeError,
			OpeError::HdgInvalidInputs => Self::OpeHdgInvalidInputs,
		}
	}
}
