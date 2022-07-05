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
	DecodeRandomValueFailed,
	DerivedKeyWrongFormat,

	LoginServerOutputWrong,
	KeyRotationServerOutputWrong,

	GettingGroupDataFailed,

	DecodePrivateKeyFailed,
	DecodePublicKeyFailed,

	ImportingPrivateKeyFailed,
	ImportingSignKeyFailed,
	ImportSymmetricKeyFailed,
	ImportPublicKeyFailed,

	ExportingPublicKeyFailed,
	ImportingKeyFromPemFailed,

	JsonToStringFailed,
	JsonParseFailed,
}
