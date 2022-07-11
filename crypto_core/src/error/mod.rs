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
	DecodeEncryptedDataFailed,

	ImportingPrivateKeyFailed,
	ImportingSignKeyFailed,
	ImportSymmetricKeyFailed,
	ImportPublicKeyFailed,
	ImportVerifyKeyFailed,

	ExportingPublicKeyFailed,
	ImportingKeyFromPemFailed,

	JsonToStringFailed,
	JsonParseFailed,

	SigFoundNotKey,
	VerifyFailed,
}
