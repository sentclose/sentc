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
}