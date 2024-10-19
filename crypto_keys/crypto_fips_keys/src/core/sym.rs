use openssl::rand::rand_bytes;
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use sentc_crypto_core::cryptomat::{SymKey, SymKeyComposer, SymKeyGen};
use sentc_crypto_core::{as_ref_bytes_single_value, crypto_alg_str_impl, try_from_bytes_owned_single_value, try_from_bytes_single_value, Error};

pub const FIPS_OPENSSL_AES_GCM: &str = "FIPS_OPENSSL_AES_GCM-256";

const AES_MAC_LENGTH: usize = 16;
const AES_IV_LENGTH: usize = 12;

pub(crate) type AesKey = [u8; 32];

pub struct Aes256GcmKey(AesKey);

impl Aes256GcmKey
{
	pub fn from_raw_key(raw: AesKey) -> Self
	{
		Self(raw)
	}
}

try_from_bytes_single_value!(Aes256GcmKey);
try_from_bytes_owned_single_value!(Aes256GcmKey);
as_ref_bytes_single_value!(Aes256GcmKey);
crypto_alg_str_impl!(Aes256GcmKey, FIPS_OPENSSL_AES_GCM);

impl SymKey for Aes256GcmKey
{
	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>
	{
		encrypt_internally(&self.0, data, None)
	}

	fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
	{
		decrypt_internally(&self.0, ciphertext, None)
	}

	fn encrypt_with_aad(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>
	{
		encrypt_internally(&self.0, data, Some(aad))
	}

	fn decrypt_with_aad(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>
	{
		decrypt_internally(&self.0, ciphertext, Some(aad))
	}
}

impl SymKeyGen for Aes256GcmKey
{
	type SymmetricKey = Self;

	fn generate() -> Result<Self::SymmetricKey, Error>
	{
		let key = raw_generate()?;

		Ok(Aes256GcmKey(key))
	}
}

impl SymKeyComposer for Aes256GcmKey
{
	type SymmetricKey = Self;

	fn from_bytes_owned(bytes: Vec<u8>, alg_str: &str) -> Result<Self::SymmetricKey, Error>
	{
		if alg_str != FIPS_OPENSSL_AES_GCM {
			return Err(Error::AlgNotFound);
		}

		Self::try_from(bytes)
	}
}

//__________________________________________________________________________________________________

pub fn raw_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error>
{
	encrypt_internally(key, data, None)
}

pub fn raw_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error>
{
	decrypt_internally(key, ciphertext, None)
}

pub fn raw_generate() -> Result<AesKey, Error>
{
	let mut key = [0u8; 32]; //aes 256

	rand_bytes(&mut key).map_err(|_| Error::KeyCreationFailed)?;
	Ok(key)
}

fn encrypt_internally(key: &[u8], data: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>, Error>
{
	//IV
	let mut nonce = [0u8; AES_IV_LENGTH];
	rand_bytes(&mut nonce).map_err(|_| Error::EncryptionFailedRng)?;

	let mut tag = [0u8; AES_MAC_LENGTH];

	let ciphertext = encrypt_aead(
		Cipher::aes_256_gcm(),
		key,
		Some(&nonce),
		aad.unwrap_or_default(),
		data,
		&mut tag,
	)
	.map_err(|_| Error::EncryptionFailed)?;

	let mut output = Vec::with_capacity(AES_IV_LENGTH + AES_MAC_LENGTH + ciphertext.len());
	output.extend_from_slice(&nonce);
	output.extend_from_slice(&tag);
	output.extend_from_slice(&ciphertext);

	Ok(output)
}

fn decrypt_internally(key: &[u8], ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>, Error>
{
	let nonce = &ciphertext[..AES_IV_LENGTH];
	let tag = &ciphertext[AES_IV_LENGTH..AES_MAC_LENGTH];
	let encrypted = &ciphertext[(AES_IV_LENGTH + AES_MAC_LENGTH)..];

	decrypt_aead(
		Cipher::aes_256_gcm(),
		key,
		Some(nonce),
		aad.unwrap_or_default(),
		encrypted,
		tag,
	)
	.map_err(|_| Error::DecryptionFailed)
}

#[cfg(test)]
mod test
{
	use core::str::from_utf8;

	use sentc_crypto_core::Error::DecryptionFailed;

	use super::*;

	#[test]
	fn test_key_generated()
	{
		openssl::provider::Provider::load(None, "fips").unwrap();

		let _output = Aes256GcmKey::generate().unwrap();
	}

	#[test]
	fn test_plain_encrypt_decrypt()
	{
		openssl::provider::Provider::load(None, "fips").unwrap();

		let text = "Hello world üöäéèßê°";

		let output = Aes256GcmKey::generate().unwrap();

		let encrypted = output.encrypt(text.as_bytes()).unwrap();

		let decrypted = output.decrypt(&encrypted).unwrap();

		assert_eq!(text.as_bytes(), decrypted);

		let decrypted_text = from_utf8(&decrypted).unwrap();

		assert_eq!(text, decrypted_text);
	}

	#[test]
	fn test_not_decrypt_with_wrong_key()
	{
		openssl::provider::Provider::load(None, "fips").unwrap();

		let text = "Hello world üöäéèßê°";

		let output1 = Aes256GcmKey::generate().unwrap();
		let output2 = Aes256GcmKey::generate().unwrap();

		let encrypted = output1.encrypt(text.as_bytes()).unwrap();

		let decrypt_result = output2.decrypt(&encrypted);

		assert!(matches!(decrypt_result, Err(DecryptionFailed)));
	}

	#[test]
	fn test_encrypt_decrypt_with_payload()
	{
		openssl::provider::Provider::load(None, "fips").unwrap();

		let text = "Hello world üöäéèßê°";
		let payload = b"payload1234567891011121314151617";

		let output = Aes256GcmKey::generate().unwrap();

		let encrypted = output.encrypt_with_aad(text.as_bytes(), payload).unwrap();

		let decrypted = output.decrypt_with_aad(&encrypted, payload).unwrap();

		assert_eq!(text.as_bytes(), decrypted);

		let decrypted_text = from_utf8(&decrypted).unwrap();

		assert_eq!(text, decrypted_text);
	}

	#[test]
	fn test_encrypt_decrypt_with_wrong_payload()
	{
		openssl::provider::Provider::load(None, "fips").unwrap();

		let text = "Hello world üöäéèßê°";
		let payload = b"payload1234567891011121314151617";
		let payload2 = b"payload1234567891011121314151618";

		let output = Aes256GcmKey::generate().unwrap();

		let encrypted = output.encrypt_with_aad(text.as_bytes(), payload).unwrap();

		let decrypted = output.decrypt_with_aad(&encrypted, payload2);

		assert!(matches!(decrypted, Err(DecryptionFailed)));
	}
}
