use alloc::vec::Vec;

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, NewAead, Payload};
use aes_gcm::{Aes256Gcm, Key};
use rand_core::{CryptoRng, RngCore};

use crate::cryptomat::{CryptoAlg, Pk, SymKey};
use crate::error::Error;
use crate::{get_rand, try_from_bytes_single_value, SymmetricKey};

const AES_IV_LENGTH: usize = 12;

pub const AES_GCM_OUTPUT: &str = "AES-GCM-256";

pub(crate) type AesKey = [u8; 32];

pub struct Aes256GcmKey(AesKey);

try_from_bytes_single_value!(Aes256GcmKey);

impl CryptoAlg for Aes256GcmKey
{
	fn get_alg_str(&self) -> &'static str
	{
		AES_GCM_OUTPUT
	}
}

impl Into<SymmetricKey> for Aes256GcmKey
{
	fn into(self) -> SymmetricKey
	{
		SymmetricKey::Aes(self)
	}
}

impl SymKey for Aes256GcmKey
{
	fn generate() -> Result<impl SymKey, Error>
	{
		let key = generate_key_internally(&mut get_rand())?;

		Ok(Self(key))
	}

	fn encrypt_key_with_master_key<M: Pk>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		master_key.encrypt(&self.0)
	}

	fn encrypt_with_sym_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		master_key.encrypt(&self.0)
	}

	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>
	{
		encrypt_internally(&self.0, data, None, &mut get_rand())
	}

	fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
	{
		decrypt_internally(&self.0, ciphertext, None)
	}

	fn encrypt_with_aad(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>
	{
		encrypt_internally(&self.0, data, Some(aad), &mut get_rand())
	}

	fn decrypt_with_aad(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>
	{
		decrypt_internally(&self.0, ciphertext, Some(aad))
	}
}

pub fn raw_encrypt(key: &AesKey, data: &[u8]) -> Result<Vec<u8>, Error>
{
	encrypt_internally(key, data, None, &mut get_rand())
}

pub fn raw_decrypt(key: &AesKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
{
	decrypt_internally(key, ciphertext, None)
}

pub fn raw_generate() -> Result<AesKey, Error>
{
	generate_key_internally(&mut get_rand())
}

//__________________________________________________________________________________________________
//internally function

fn generate_key_internally<R: CryptoRng + RngCore>(rng: &mut R) -> Result<[u8; 32], Error>
{
	let mut key = [0u8; 32]; //aes 256

	rng.try_fill_bytes(&mut key)
		.map_err(|_| Error::KeyCreationFailed)?;

	Ok(key)
}

fn encrypt_internally<R: CryptoRng + RngCore>(key: &AesKey, data: &[u8], aad: Option<&[u8]>, rng: &mut R) -> Result<Vec<u8>, Error>
{
	let key = Key::from_slice(key);
	let aead = Aes256Gcm::new(key);

	//IV
	let mut nonce = [0u8; AES_IV_LENGTH];
	rng.try_fill_bytes(&mut nonce)
		.map_err(|_| Error::EncryptionFailedRng)?;
	let nonce = GenericArray::from_slice(&nonce);

	let plaintext = if let Some(a) = aad {
		Payload {
			aad: a,
			msg: data,
		}
	} else {
		Payload::from(data)
	};

	let ciphertext = aead
		.encrypt(nonce, plaintext)
		.map_err(|_| Error::EncryptionFailed)?;

	//put the IV in front of the ciphertext
	let mut output = Vec::with_capacity(AES_IV_LENGTH + ciphertext.len());
	output.extend_from_slice(nonce);
	output.extend_from_slice(&ciphertext);

	Ok(output)
}

fn decrypt_internally(key: &AesKey, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>, Error>
{
	let key = Key::from_slice(key);
	let aead = Aes256Gcm::new(key);

	let nonce = GenericArray::from_slice(&ciphertext[..AES_IV_LENGTH]);
	let encrypted = &ciphertext[AES_IV_LENGTH..];

	let encrypted = if let Some(a) = aad {
		Payload {
			aad: a,
			msg: encrypted,
		}
	} else {
		Payload::from(encrypted)
	};

	let decrypted = aead
		.decrypt(nonce, encrypted)
		.map_err(|_| Error::DecryptionFailed)?;

	Ok(decrypted)
}

#[cfg(test)]
mod test
{
	use core::str::from_utf8;

	use super::*;
	use crate::error::Error::DecryptionFailed;

	#[test]
	fn test_key_generated()
	{
		let _output = Aes256GcmKey::generate().unwrap();
	}

	#[test]
	fn test_plain_encrypt_decrypt()
	{
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
		let text = "Hello world üöäéèßê°";
		let payload = b"payload1234567891011121314151617";
		let payload2 = b"payload1234567891011121314151618";

		let output = Aes256GcmKey::generate().unwrap();

		let encrypted = output.encrypt_with_aad(text.as_bytes(), payload).unwrap();

		let decrypted = output.decrypt_with_aad(&encrypted, payload2);

		assert!(matches!(decrypted, Err(DecryptionFailed)));
	}
}
