use alloc::vec::Vec;

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, NewAead, Payload};
use aes_gcm::{Aes256Gcm, Key};
use rand_core::{CryptoRng, RngCore};

use crate::error::Error;
use crate::{get_rand, SymKey, SymKeyOutput};

const AES_IV_LENGTH: usize = 12;

pub const AES_GCM_OUTPUT: &str = "AES-GCM-256";

pub(crate) type AesKey = [u8; 32];

pub(crate) fn generate_key() -> Result<SymKeyOutput, Error>
{
	let key = generate_key_internally(&mut get_rand())?;

	Ok(SymKeyOutput {
		alg: AES_GCM_OUTPUT,
		key: SymKey::Aes(key),
	})
}

pub(crate) fn encrypt(key: &SymKey, data: &[u8]) -> Result<Vec<u8>, Error>
{
	let key = get_key_from_enum(key);

	encrypt_with_generated_key(key, data)
}

pub(crate) fn encrypt_with_generated_key(key: &AesKey, data: &[u8]) -> Result<Vec<u8>, Error>
{
	encrypt_internally(key, data, None, &mut get_rand())
}

pub(crate) fn decrypt(key: &SymKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
{
	let key = get_key_from_enum(key);

	decrypt_internally(key, ciphertext, None)
}

pub(crate) fn decrypt_with_generated_key(key: &AesKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
{
	decrypt_internally(key, ciphertext, None)
}

//___________________________________
//with aad

pub(crate) fn encrypt_with_generated_key_with_aad(key: &AesKey, data: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>
{
	encrypt_internally(key, data, Some(aad), &mut get_rand())
}

pub(crate) fn decrypt_with_generated_key_with_aad(key: &AesKey, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>
{
	decrypt_internally(key, ciphertext, Some(aad))
}

//__________________________________________________________________________________________________
//internally function

fn get_key_from_enum(key: &SymKey) -> &AesKey
{
	match key {
		SymKey::Aes(k) => k,
	}
}

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
	output.extend(nonce);
	output.extend(ciphertext);

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

	fn test_key_gen_output(output: &SymKeyOutput)
	{
		assert_eq!(output.alg, AES_GCM_OUTPUT);

		let key = match output.key {
			SymKey::Aes(k) => k,
		};

		assert_eq!(key.len(), 32);
	}

	#[test]
	fn test_key_generated()
	{
		let output = generate_key().unwrap();

		test_key_gen_output(&output);
	}

	#[test]
	fn test_plain_encrypt_decrypt()
	{
		let text = "Hello world üöäéèßê°";

		let output = generate_key().unwrap();

		//test with plain key
		let key = match output.key {
			SymKey::Aes(k) => k,
		};

		let encrypted = encrypt_with_generated_key(&key, text.as_bytes()).unwrap();

		let decrypted = decrypt_with_generated_key(&key, &encrypted).unwrap();

		assert_eq!(text.as_bytes(), decrypted);

		let decrypted_text = from_utf8(&decrypted).unwrap();

		assert_eq!(text, decrypted_text);
	}

	#[test]
	fn test_encrypt_decrypt()
	{
		let text = "Hello world üöäéèßê°";

		let output = generate_key().unwrap();

		let encrypted = encrypt(&output.key, text.as_bytes()).unwrap();

		let decrypted = decrypt(&output.key, &encrypted).unwrap();

		assert_eq!(text.as_bytes(), decrypted);

		let decrypted_text = from_utf8(&decrypted).unwrap();

		assert_eq!(text, decrypted_text);
	}

	#[test]
	fn test_not_decrypt_with_wrong_key()
	{
		let text = "Hello world üöäéèßê°";

		let output1 = generate_key().unwrap();
		let output2 = generate_key().unwrap();

		let encrypted = encrypt(&output1.key, text.as_bytes()).unwrap();

		let decrypt_result = decrypt(&output2.key, &encrypted);

		assert!(matches!(decrypt_result, Err(DecryptionFailed)));
	}

	#[test]
	fn test_encrypt_decrypt_with_payload()
	{
		let text = "Hello world üöäéèßê°";
		let payload = b"payload1234567891011121314151617";

		let output = generate_key().unwrap();

		let key = match output.key {
			SymKey::Aes(k) => k,
		};

		let encrypted = encrypt_with_generated_key_with_aad(&key, text.as_bytes(), payload).unwrap();

		let decrypted = decrypt_with_generated_key_with_aad(&key, &encrypted, payload).unwrap();

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

		let output = generate_key().unwrap();

		let key = match output.key {
			SymKey::Aes(k) => k,
		};

		let encrypted = encrypt_with_generated_key_with_aad(&key, text.as_bytes(), payload).unwrap();

		let decrypted = decrypt_with_generated_key_with_aad(&key, &encrypted, payload2);

		match decrypted {
			Err(DecryptionFailed) => {
				//
			},
			_ => panic!("Should be an error"),
		}
	}
}
