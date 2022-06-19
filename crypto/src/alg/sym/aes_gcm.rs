use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::Aes256Gcm;
use rand_core::{CryptoRng, OsRng, RngCore};

use crate::error::Error;

const AES_IV_LENGTH: usize = 12;

pub type AesKey = [u8; 32];

pub(crate) fn generate_key() -> Result<[u8; 32], Error>
{
	generate_key_internally(&mut OsRng)
}

pub(crate) fn encrypt(data: &[u8]) -> Result<([u8; 32], Vec<u8>), Error>
{
	let key = generate_key()?;

	match encrypt_with_generated_key(&key, data) {
		Ok(res) => Ok((key, res)),
		Err(e) => Err(e),
	}
}

pub(crate) fn encrypt_with_generated_key(key: &AesKey, data: &[u8]) -> Result<Vec<u8>, Error>
{
	encrypt_internally(key, data, &mut OsRng)
}

pub(crate) fn decrypt(key: &AesKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
{
	decrypt_internally(key, ciphertext)
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

fn encrypt_internally<R: CryptoRng + RngCore>(key: &AesKey, data: &[u8], rng: &mut R) -> Result<Vec<u8>, Error>
{
	let key = GenericArray::from_slice(key);
	let aead = Aes256Gcm::new(key);

	//IV
	let mut nonce = [0u8; AES_IV_LENGTH];
	rng.try_fill_bytes(&mut nonce)
		.map_err(|_| Error::EncryptionFailedRng)?;
	let nonce = GenericArray::from_slice(&nonce);

	let ciphertext = aead
		.encrypt(nonce, data)
		.map_err(|_| Error::EncryptionFailed)?;

	//put the IV in front of the ciphertext
	let mut output = Vec::with_capacity(AES_IV_LENGTH + ciphertext.len());
	output.extend(nonce);
	output.extend(ciphertext);

	Ok(output)
}

fn decrypt_internally(key: &AesKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
{
	let key = GenericArray::from_slice(key);
	let aead = Aes256Gcm::new(key);

	let nonce = GenericArray::from_slice(&ciphertext[..AES_IV_LENGTH]);
	let encrypted = &ciphertext[AES_IV_LENGTH..];

	let decrypted = aead
		.decrypt(nonce, encrypted)
		.map_err(|_| Error::DecryptionFailed)?;

	Ok(decrypted)
}
