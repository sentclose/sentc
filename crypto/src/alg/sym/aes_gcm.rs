use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key};
use rand_core::{CryptoRng, OsRng, RngCore};

use crate::error::Error;
use crate::{SymKey, SymKeyOutput};

const AES_IV_LENGTH: usize = 12;

pub const AES_GCM_OUTPUT: &'static str = "AES-GCM-256";

pub type AesKey = [u8; 32];

pub(crate) fn generate_key() -> Result<SymKeyOutput, Error>
{
	let key = generate_key_internally(&mut OsRng)?;

	Ok(SymKeyOutput {
		alg: AES_GCM_OUTPUT,
		key: SymKey::Aes(key),
	})
}

pub(crate) fn generate_and_encrypt(data: &[u8]) -> Result<(SymKeyOutput, Vec<u8>), Error>
{
	let key_out = generate_key()?;

	match encrypt(&key_out.key, data) {
		Ok(res) => Ok((key_out, res)),
		Err(e) => Err(e),
	}
}

pub(crate) fn encrypt(key: &SymKey, data: &[u8]) -> Result<Vec<u8>, Error>
{
	let key = get_key_from_enum(key);

	encrypt_with_generated_key(key, data)
}

pub(crate) fn encrypt_with_generated_key(key: &AesKey, data: &[u8]) -> Result<Vec<u8>, Error>
{
	encrypt_internally(key, data, &mut OsRng)
}

pub(crate) fn decrypt(key: &SymKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
{
	let key = get_key_from_enum(key);

	decrypt_internally(key, ciphertext)
}

pub(crate) fn decrypt_with_generated_key(key: &AesKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
{
	decrypt_internally(key, ciphertext)
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

fn encrypt_internally<R: CryptoRng + RngCore>(key: &AesKey, data: &[u8], rng: &mut R) -> Result<Vec<u8>, Error>
{
	let key = Key::from_slice(key);
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
	let key = Key::from_slice(key);
	let aead = Aes256Gcm::new(key);

	let nonce = GenericArray::from_slice(&ciphertext[..AES_IV_LENGTH]);
	let encrypted = &ciphertext[AES_IV_LENGTH..];

	let decrypted = aead
		.decrypt(nonce, encrypted)
		.map_err(|_| Error::DecryptionFailed)?;

	Ok(decrypted)
}
