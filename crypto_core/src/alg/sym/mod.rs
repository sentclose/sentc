use alloc::vec::Vec;
use core::ops::Deref;

use crate::alg::sym::aes_gcm::Aes256GcmKey;
use crate::cryptomat::{CryptoAlg, Pk, Sk, SymKey};
use crate::Error;

pub(crate) mod aes_gcm;

pub fn generate_key() -> Result<impl SymKey, Error>
{
	#[cfg(feature = "aes")]
	Aes256GcmKey::generate()
}

pub enum SymmetricKey
{
	Aes(Aes256GcmKey),
}

impl SymmetricKey
{
	pub fn from_bytes(bytes: &[u8], alg_str: &str) -> Result<Self, Error>
	{
		match alg_str {
			aes_gcm::AES_GCM_OUTPUT => Ok(Self::Aes(bytes.try_into()?)),
			_ => return Err(Error::AlgNotFound),
		}
	}

	pub fn decrypt_key_by_master_key<M: Sk>(master_key: &M, encrypted_key: &[u8], alg_str: &str) -> Result<Self, Error>
	{
		let decrypted_bytes = master_key.decrypt(encrypted_key)?;

		Self::from_bytes(&decrypted_bytes, alg_str)
	}

	pub fn decrypt_key_by_sym_key<M: SymKey>(master_key: &M, encrypted_key: &[u8], alg_str: &str) -> Result<Self, Error>
	{
		let decrypted_bytes = master_key.decrypt(encrypted_key)?;

		Self::from_bytes(&decrypted_bytes, alg_str)
	}

	fn deref(&self) -> &impl SymKey
	{
		match self {
			SymmetricKey::Aes(k) => k,
		}
	}
}

impl CryptoAlg for SymmetricKey
{
	fn get_alg_str(&self) -> &'static str
	{
		self.deref().get_alg_str()
	}
}

impl SymKey for SymmetricKey
{
	fn generate() -> Result<impl SymKey, Error>
	{
		generate_key()
	}

	fn encrypt_key_with_master_key<M: Pk>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		self.deref().encrypt_key_with_master_key(master_key)
	}

	fn encrypt_with_sym_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		self.deref().encrypt_key_with_master_key(master_key)
	}

	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>
	{
		self.deref().encrypt(data)
	}

	fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
	{
		self.deref().decrypt(ciphertext)
	}

	fn encrypt_with_aad(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>
	{
		self.deref().encrypt_with_aad(data, aad)
	}

	fn decrypt_with_aad(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>
	{
		self.deref().decrypt_with_aad(ciphertext, aad)
	}
}
