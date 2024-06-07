use alloc::vec::Vec;

use crate::alg::sym::aes_gcm::Aes256GcmKey;
use crate::cryptomat::{CryptoAlg, Pk, Sk, SymKey, SymKeyComposer, SymKeyGen};
use crate::Error;

pub(crate) mod aes_gcm;

macro_rules! deref_macro {
    ($self:expr, $method:ident $(, $args:expr)*) => {
        match $self {
           	Self::Aes(inner) => inner.$method($($args),*),
        }
    };
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
			_ => Err(Error::AlgNotFound),
		}
	}

	pub fn aes_key_from_bytes_owned(bytes: Vec<u8>) -> Result<Self, Error>
	{
		Ok(Self::Aes(bytes.try_into()?))
	}
}

impl SymKeyComposer for SymmetricKey
{
	type SymmetricKey = Self;

	fn decrypt_key_by_master_key<M: Sk>(master_key: &M, encrypted_key: &[u8], alg_str: &str) -> Result<Self::SymmetricKey, Error>
	{
		let decrypted_bytes = master_key.decrypt(encrypted_key)?;

		Self::from_bytes(&decrypted_bytes, alg_str)
	}

	fn decrypt_key_by_sym_key<M: SymKey>(master_key: &M, encrypted_key: &[u8], alg_str: &str) -> Result<Self::SymmetricKey, Error>
	{
		let decrypted_bytes = master_key.decrypt(encrypted_key)?;

		Self::from_bytes(&decrypted_bytes, alg_str)
	}
}

impl SymKeyGen for SymmetricKey
{
	#[cfg(feature = "aes")]
	type SymmetricKey = Aes256GcmKey;

	fn generate() -> Result<Self::SymmetricKey, Error>
	{
		#[cfg(feature = "aes")]
		Aes256GcmKey::generate()
	}
}

impl CryptoAlg for SymmetricKey
{
	fn get_alg_str(&self) -> &'static str
	{
		deref_macro!(self, get_alg_str)
	}
}

impl AsRef<[u8]> for SymmetricKey
{
	fn as_ref(&self) -> &[u8]
	{
		deref_macro!(self, as_ref)
	}
}

impl SymKey for SymmetricKey
{
	fn encrypt_key_with_master_key<M: Pk>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		deref_macro!(self, encrypt_key_with_master_key, master_key)
	}

	fn encrypt_with_sym_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		deref_macro!(self, encrypt_with_sym_key, master_key)
	}

	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>
	{
		deref_macro!(self, encrypt, data)
	}

	fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
	{
		deref_macro!(self, decrypt, ciphertext)
	}

	fn encrypt_with_aad(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>
	{
		deref_macro!(self, encrypt_with_aad, data, aad)
	}

	fn decrypt_with_aad(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>
	{
		deref_macro!(self, decrypt_with_aad, ciphertext, aad)
	}
}
