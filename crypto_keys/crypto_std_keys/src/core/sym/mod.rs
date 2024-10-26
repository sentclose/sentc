use alloc::vec::Vec;

use sentc_crypto_core::cryptomat::{CryptoAlg, SymKey, SymKeyComposer, SymKeyGen};
use sentc_crypto_core::Error;

use crate::core::sym::aes_gcm::Aes256GcmKey;

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
	pub fn aes_key_from_bytes_owned(bytes: Vec<u8>) -> Result<Self, Error>
	{
		Ok(Self::Aes(bytes.try_into()?))
	}
}

impl SymKeyComposer for SymmetricKey
{
	type SymmetricKey = Self;

	fn from_bytes_owned(bytes: Vec<u8>, alg_str: &str) -> Result<Self::SymmetricKey, Error>
	{
		match alg_str {
			aes_gcm::AES_GCM_OUTPUT => Ok(Self::Aes(bytes.try_into()?)),
			_ => Err(Error::AlgNotFound),
		}
	}
}

impl SymKeyGen for SymmetricKey
{
	type SymmetricKey = Self;

	fn generate() -> Result<Self::SymmetricKey, Error>
	{
		#[cfg(feature = "aes")]
		Ok(Aes256GcmKey::generate()?.into())
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
