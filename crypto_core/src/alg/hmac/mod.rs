use alloc::vec::Vec;

use crate::alg::hmac::hmac_sha256::HmacSha256Key;
use crate::cryptomat::{CryptoAlg, SearchableKey, SymKey};
use crate::Error;

pub(crate) mod hmac_sha256;

pub fn generate_key() -> Result<impl SearchableKey, Error>
{
	#[cfg(feature = "hmac_sha256")]
	HmacSha256Key::generate()
}

macro_rules! deref_macro {
    ($self:expr, $method:ident $(, $args:expr)*) => {
        match $self {
           	Self::HmacSha256(inner) => inner.$method($($args),*),
        }
    };
}

pub enum HmacKey
{
	HmacSha256(HmacSha256Key),
}

impl HmacKey
{
	pub fn from_bytes(bytes: &[u8], alg_str: &str) -> Result<Self, Error>
	{
		match alg_str {
			hmac_sha256::HMAC_SHA256_OUTPUT => Ok(HmacKey::HmacSha256(bytes.try_into()?)),
			_ => Err(Error::AlgNotFound),
		}
	}

	pub fn decrypt_key_with_master_key<M: SymKey>(master_key: &M, encrypted_key: &[u8], alg_str: &str) -> Result<Self, Error>
	{
		let key = master_key.decrypt(encrypted_key)?;

		Self::from_bytes(&key, alg_str)
	}

	pub fn hmac_sha256_from_bytes_owned(bytes: Vec<u8>) -> Result<Self, Error>
	{
		Ok(HmacKey::HmacSha256(bytes.try_into()?))
	}
}

impl CryptoAlg for HmacKey
{
	fn get_alg_str(&self) -> &'static str
	{
		deref_macro!(self, get_alg_str)
	}
}

impl AsRef<[u8]> for HmacKey
{
	fn as_ref(&self) -> &[u8]
	{
		deref_macro!(self, as_ref)
	}
}

impl SearchableKey for HmacKey
{
	fn generate() -> Result<impl SearchableKey, Error>
	{
		generate_key()
	}

	fn encrypt_key_with_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		deref_macro!(self, encrypt_key_with_master_key, master_key)
	}

	fn encrypt_searchable(&self, data: &[u8]) -> Result<Vec<u8>, Error>
	{
		deref_macro!(self, encrypt_searchable, data)
	}

	fn verify_encrypted_searchable(&self, data: &[u8], check: &[u8]) -> Result<bool, Error>
	{
		deref_macro!(self, verify_encrypted_searchable, data, check)
	}
}
