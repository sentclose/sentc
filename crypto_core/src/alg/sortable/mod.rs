use alloc::vec::Vec;

use crate::alg::sortable::ope::OpeSortableKey;
use crate::cryptomat::{CryptoAlg, SortableKey, SymKey};
use crate::Error;

pub(crate) mod ope;

pub fn generate_key() -> Result<impl SortableKey, Error>
{
	#[cfg(feature = "ope_sort")]
	OpeSortableKey::generate()
}

macro_rules! deref_macro {
    ($self:expr, $method:ident $(, $args:expr)*) => {
        match $self {
           	Self::Ope(inner) => inner.$method($($args),*),
        }
    };
}

pub enum SortKeys
{
	Ope(OpeSortableKey),
}

impl SortKeys
{
	pub fn from_bytes(bytes: &[u8], alg_str: &str) -> Result<Self, Error>
	{
		match alg_str {
			ope::OPE_OUT => Ok(SortKeys::Ope(bytes.try_into()?)),
			_ => Err(Error::AlgNotFound),
		}
	}

	pub fn decrypt_key_with_master_key<M: SymKey>(master_key: &M, encrypted_key: &[u8], alg_str: &str) -> Result<Self, Error>
	{
		let key = master_key.decrypt(encrypted_key)?;

		Self::from_bytes(&key, alg_str)
	}
}

impl CryptoAlg for SortKeys
{
	fn get_alg_str(&self) -> &'static str
	{
		deref_macro!(self, get_alg_str)
	}
}

impl SortableKey for SortKeys
{
	fn generate() -> Result<impl SortableKey, Error>
	{
		generate_key()
	}

	fn encrypt_key_with_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		deref_macro!(self, encrypt_key_with_master_key, master_key)
	}

	fn encrypt_sortable(&self, data: u64) -> Result<u64, Error>
	{
		deref_macro!(self, encrypt_sortable, data)
	}
}
