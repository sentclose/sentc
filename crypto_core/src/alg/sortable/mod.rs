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

	fn deref(&self) -> &impl SortableKey
	{
		match self {
			SortKeys::Ope(k) => k,
		}
	}
}

impl CryptoAlg for SortKeys
{
	fn get_alg_str(&self) -> &'static str
	{
		self.deref().get_alg_str()
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
		self.deref().encrypt_key_with_master_key(master_key)
	}

	fn encrypt_sortable(&self, data: u64) -> Result<u64, Error>
	{
		self.deref().encrypt_sortable(data)
	}
}
