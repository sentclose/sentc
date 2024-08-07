use alloc::vec::Vec;

use sentc_crypto_core::cryptomat::{CryptoAlg, SortableKey, SortableKeyComposer, SortableKeyGen, SymKey};
use sentc_crypto_core::Error;

use crate::core::sortable::ope::OpeSortableKey;

pub(crate) mod ope;

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
	pub fn ope_key_from_bytes_owned(bytes: Vec<u8>) -> Result<Self, Error>
	{
		Ok(SortKeys::Ope(bytes.try_into()?))
	}
}

impl CryptoAlg for SortKeys
{
	fn get_alg_str(&self) -> &'static str
	{
		deref_macro!(self, get_alg_str)
	}
}

impl AsRef<[u8]> for SortKeys
{
	fn as_ref(&self) -> &[u8]
	{
		deref_macro!(self, as_ref)
	}
}

impl SortableKey for SortKeys
{
	fn encrypt_key_with_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		deref_macro!(self, encrypt_key_with_master_key, master_key)
	}

	fn encrypt_sortable(&self, data: u64) -> Result<u64, Error>
	{
		deref_macro!(self, encrypt_sortable, data)
	}
}

impl SortableKeyGen for SortKeys
{
	type SortableKey = Self;

	fn generate() -> Result<Self::SortableKey, Error>
	{
		#[cfg(feature = "ope_sort")]
		Ok(OpeSortableKey::generate()?.into())
	}
}

impl SortableKeyComposer for SortKeys
{
	type Key = Self;

	fn decrypt_by_master_key<M: SymKey>(master_key: &M, encrypted_key: &[u8], alg_str: &str) -> Result<Self::Key, Error>
	{
		let key = master_key.decrypt(encrypted_key)?;

		match alg_str {
			ope::OPE_OUT => Ok(SortKeys::Ope(key.try_into()?)),
			_ => Err(Error::AlgNotFound),
		}
	}
}
