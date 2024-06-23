use sentc_crypto_core::cryptomat::{SortableKey, SortableKeyComposer, SortableKeyGen, SymKey};
use sentc_crypto_core::{crypto_alg_str_impl, Error};

pub const FIPS_OPENSSL_SORTABLE: &str = "fips_openssl_sortable_none";

pub struct NonSortableKeys;

crypto_alg_str_impl!(NonSortableKeys, FIPS_OPENSSL_SORTABLE);

impl SortableKey for NonSortableKeys
{
	fn encrypt_key_with_master_key<M: SymKey>(&self, _master_key: &M) -> Result<Vec<u8>, Error>
	{
		Ok(Default::default())
	}

	fn encrypt_sortable(&self, _data: u64) -> Result<u64, Error>
	{
		Err(Error::AlgNotFound)
	}
}

impl SortableKeyGen for NonSortableKeys
{
	type SortableKey = Self;

	fn generate() -> Result<Self::SortableKey, Error>
	{
		Ok(Self)
	}
}

impl SortableKeyComposer for NonSortableKeys
{
	type Key = Self;

	fn decrypt_by_master_key<M: SymKey>(_master_key: &M, _encrypted_key: &[u8], alg_str: &str) -> Result<Self::Key, Error>
	{
		if alg_str != FIPS_OPENSSL_SORTABLE {
			return Err(Error::AlgNotFound);
		}

		Ok(Self)
	}
}

#[cfg(test)]
mod test
{
	use super::*;

	#[test]
	fn test_gen_key()
	{
		let _ = NonSortableKeys::generate().unwrap();
	}

	#[test]
	fn test_encrypt()
	{
		let key = NonSortableKeys::generate().unwrap();

		let numbers = [262u64, 300, 1000, 65531];

		for number in numbers {
			let res = key.encrypt_sortable(number);

			//not implemented for fips
			assert!(matches!(res, Err(Error::AlgNotFound)));
		}
	}
}
