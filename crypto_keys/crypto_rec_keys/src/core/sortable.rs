use ope::{get_ope, OpeError, OpeKey};
use openssl::rand::rand_bytes;
use sentc_crypto_core::cryptomat::{SortableKey, SortableKeyComposer, SortableKeyGen, SymKey};
use sentc_crypto_core::{as_ref_bytes_single_value, crypto_alg_str_impl, try_from_bytes_owned_single_value, try_from_bytes_single_value, Error};

pub const OPE_REC_OUT: &str = "OPE_REC-16";

pub struct OpeSortableKey(OpeKey);

try_from_bytes_single_value!(OpeSortableKey);
try_from_bytes_owned_single_value!(OpeSortableKey);
as_ref_bytes_single_value!(OpeSortableKey);

crypto_alg_str_impl!(OpeSortableKey, OPE_REC_OUT);

impl SortableKey for OpeSortableKey
{
	fn encrypt_key_with_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		master_key.encrypt(&self.0)
	}

	fn encrypt_sortable(&self, data: u64) -> Result<u64, Error>
	{
		if data > 65532 {
			return Err(Error::OpeStringToLarge);
		}

		let ope = get_ope(&self.0);

		let out = ope.encrypt(data);

		match out {
			Ok(o) => Ok(o),
			Err(err) => {
				match err {
					OpeError::HdgInvalidInputs => Err(Error::OpeHdgInvalidInputs),
					OpeError::OpeRange => Err(Error::OpeRangeError),
				}
			},
		}
	}
}

impl SortableKeyGen for OpeSortableKey
{
	type SortableKey = Self;

	fn generate() -> Result<Self::SortableKey, Error>
	{
		let mut key = [0u8; 16];
		rand_bytes(&mut key).map_err(|_| Error::KeyCreationFailed)?;

		Ok(Self(key))
	}
}

impl SortableKeyComposer for OpeSortableKey
{
	type Key = Self;

	fn decrypt_by_master_key<M: SymKey>(master_key: &M, encrypted_key: &[u8], alg_str: &str) -> Result<Self::Key, Error>
	{
		if alg_str != OPE_REC_OUT {
			return Err(Error::AlgNotFound);
		}

		let key = master_key.decrypt(encrypted_key)?;

		key.try_into()
	}
}

#[cfg(test)]
mod test
{
	use super::*;

	#[test]
	fn test_gen_key()
	{
		let _ = OpeSortableKey::generate().unwrap();
	}

	#[test]
	fn test_encrypt()
	{
		let key = OpeSortableKey::generate().unwrap();

		let numbers = [262u64, 300, 1000, 65531];

		let mut out = [0u64; 4];

		for (i, number) in numbers.iter().enumerate() {
			out[i] = key.encrypt_sortable(*number).unwrap();
		}

		//check

		let mut past_item = 0;

		for item in out {
			assert!(past_item < item);

			past_item = item;
		}
	}
}
