use alloc::vec::Vec;

use ope::{get_ope, OpeError, OpeKey};
use rand_core::{CryptoRng, RngCore};
use sentc_crypto_core::cryptomat::{CryptoAlg, SortableKey, SortableKeyGen, SymKey};
use sentc_crypto_core::Error;

use crate::core::sortable::SortKeys;
use crate::{as_ref_bytes_single_value, get_rand, try_from_bytes_owned_single_value, try_from_bytes_single_value};

pub const OPE_OUT: &str = "OPE-16";

pub struct OpeSortableKey(OpeKey);

try_from_bytes_single_value!(OpeSortableKey);
try_from_bytes_owned_single_value!(OpeSortableKey);
as_ref_bytes_single_value!(OpeSortableKey);

impl CryptoAlg for OpeSortableKey
{
	fn get_alg_str(&self) -> &'static str
	{
		OPE_OUT
	}
}

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

impl Into<SortKeys> for OpeSortableKey
{
	fn into(self) -> SortKeys
	{
		SortKeys::Ope(self)
	}
}

impl SortableKeyGen for OpeSortableKey
{
	type SortableKey = Self;

	fn generate() -> Result<Self::SortableKey, Error>
	{
		Ok(Self(generate_key_internally(&mut get_rand())?))
	}
}

//__________________________________________________________________________________________________

fn generate_key_internally<R: CryptoRng + RngCore>(rng: &mut R) -> Result<OpeKey, Error>
{
	let mut key = [0u8; 16];

	rng.try_fill_bytes(&mut key)
		.map_err(|_| Error::KeyCreationFailed)?;

	Ok(key)
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
