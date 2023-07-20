use ope::{get_ope, OpeKey};
use rand_core::{CryptoRng, RngCore};

use crate::alg::sortable::{SortableKey, SortableOutput};
use crate::{get_rand, Error};

pub const OPE_OUT: &str = "OPE-16";

pub(crate) fn generate_key() -> Result<SortableOutput, Error>
{
	let key = generate_key_internally(&mut get_rand())?;

	Ok(SortableOutput {
		key: SortableKey::Ope(key),
		alg: OPE_OUT,
	})
}

pub(crate) fn encrypt_with_generated_key(key: &OpeKey, data: u64) -> Result<u64, Error>
{
	if data > 65532 {
		return Err(Error::OpeStringToLarge);
	}

	let ope = get_ope(key);
	Ok(ope.encrypt(data)?)
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

	fn test_key_gen_output(out: &SortableOutput) -> OpeKey
	{
		assert_eq!(out.alg, OPE_OUT);

		let key = match out.key {
			SortableKey::Ope(k) => k,
		};

		assert_eq!(key.len(), 16);

		key
	}

	#[test]
	fn test_gen_key()
	{
		let out = generate_key().unwrap();

		test_key_gen_output(&out);
	}

	#[test]
	fn test_encrypt()
	{
		let out = generate_key().unwrap();

		let key = test_key_gen_output(&out);

		let numbers = [262u64, 300, 1000, 65531];

		let mut out = [0u64; 4];

		for (i, number) in numbers.iter().enumerate() {
			out[i] = encrypt_with_generated_key(&key, *number).unwrap();
		}

		//check

		let mut past_item = 0;

		for item in out {
			assert!(past_item < item);

			past_item = item;
		}
	}
}
