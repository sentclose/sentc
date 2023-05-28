use alloc::vec::Vec;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::alg::sym::aes_gcm::AesKey;
use crate::{alg, Error, HmacKey, HmacKeyOutput, SymKey};

pub const HMAC_SHA256_OUTPUT: &str = "HMAC-SHA256";

pub(crate) type HmacSha256Key = AesKey;

type HmacSha256 = Hmac<Sha256>;

pub(crate) fn generate_key() -> Result<HmacKeyOutput, Error>
{
	//use the aes key gen for an hmac key because the recommended key size is also 32

	let key = alg::sym::aes_gcm::generate_key()?;

	let key = match key.key {
		SymKey::Aes(k) => k,
	};

	Ok(HmacKeyOutput {
		alg: HMAC_SHA256_OUTPUT,
		key: HmacKey::HmacSha256(key),
	})
}

pub(crate) fn auth_with_generated_key(key: &HmacSha256Key, data: &[u8]) -> Result<Vec<u8>, Error>
{
	let mut mac = HmacSha256::new_from_slice(key).map_err(|_| Error::HmacAuthFailedLength)?;

	mac.update(data);

	let result = mac.finalize();
	let result = result.into_bytes();

	Ok(result.to_vec())
}

pub(crate) fn verify_with_generated_key(key: &HmacSha256Key, data: &[u8], check_mac: &[u8]) -> Result<bool, Error>
{
	let mut mac = HmacSha256::new_from_slice(key).map_err(|_| Error::HmacAuthFailedLength)?;

	mac.update(data);

	if mac.verify_slice(check_mac).is_ok() {
		Ok(true)
	} else {
		Ok(false)
	}
}

#[cfg(test)]
mod test
{
	use super::*;

	fn test_key_gen_output(out: &HmacKeyOutput)
	{
		assert_eq!(out.alg, HMAC_SHA256_OUTPUT);

		let key = match out.key {
			HmacKey::HmacSha256(k) => k,
		};

		assert_eq!(key.len(), 32);
	}

	#[test]
	fn test_create_hmac_key()
	{
		let out = generate_key().unwrap();

		test_key_gen_output(&out);
	}

	#[test]
	fn test_plain_auth_msg()
	{
		let msg = "Hello world üöäéèßê°";

		let out = generate_key().unwrap();

		test_key_gen_output(&out);

		let key = match out.key {
			HmacKey::HmacSha256(k) => k,
		};

		let mac = auth_with_generated_key(&key, msg.as_bytes()).unwrap();

		let verify = verify_with_generated_key(&key, msg.as_bytes(), &mac).unwrap();

		assert!(verify);
	}

	#[test]
	fn test_not_verify_with_wrong_key()
	{
		let msg = "Hello world üöäéèßê°";

		let out = generate_key().unwrap();
		let out2 = generate_key().unwrap();

		let (key, key2) = match (out.key, out2.key) {
			(HmacKey::HmacSha256(k), HmacKey::HmacSha256(k2)) => (k, k2),
		};

		let mac = auth_with_generated_key(&key, msg.as_bytes()).unwrap();

		let verify = verify_with_generated_key(&key2, msg.as_bytes(), &mac).unwrap();

		assert!(!verify);
	}

	#[test]
	fn test_not_producing_the_same_output_with_different_keys()
	{
		let msg = "Hello world üöäéèßê°";

		let out = generate_key().unwrap();
		let out2 = generate_key().unwrap();

		let (key, key2) = match (out.key, out2.key) {
			(HmacKey::HmacSha256(k), HmacKey::HmacSha256(k2)) => (k, k2),
		};

		let mac1 = auth_with_generated_key(&key, msg.as_bytes()).unwrap();

		let mac2 = auth_with_generated_key(&key2, msg.as_bytes()).unwrap();

		assert_ne!(mac1, mac2);
	}

	#[test]
	fn test_producing_the_same_output_with_same_keys()
	{
		let msg = "Hello world üöäéèßê°";

		let out = generate_key().unwrap();

		let key = match out.key {
			HmacKey::HmacSha256(k) => k,
		};

		let mac1 = auth_with_generated_key(&key, msg.as_bytes()).unwrap();

		let mac2 = auth_with_generated_key(&key, msg.as_bytes()).unwrap();

		assert_eq!(mac1, mac2);
	}
}
