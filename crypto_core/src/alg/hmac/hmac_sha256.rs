use alloc::vec::Vec;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::alg::hmac::HmacKey;
use crate::alg::sym::aes_gcm::AesKey;
use crate::cryptomat::{CryptoAlg, SearchableKey, SearchableKeyGen, SymKey};
use crate::{alg, as_ref_bytes_single_value, crypto_alg_str_impl, try_from_bytes_owned_single_value, try_from_bytes_single_value, Error};

pub const HMAC_SHA256_OUTPUT: &str = "HMAC-SHA256";

type HmacSha256 = Hmac<Sha256>;

pub struct HmacSha256Key(AesKey);

try_from_bytes_single_value!(HmacSha256Key);
try_from_bytes_owned_single_value!(HmacSha256Key);
as_ref_bytes_single_value!(HmacSha256Key);
crypto_alg_str_impl!(HmacSha256Key, HMAC_SHA256_OUTPUT);

impl Into<HmacKey> for HmacSha256Key
{
	fn into(self) -> HmacKey
	{
		HmacKey::HmacSha256(self)
	}
}

impl SearchableKey for HmacSha256Key
{
	fn encrypt_key_with_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		master_key.encrypt(&self.0)
	}

	fn encrypt_searchable(&self, data: &[u8]) -> Result<Vec<u8>, Error>
	{
		let mut mac = HmacSha256::new_from_slice(&self.0).map_err(|_| Error::HmacAuthFailedLength)?;

		mac.update(data);

		let result = mac.finalize();
		let result = result.into_bytes();

		Ok(result.to_vec())
	}

	fn verify_encrypted_searchable(&self, data: &[u8], check: &[u8]) -> Result<bool, Error>
	{
		let mut mac = HmacSha256::new_from_slice(&self.0).map_err(|_| Error::HmacAuthFailedLength)?;

		mac.update(data);

		Ok(mac.verify_slice(check).is_ok())
	}
}

impl SearchableKeyGen for HmacSha256Key
{
	type SearchableKey = Self;

	fn generate() -> Result<Self::SearchableKey, Error>
	{
		Ok(Self(alg::sym::aes_gcm::raw_generate()?))
	}
}

#[cfg(test)]
mod test
{
	use super::*;

	#[test]
	fn test_create_hmac_key()
	{
		let _ = HmacSha256Key::generate().unwrap();
	}

	#[test]
	fn test_plain_auth_msg()
	{
		let msg = "Hello world üöäéèßê°";

		let out = HmacSha256Key::generate().unwrap();

		let mac = out.encrypt_searchable(msg.as_bytes()).unwrap();

		let verify = out
			.verify_encrypted_searchable(msg.as_bytes(), &mac)
			.unwrap();

		assert!(verify);
	}

	#[test]
	fn test_not_verify_with_wrong_key()
	{
		let msg = "Hello world üöäéèßê°";

		let out = HmacSha256Key::generate().unwrap();
		let out2 = HmacSha256Key::generate().unwrap();

		let mac = out.encrypt_searchable(msg.as_bytes()).unwrap();

		let verify = out2
			.verify_encrypted_searchable(msg.as_bytes(), &mac)
			.unwrap();

		assert!(!verify);
	}

	#[test]
	fn test_not_producing_the_same_output_with_different_keys()
	{
		let msg = "Hello world üöäéèßê°";

		let out = HmacSha256Key::generate().unwrap();
		let out2 = HmacSha256Key::generate().unwrap();

		let mac1 = out.encrypt_searchable(msg.as_bytes()).unwrap();

		let mac2 = out2.encrypt_searchable(msg.as_bytes()).unwrap();

		assert_ne!(mac1, mac2);
	}

	#[test]
	fn test_producing_the_same_output_with_same_keys()
	{
		let msg = "Hello world üöäéèßê°";

		let out = HmacSha256Key::generate().unwrap();

		let mac1 = out.encrypt_searchable(msg.as_bytes()).unwrap();

		let mac2 = out.encrypt_searchable(msg.as_bytes()).unwrap();

		assert_eq!(mac1, mac2);
	}
}
