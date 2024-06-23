use openssl::hash::MessageDigest;
use openssl::memcmp;
use openssl::pkey::{Id, PKey, Private};
use openssl::sign::Signer;
use sentc_crypto_core::cryptomat::{SearchableKey, SearchableKeyComposer, SearchableKeyGen, SymKey};
use sentc_crypto_core::{crypto_alg_str_impl, Error};

use crate::core::{export_sk, sym};

pub const FIPS_OPENSSL_HMAC_SHA256_OUTPUT: &str = "fips_openssl_HMAC-SHA256";

pub struct HmacKey(PKey<Private>);

impl HmacKey
{
	pub fn export(&self) -> Result<Vec<u8>, Error>
	{
		export_sk(&self.0)
	}

	pub fn import(bytes: &[u8]) -> Result<Self, Error>
	{
		Ok(Self(import_sk(bytes)?))
	}
}

crypto_alg_str_impl!(HmacKey, FIPS_OPENSSL_HMAC_SHA256_OUTPUT);

impl SearchableKey for HmacKey
{
	fn encrypt_key_with_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		master_key.encrypt(&export_sk(&self.0)?)
	}

	fn encrypt_searchable(&self, data: &[u8]) -> Result<Vec<u8>, Error>
	{
		let mut signer = Signer::new(MessageDigest::sha256(), &self.0).map_err(|_| Error::HmacAuthFailedLength)?;
		signer
			.update(data)
			.map_err(|_| Error::HmacAuthFailedLength)?;

		signer
			.sign_to_vec()
			.map_err(|_| Error::HmacAuthFailedLength)
	}

	fn verify_encrypted_searchable(&self, data: &[u8], check: &[u8]) -> Result<bool, Error>
	{
		let sign = self.encrypt_searchable(data)?;

		Ok(memcmp::eq(&sign, check))
	}
}

impl SearchableKeyGen for HmacKey
{
	type SearchableKey = Self;

	fn generate() -> Result<Self::SearchableKey, Error>
	{
		let secret = sym::raw_generate()?;

		let key = PKey::hmac(&secret).map_err(|_| Error::KeyCreationFailed)?;

		Ok(Self(key))
	}
}

impl SearchableKeyComposer for HmacKey
{
	type Key = Self;

	fn decrypt_by_master_key<M: SymKey>(master_key: &M, encrypted_key: &[u8], alg_str: &str) -> Result<Self::Key, Error>
	{
		if alg_str != FIPS_OPENSSL_HMAC_SHA256_OUTPUT {
			return Err(Error::AlgNotFound);
		}

		let key = master_key.decrypt(encrypted_key)?;

		Self::import(&key)
	}
}

fn import_sk(key: &[u8]) -> Result<PKey<Private>, Error>
{
	PKey::private_key_from_raw_bytes(key, Id::HMAC).map_err(|_e| Error::KeyCreationFailed)
}

#[cfg(test)]
mod test
{
	use super::*;

	#[test]
	fn test_create_hmac_key()
	{
		openssl::provider::Provider::load(None, "fips").unwrap();
		let _ = HmacKey::generate().unwrap();
	}

	#[test]
	fn test_plain_auth_msg()
	{
		openssl::provider::Provider::load(None, "fips").unwrap();

		let msg = "Hello world üöäéèßê°";

		let out = HmacKey::generate().unwrap();

		let mac = out.encrypt_searchable(msg.as_bytes()).unwrap();

		let verify = out
			.verify_encrypted_searchable(msg.as_bytes(), &mac)
			.unwrap();

		assert!(verify);
	}

	#[test]
	fn test_not_verify_with_wrong_key()
	{
		openssl::provider::Provider::load(None, "fips").unwrap();

		let msg = "Hello world üöäéèßê°";

		let out = HmacKey::generate().unwrap();
		let out2 = HmacKey::generate().unwrap();

		let mac = out.encrypt_searchable(msg.as_bytes()).unwrap();

		let verify = out2
			.verify_encrypted_searchable(msg.as_bytes(), &mac)
			.unwrap();

		assert!(!verify);
	}

	#[test]
	fn test_not_producing_the_same_output_with_different_keys()
	{
		openssl::provider::Provider::load(None, "fips").unwrap();

		let msg = "Hello world üöäéèßê°";

		let out = HmacKey::generate().unwrap();
		let out2 = HmacKey::generate().unwrap();

		let mac1 = out.encrypt_searchable(msg.as_bytes()).unwrap();

		let mac2 = out2.encrypt_searchable(msg.as_bytes()).unwrap();

		assert_ne!(mac1, mac2);
	}

	#[test]
	fn test_producing_the_same_output_with_same_keys()
	{
		openssl::provider::Provider::load(None, "fips").unwrap();

		let msg = "Hello world üöäéèßê°";

		let out = HmacKey::generate().unwrap();

		let mac1 = out.encrypt_searchable(msg.as_bytes()).unwrap();

		let mac2 = out.encrypt_searchable(msg.as_bytes()).unwrap();

		assert_eq!(mac1, mac2);
	}
}
