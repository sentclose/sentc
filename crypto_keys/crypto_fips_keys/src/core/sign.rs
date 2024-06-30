use digest::Digest;
use openssl::pkey::{HasPrivate, HasPublic, Id, PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use sentc_crypto_core::cryptomat::{Sig, SignK, SignKeyComposer, SignKeyPair, SymKey, VerifyK};
use sentc_crypto_core::{as_ref_bytes_single_value, crypto_alg_str_impl, try_from_bytes_owned_single_value, try_from_bytes_single_value, Error};

use crate::core::export_sk;
use crate::import_export_openssl;

pub const FIPS_OPENSSL_ED25519: &str = "fips_openssl_ED25519";
pub const SIG_LENGTH: usize = 64;

pub struct Ed25519FIPSSig(Vec<u8>);
crypto_alg_str_impl!(Ed25519FIPSSig, FIPS_OPENSSL_ED25519);
try_from_bytes_single_value!(Ed25519FIPSSig);
try_from_bytes_owned_single_value!(Ed25519FIPSSig);
as_ref_bytes_single_value!(Ed25519FIPSSig);

impl Into<Vec<u8>> for Ed25519FIPSSig
{
	fn into(self) -> Vec<u8>
	{
		self.0
	}
}

impl Sig for Ed25519FIPSSig {}

pub struct Ed25519FIPSVerifyK(PKey<Public>);

import_export_openssl!(Ed25519FIPSVerifyK, import_pk, export_pk);
crypto_alg_str_impl!(Ed25519FIPSVerifyK, FIPS_OPENSSL_ED25519);

impl VerifyK for Ed25519FIPSVerifyK
{
	type Signature = Ed25519FIPSSig;

	fn verify<'a>(&self, data_with_sig: &'a [u8]) -> Result<(&'a [u8], bool), Error>
	{
		let (sig, data) = split_sig_and_data(data_with_sig)?;

		Ok((data, verify_internally(&self.0, sig, data)?))
	}

	fn verify_only(&self, sig: &Self::Signature, data: &[u8]) -> Result<bool, Error>
	{
		verify_internally(&self.0, &sig.0, data)
	}

	fn create_hash<D: Digest>(&self, hasher: &mut D)
	{
		hasher.update(export_pk(&self.0).unwrap())
	}
}

pub struct Ed25519FIPSSignK(PKey<Private>);

impl Ed25519FIPSSignK
{
	pub fn import(bytes: &[u8]) -> Result<Self, Error>
	{
		Ok(Self(import_sk(bytes)?))
	}
}

import_export_openssl!(Ed25519FIPSSignK, import_sk, export_sk);
crypto_alg_str_impl!(Ed25519FIPSSignK, FIPS_OPENSSL_ED25519);

impl SignK for Ed25519FIPSSignK
{
	type Signature = Ed25519FIPSSig;

	fn encrypt_by_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		master_key.encrypt(&export_sk(&self.0)?)
	}

	fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>
	{
		let sig = sign_internally(&self.0, data)?;

		let mut output = Vec::with_capacity(sig.len() + data.len());
		output.extend_from_slice(&sig);
		output.extend_from_slice(data);

		Ok(output)
	}

	fn sign_only<D: AsRef<[u8]>>(&self, data: D) -> Result<Self::Signature, Error>
	{
		let sig = sign_internally(&self.0, data.as_ref())?;

		Ok(Ed25519FIPSSig(sig))
	}
}

impl SignKeyPair for Ed25519FIPSSignK
{
	type SignKey = Self;
	type VerifyKey = Ed25519FIPSVerifyK;

	fn generate_key_pair() -> Result<(Self::SignKey, Self::VerifyKey), Error>
	{
		let (vk, sk) = generate_key_pair()?;

		Ok((Self(sk), Ed25519FIPSVerifyK(vk)))
	}
}

impl SignKeyComposer for Ed25519FIPSSignK
{
	type Key = Self;

	fn decrypt_by_master_key<M: SymKey>(master_key: &M, encrypted_key: &[u8], alg_str: &str) -> Result<Self::Key, Error>
	{
		if alg_str != FIPS_OPENSSL_ED25519 {
			return Err(Error::AlgNotFound);
		}

		let key = master_key.decrypt(encrypted_key)?;

		Self::import(&key)
	}
}

pub(crate) fn split_sig_and_data(data_with_sig: &[u8]) -> Result<(&[u8], &[u8]), Error>
{
	sentc_crypto_core::split_sig_and_data(data_with_sig, SIG_LENGTH)
}

//__________________________________________________________________________________________________

pub fn import_sk(key: &[u8]) -> Result<PKey<Private>, Error>
{
	PKey::private_key_from_raw_bytes(key, Id::ED25519).map_err(|_e| Error::KeyCreationFailed)
}

fn export_pk<T: HasPublic>(verify_key: &PKey<T>) -> Result<Vec<u8>, Error>
{
	verify_key
		.raw_public_key()
		.map_err(|_e| Error::KeyCreationFailed)
}

pub fn import_pk(key: &[u8]) -> Result<PKey<Public>, Error>
{
	PKey::public_key_from_raw_bytes(key, Id::ED25519).map_err(|_e| Error::KeyCreationFailed)
}

pub fn generate_key_pair() -> Result<(PKey<Public>, PKey<Private>), Error>
{
	let k = PKey::generate_ed25519().map_err(|_| Error::SignKeyCreateFailed)?;

	Ok((import_pk(&export_pk(&k)?)?, k))
}

pub fn sign_internally<T: HasPrivate>(sign_key: &PKey<T>, data: &[u8]) -> Result<Vec<u8>, Error>
{
	let mut signer = Signer::new_without_digest(sign_key).map_err(|_| Error::InitSignFailed)?;
	signer
		.sign_oneshot_to_vec(data)
		.map_err(|_| Error::InitSignFailed)
}

pub fn verify_internally<T: HasPublic>(verify_key: &PKey<T>, sig: &[u8], data: &[u8]) -> Result<bool, Error>
{
	let mut verifier = Verifier::new_without_digest(verify_key).map_err(|_| Error::InitVerifyFailed)?;

	verifier
		.verify_oneshot(sig, data)
		.map_err(|_| Error::InitVerifyFailed)
}

#[cfg(test)]
mod test
{
	use sentc_crypto_core::user::safety_number;
	use sentc_crypto_core::Error::DataToSignTooShort;

	use super::*;

	#[test]
	fn test_generate_keypair()
	{
		openssl::provider::Provider::load(None, "fips").unwrap();

		let _ = Ed25519FIPSSignK::generate_key_pair().unwrap();
	}

	#[test]
	fn test_sign_and_verify()
	{
		openssl::provider::Provider::load(None, "fips").unwrap();

		let (sk, vk) = Ed25519FIPSSignK::generate_key_pair().unwrap();

		let text = "Hello world üöäéèßê°";

		let data_with_sig = sk.sign(text.as_bytes()).unwrap();

		let (data, check) = vk.verify(&data_with_sig).unwrap();

		assert!(check);
		assert_eq!(data, text.as_bytes());
	}

	#[test]
	fn test_wrong_verify()
	{
		openssl::provider::Provider::load(None, "fips").unwrap();

		let (_sk, vk) = Ed25519FIPSSignK::generate_key_pair().unwrap();
		let (sk, _vk) = Ed25519FIPSSignK::generate_key_pair().unwrap();

		let text = "Hello world üöäéèßê°";

		let data_with_sig = sk.sign(text.as_bytes()).unwrap();

		let (data, check) = vk.verify(&data_with_sig).unwrap();

		assert!(!check);
		assert_eq!(data, text.as_bytes());
	}

	#[test]
	fn test_too_short_sig_bytes()
	{
		openssl::provider::Provider::load(None, "fips").unwrap();

		let (sk, vk) = Ed25519FIPSSignK::generate_key_pair().unwrap();
		let text = "Hello world üöäéèßê°";

		let data_with_sig = sk.sign(text.as_bytes()).unwrap();

		let data_with_sig = &data_with_sig[..31];

		let check_result = vk.verify(data_with_sig);

		assert!(matches!(check_result, Err(DataToSignTooShort)));
	}

	#[test]
	fn test_wrong_sig_bytes()
	{
		openssl::provider::Provider::load(None, "fips").unwrap();

		let (sk, vk) = Ed25519FIPSSignK::generate_key_pair().unwrap();
		let text = "Hello world üöäéèßê°";

		let data_with_sig = sk.sign(text.as_bytes()).unwrap();

		let data_with_sig = &data_with_sig[..SIG_LENGTH + 2];

		let (_data, check) = vk.verify(data_with_sig).unwrap();

		assert!(!check);
	}

	#[test]
	fn test_safety_number()
	{
		openssl::provider::Provider::load(None, "fips").unwrap();

		let (_sk, vk) = Ed25519FIPSSignK::generate_key_pair().unwrap();

		let number = safety_number(&vk, "123", None, None);

		assert_eq!(number.len(), 32);
	}

	#[test]
	fn test_combined_safety_number()
	{
		openssl::provider::Provider::load(None, "fips").unwrap();

		let (_sk, vk) = Ed25519FIPSSignK::generate_key_pair().unwrap();
		let (_sk1, vk1) = Ed25519FIPSSignK::generate_key_pair().unwrap();

		let number = safety_number(&vk, "123", Some(&vk1), Some("321"));

		assert_eq!(number.len(), 32);

		//test the other way around

		let number_2 = safety_number(&vk1, "321", Some(&vk), Some("123"));

		assert_eq!(number_2.len(), 32);

		assert_ne!(number, number_2);
	}
}
