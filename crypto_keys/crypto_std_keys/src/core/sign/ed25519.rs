use alloc::vec::Vec;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::digest::Digest;
use rand_core::{CryptoRng, RngCore};
use sentc_crypto_core::cryptomat::{Sig, SignK, SignKeyPair, SymKey, VerifyK};
use sentc_crypto_core::{
	as_ref_bytes_single_value,
	crypto_alg_str_impl,
	into_bytes_single_value,
	try_from_bytes_owned_single_value,
	try_from_bytes_single_value,
	Error,
};

use crate::core::sign::{SignKey, VerifyKey};
use crate::get_rand;

pub const SIG_LENGTH: usize = 64;

pub const ED25519_OUTPUT: &str = "ED25519";

pub struct Ed25519Sig([u8; 64]);

crypto_alg_str_impl!(Ed25519Sig, ED25519_OUTPUT);
try_from_bytes_single_value!(Ed25519Sig);
try_from_bytes_owned_single_value!(Ed25519Sig);
as_ref_bytes_single_value!(Ed25519Sig);
into_bytes_single_value!(Ed25519Sig);

impl Into<crate::core::sign::Signature> for Ed25519Sig
{
	fn into(self) -> crate::core::sign::Signature
	{
		crate::core::sign::Signature::Ed25519(self)
	}
}

impl Sig for Ed25519Sig
{
	// fn split_sig_and_data<'a>(&self) -> Result<(&'a [u8], &'a [u8]), Error>
	// {
	// 	split_sig_and_data(&self.0)
	// }
	//
	// fn get_raw(&self) -> &[u8]
	// {
	// 	&self.0
	// }
}

pub struct Ed25519VerifyK([u8; 32]);

try_from_bytes_single_value!(Ed25519VerifyK);
try_from_bytes_owned_single_value!(Ed25519VerifyK);
crypto_alg_str_impl!(Ed25519VerifyK, ED25519_OUTPUT);
as_ref_bytes_single_value!(Ed25519VerifyK);

impl Into<VerifyKey> for Ed25519VerifyK
{
	fn into(self) -> VerifyKey
	{
		VerifyKey::Ed25519(self)
	}
}

impl VerifyK for Ed25519VerifyK
{
	type Signature = Ed25519Sig;

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
		hasher.update(self.0)
	}
}

pub struct Ed25519SignK([u8; 32]);

try_from_bytes_single_value!(Ed25519SignK);
try_from_bytes_owned_single_value!(Ed25519SignK);
crypto_alg_str_impl!(Ed25519SignK, ED25519_OUTPUT);
as_ref_bytes_single_value!(Ed25519SignK);

impl Into<SignKey> for Ed25519SignK
{
	fn into(self) -> SignKey
	{
		SignKey::Ed25519(self)
	}
}

impl SignK for Ed25519SignK
{
	type Signature = Ed25519Sig;

	fn encrypt_by_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		master_key.encrypt(&self.0)
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

		Ok(Ed25519Sig(sig))
	}
}

pub struct Ed25519KeyPair;

impl SignKeyPair for Ed25519KeyPair
{
	type SignKey = Ed25519SignK;
	type VerifyKey = Ed25519VerifyK;

	fn generate_key_pair() -> Result<(Self::SignKey, Self::VerifyKey), Error>
	{
		let (s, v) = generate_key_pair_internally(&mut get_rand())?;

		Ok((Ed25519SignK(s), Ed25519VerifyK(v)))
	}
}

pub(crate) fn split_sig_and_data(data_with_sig: &[u8]) -> Result<(&[u8], &[u8]), Error>
{
	super::split_sig_and_data(data_with_sig, SIG_LENGTH)
}

//__________________________________________________________________________________________________
//internally function

pub(super) fn generate_key_pair_internally<R: CryptoRng + RngCore>(rng: &mut R) -> Result<([u8; 32], [u8; 32]), Error>
{
	let sk = SigningKey::generate(rng);
	let verify_key = sk.verifying_key().to_bytes();
	let sign_key = sk.to_bytes();

	Ok((sign_key, verify_key))
}

pub(super) fn sign_internally(sign_key: &[u8; 32], data: &[u8]) -> Result<[u8; 64], Error>
{
	let sk = SigningKey::from_bytes(sign_key);

	let sig = sk.sign(data);

	Ok(sig.to_bytes())
}

pub(super) fn verify_internally(verify_key: &[u8; 32], sig: &[u8], data: &[u8]) -> Result<bool, Error>
{
	let vk = VerifyingKey::from_bytes(verify_key).map_err(|_| Error::InitVerifyFailed)?;
	let sig = Signature::try_from(sig).map_err(|_| Error::InitVerifyFailed)?;

	let result = vk.verify(data, &sig);

	match result {
		Ok(()) => Ok(true),
		Err(_e) => Ok(false),
	}
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
		let _ = Ed25519KeyPair::generate_key_pair().unwrap();
	}

	#[test]
	fn test_sign_and_verify()
	{
		let (sk, vk) = Ed25519KeyPair::generate_key_pair().unwrap();

		let text = "Hello world üöäéèßê°";

		let data_with_sig = sk.sign(text.as_bytes()).unwrap();

		let (data, check) = vk.verify(&data_with_sig).unwrap();

		assert!(check);
		assert_eq!(data, text.as_bytes());
	}

	#[test]
	fn test_wrong_verify()
	{
		let (_sk, vk) = Ed25519KeyPair::generate_key_pair().unwrap();
		let (sk, _vk) = Ed25519KeyPair::generate_key_pair().unwrap();

		let text = "Hello world üöäéèßê°";

		let data_with_sig = sk.sign(text.as_bytes()).unwrap();

		let (data, check) = vk.verify(&data_with_sig).unwrap();

		assert!(!check);
		assert_eq!(data, text.as_bytes());
	}

	#[test]
	fn test_too_short_sig_bytes()
	{
		let (sk, vk) = Ed25519KeyPair::generate_key_pair().unwrap();
		let text = "Hello world üöäéèßê°";

		let data_with_sig = sk.sign(text.as_bytes()).unwrap();

		let data_with_sig = &data_with_sig[..31];

		let check_result = vk.verify(data_with_sig);

		assert!(matches!(check_result, Err(DataToSignTooShort)));
	}

	#[test]
	fn test_wrong_sig_bytes()
	{
		let (sk, vk) = Ed25519KeyPair::generate_key_pair().unwrap();
		let text = "Hello world üöäéèßê°";

		let data_with_sig = sk.sign(text.as_bytes()).unwrap();

		let data_with_sig = &data_with_sig[..SIG_LENGTH + 2];

		let (_data, check) = vk.verify(data_with_sig).unwrap();

		assert!(!check);
	}

	#[test]
	fn test_safety_number()
	{
		let (_sk, vk) = Ed25519KeyPair::generate_key_pair().unwrap();

		let number = safety_number(&vk, "123", None, None);

		assert_eq!(number.len(), 32);
	}

	#[test]
	fn test_combined_safety_number()
	{
		let (_sk, vk) = Ed25519KeyPair::generate_key_pair().unwrap();
		let (_sk1, vk1) = Ed25519KeyPair::generate_key_pair().unwrap();

		let number = safety_number(&vk, "123", Some(&vk1), Some("321"));

		assert_eq!(number.len(), 32);

		//test the other way around

		let number_2 = safety_number(&vk1, "321", Some(&vk), Some("123"));

		assert_eq!(number_2.len(), 32);

		assert_ne!(number, number_2);
	}
}
