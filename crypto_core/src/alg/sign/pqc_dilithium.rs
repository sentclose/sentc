use alloc::vec::Vec;

use hmac::digest::Digest;
use pqc_dilithium_edit::{Keypair, PUBLICKEYBYTES, SECRETKEYBYTES, SIGNBYTES};
use rand_core::{CryptoRng, RngCore};

use crate::cryptomat::{CryptoAlg, Sig, SignK, SignKeyPair, SymKey, VerifyK};
use crate::{
	as_ref_bytes_single_value,
	crypto_alg_str_impl,
	get_rand,
	into_bytes_single_value,
	try_from_bytes_owned_single_value,
	try_from_bytes_single_value,
	Error,
	SignKey,
	Signature,
	VerifyKey,
};

pub const DILITHIUM_OUTPUT: &str = "DILITHIUM_3";

pub struct DilithiumSig([u8; SIGNBYTES]);

crypto_alg_str_impl!(DilithiumSig, DILITHIUM_OUTPUT);
try_from_bytes_single_value!(DilithiumSig);
try_from_bytes_owned_single_value!(DilithiumSig);
as_ref_bytes_single_value!(DilithiumSig);
into_bytes_single_value!(DilithiumSig);

impl Into<Signature> for DilithiumSig
{
	fn into(self) -> Signature
	{
		Signature::Dilithium(self)
	}
}

impl Sig for DilithiumSig
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

pub struct DilithiumSignKey([u8; SECRETKEYBYTES]);

try_from_bytes_single_value!(DilithiumSignKey);
try_from_bytes_owned_single_value!(DilithiumSignKey);
crypto_alg_str_impl!(DilithiumSignKey, DILITHIUM_OUTPUT);
as_ref_bytes_single_value!(DilithiumSignKey);

impl Into<SignKey> for DilithiumSignKey
{
	fn into(self) -> SignKey
	{
		SignKey::Dilithium(self)
	}
}

impl SignK for DilithiumSignKey
{
	type Signature = DilithiumSig;

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

		Ok(DilithiumSig(sig))
	}
}

pub struct DilithiumVerifyKey([u8; PUBLICKEYBYTES]);

try_from_bytes_single_value!(DilithiumVerifyKey);
try_from_bytes_owned_single_value!(DilithiumVerifyKey);
crypto_alg_str_impl!(DilithiumVerifyKey, DILITHIUM_OUTPUT);
as_ref_bytes_single_value!(DilithiumVerifyKey);

impl Into<VerifyKey> for DilithiumVerifyKey
{
	fn into(self) -> VerifyKey
	{
		VerifyKey::Dilithium(self)
	}
}

impl VerifyK for DilithiumVerifyKey
{
	type Signature = DilithiumSig;

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
		hasher.update(&self.0)
	}
}

pub struct DilithiumKeyPair;

impl SignKeyPair for DilithiumKeyPair
{
	type SignKey = DilithiumSignKey;
	type VerifyKey = DilithiumVerifyKey;

	fn generate_key_pair() -> Result<(Self::SignKey, Self::VerifyKey), Error>
	{
		let (sk, pk) = generate_key_pair_internally(&mut get_rand())?;

		Ok((DilithiumSignKey(sk), DilithiumVerifyKey(pk)))
	}
}

pub(crate) fn split_sig_and_data(data_with_sig: &[u8]) -> Result<(&[u8], &[u8]), Error>
{
	super::split_sig_and_data(data_with_sig, SIGNBYTES)
}

//__________________________________________________________________________________________________
//internally function

pub(super) fn generate_key_pair_internally<R: CryptoRng + RngCore>(rng: &mut R) -> Result<([u8; SECRETKEYBYTES], [u8; PUBLICKEYBYTES]), Error>
{
	let keys = Keypair::generate(rng).map_err(|_| Error::KeyCreationFailed)?;

	Ok((keys.secret, keys.public))
}

pub(super) fn sign_internally(sign_key: &[u8; SECRETKEYBYTES], data: &[u8]) -> Result<[u8; SIGNBYTES], Error>
{
	let sig = pqc_dilithium_edit::sign(data, &mut get_rand(), sign_key).map_err(|_| Error::InitSignFailed)?;

	Ok(sig)
}

pub(super) fn verify_internally(verify_key: &[u8; PUBLICKEYBYTES], sig: &[u8], data: &[u8]) -> Result<bool, Error>
{
	let result = pqc_dilithium_edit::verify(sig, data, verify_key);

	match result {
		Ok(()) => Ok(true),
		Err(_e) => Ok(false),
	}
}

#[cfg(test)]
mod test
{
	use super::*;
	use crate::alg::sign::safety_number;
	use crate::error::Error::DataToSignTooShort;
	use crate::SafetyNumber;

	#[test]
	fn test_generate_keypair()
	{
		let _ = DilithiumKeyPair::generate_key_pair().unwrap();
	}

	#[test]
	fn test_sign_and_verify()
	{
		let (sk, vk) = DilithiumKeyPair::generate_key_pair().unwrap();

		let text = "Hello world üöäéèßê°";

		let data_with_sig = sk.sign(text.as_bytes()).unwrap();

		let (data, check) = vk.verify(&data_with_sig).unwrap();

		assert!(check);
		assert_eq!(data, text.as_bytes());
	}

	#[test]
	fn test_wrong_verify()
	{
		let (_sk, vk) = DilithiumKeyPair::generate_key_pair().unwrap();
		let (sk, _vk) = DilithiumKeyPair::generate_key_pair().unwrap();

		let text = "Hello world üöäéèßê°";

		let data_with_sig = sk.sign(text.as_bytes()).unwrap();

		let (data, check) = vk.verify(&data_with_sig).unwrap();

		assert!(!check);
		assert_eq!(data, text.as_bytes());
	}

	#[test]
	fn test_too_short_sig_bytes()
	{
		let (sk, vk) = DilithiumKeyPair::generate_key_pair().unwrap();
		let text = "Hello world üöäéèßê°";

		let data_with_sig = sk.sign(text.as_bytes()).unwrap();

		let data_with_sig = &data_with_sig[..31];

		let check_result = vk.verify(data_with_sig);

		assert!(matches!(check_result, Err(DataToSignTooShort)));
	}

	#[test]
	fn test_wrong_sig_bytes()
	{
		let (sk, vk) = DilithiumKeyPair::generate_key_pair().unwrap();
		let text = "Hello world üöäéèßê°";

		let data_with_sig = sk.sign(text.as_bytes()).unwrap();

		let data_with_sig = &data_with_sig[..SIGNBYTES + 2];

		let (_data, check) = vk.verify(data_with_sig).unwrap();

		assert!(!check);
	}

	#[test]
	fn test_safety_number()
	{
		let (_, vk) = DilithiumKeyPair::generate_key_pair().unwrap();

		let number = safety_number(
			SafetyNumber {
				verify_key: &vk,
				user_info: "123",
			},
			None,
		);

		assert_eq!(number.len(), 32);
	}

	#[test]
	fn test_combined_safety_number()
	{
		let (_, vk) = DilithiumKeyPair::generate_key_pair().unwrap();
		let (_, vk1) = DilithiumKeyPair::generate_key_pair().unwrap();

		let number = safety_number(
			SafetyNumber {
				verify_key: &vk,
				user_info: "123",
			},
			Some(SafetyNumber {
				verify_key: &vk1,
				user_info: "321",
			}),
		);

		assert_eq!(number.len(), 32);

		//test the other way around

		let number_2 = safety_number(
			SafetyNumber {
				verify_key: &vk1,
				user_info: "321",
			},
			Some(SafetyNumber {
				verify_key: &vk,
				user_info: "123",
			}),
		);

		assert_eq!(number_2.len(), 32);

		assert_ne!(number, number_2);
	}
}
