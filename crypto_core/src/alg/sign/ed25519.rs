use alloc::vec::Vec;

use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use hmac::digest::Digest;
use rand_core::{CryptoRng, RngCore};

use crate::cryptomat::{CryptoAlg, Sig, SignK, SignKeyPair, SymKey, VerifyK};
use crate::error::Error;
use crate::{crypto_alg_str_impl, get_rand, into_bytes_single_value, try_from_bytes_single_value, SignKey, VerifyKey};

pub const SIGN_KEY_LENGTH: usize = 32;
pub const SIG_LENGTH: usize = 64;

pub const ED25519_OUTPUT: &str = "ED25519";

pub struct Ed25519Sig([u8; 64]);

crypto_alg_str_impl!(Ed25519Sig, ED25519_OUTPUT);

impl Into<crate::Signature> for Ed25519Sig
{
	fn into(self) -> crate::Signature
	{
		crate::Signature::Ed25519(self)
	}
}

into_bytes_single_value!(Ed25519Sig);

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
crypto_alg_str_impl!(Ed25519VerifyK, ED25519_OUTPUT);

impl Into<VerifyKey> for Ed25519VerifyK
{
	fn into(self) -> VerifyKey
	{
		VerifyKey::Ed25519(self)
	}
}

impl VerifyK for Ed25519VerifyK
{
	fn verify<'a>(&self, data_with_sig: &'a [u8]) -> Result<(&'a [u8], bool), Error>
	{
		let (sig, data) = split_sig_and_data(data_with_sig)?;

		Ok((data, verify_internally(&self.0, sig, data)?))
	}

	fn verify_only(&self, sig: &[u8], data: &[u8]) -> Result<bool, Error>
	{
		verify_internally(&self.0, sig, data)
	}

	fn create_hash<D: Digest>(&self, hasher: &mut D)
	{
		hasher.update(&self.0)
	}
}

pub struct Ed25519SignK([u8; 32]);

try_from_bytes_single_value!(Ed25519SignK);
crypto_alg_str_impl!(Ed25519SignK, ED25519_OUTPUT);

impl Into<SignKey> for Ed25519SignK
{
	fn into(self) -> SignKey
	{
		SignKey::Ed25519(self)
	}
}

impl SignK for Ed25519SignK
{
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

	fn sign_only<D: AsRef<[u8]>>(&self, data: D) -> Result<impl Sig, Error>
	{
		let sig = sign_internally(&self.0, data.as_ref())?;

		Ok(Ed25519Sig(sig))
	}
}

pub struct Ed25519KeyPair;

impl SignKeyPair for Ed25519KeyPair
{
	fn generate_key_pair() -> Result<(impl SignK, impl VerifyK), Error>
	{
		let keypair = generate_key_pair_internally(&mut get_rand())?;

		Ok((
			Ed25519SignK(keypair.secret.to_bytes()),
			Ed25519VerifyK(keypair.public.to_bytes()),
		))
	}
}

pub(crate) fn split_sig_and_data(data_with_sig: &[u8]) -> Result<(&[u8], &[u8]), Error>
{
	super::split_sig_and_data(data_with_sig, SIG_LENGTH)
}

//__________________________________________________________________________________________________
//internally function

pub(super) fn generate_key_pair_internally<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Keypair, Error>
{
	//generate the keys like the Keypair::generate() functions but with rand_core instead of rand
	let mut sk_bytes = [0u8; SIGN_KEY_LENGTH];

	rng.try_fill_bytes(&mut sk_bytes)
		.map_err(|_| Error::SignKeyCreateFailed)?;

	let sk = SecretKey::from_bytes(&sk_bytes).map_err(|_| Error::SignKeyCreateFailed)?;
	let pk: PublicKey = (&sk).into();

	Ok(Keypair {
		public: pk,
		secret: sk,
	})
}

pub(super) fn sign_internally(sign_key: &[u8; 32], data: &[u8]) -> Result<[u8; 64], Error>
{
	//create the key pair like the bytes functions but only from the select key not both to avoid select key leak
	//see here: https://github.com/MystenLabs/ed25519-unsafe-libs

	let sk = SecretKey::from_bytes(sign_key).map_err(|_| Error::InitSignFailed)?;
	let vk: PublicKey = (&sk).into();

	let keypair = Keypair {
		public: vk,
		secret: sk,
	};

	let sig = keypair.sign(data);

	Ok(sig.to_bytes())
}

pub(super) fn verify_internally(verify_key: &[u8; 32], sig: &[u8], data: &[u8]) -> Result<bool, Error>
{
	let vk = PublicKey::from_bytes(verify_key).map_err(|_| Error::InitVerifyFailed)?;
	let sig = Signature::from_bytes(sig).map_err(|_| Error::InitVerifyFailed)?;

	let result = vk.verify(data, &sig);

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
		let (_sk, vk) = Ed25519KeyPair::generate_key_pair().unwrap();
		let (_sk1, vk1) = Ed25519KeyPair::generate_key_pair().unwrap();

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
