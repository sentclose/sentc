use alloc::vec::Vec;

use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::{get_rand, SafetyNumber, SignK, SignOutput, VerifyK};

pub const SIGN_KEY_LENGTH: usize = 32;
pub const SIG_LENGTH: usize = 64;

pub const ED25519_OUTPUT: &str = "ED25519";

pub(crate) fn generate_key_pair() -> Result<SignOutput, Error>
{
	let keypair = generate_key_pair_internally(&mut get_rand())?;

	Ok(SignOutput {
		sign_key: SignK::Ed25519(keypair.secret.to_bytes()),
		verify_key: VerifyK::Ed25519(keypair.public.to_bytes()),
		alg: ED25519_OUTPUT,
	})
}

pub(crate) fn sign(sign_key: &SignK, data: &[u8]) -> Result<Vec<u8>, Error>
{
	//create the key pair like the from bytes functions but only from the select key not both to avoid select key leak
	//see here: https://github.com/MystenLabs/ed25519-unsafe-libs
	let keypair = match sign_key {
		SignK::Ed25519(sk) => {
			let sk = SecretKey::from_bytes(sk).map_err(|_| Error::InitSignFailed)?;
			let vk: PublicKey = (&sk).into();

			Keypair {
				public: vk,
				secret: sk,
			}
		},
	};

	let sig = keypair.sign(data);
	let sig = sig.to_bytes();

	let mut output = Vec::with_capacity(sig.len() + data.len());
	output.extend(sig);
	output.extend(data);

	Ok(output)
}

pub(crate) fn split_sig_and_data(data_with_sig: &[u8]) -> Result<(&[u8], &[u8]), Error>
{
	if data_with_sig.len() <= SIG_LENGTH {
		return Err(Error::DataToSignTooShort);
	}

	//split sign and data
	let sig = &data_with_sig[..SIG_LENGTH];
	let data = &data_with_sig[SIG_LENGTH..];

	Ok((sig, data))
}

pub(crate) fn verify<'a>(verify_key: &VerifyK, data_with_sig: &'a [u8]) -> Result<(&'a [u8], bool), Error>
{
	let (sig, data) = split_sig_and_data(data_with_sig)?;

	let vk = match verify_key {
		VerifyK::Ed25519(k) => PublicKey::from_bytes(k).map_err(|_| Error::InitVerifyFailed)?,
	};

	let sig = Signature::from_bytes(sig).map_err(|_| Error::InitVerifyFailed)?;

	let result = vk.verify(data, &sig);

	//get the data without the sig

	match result {
		Err(_e) => Ok((data, false)),
		Ok(()) => Ok((data, true)),
	}
}

pub(crate) fn safety_number(user_1: SafetyNumber, user_2: Option<SafetyNumber>) -> Vec<u8>
{
	let mut hasher = Sha256::new();

	match user_1.verify_key {
		VerifyK::Ed25519(k) => hasher.update(k),
	}

	hasher.update(user_1.user_info.as_bytes());

	if let Some(u_2) = user_2 {
		match u_2.verify_key {
			VerifyK::Ed25519(k) => hasher.update(k),
		}

		hasher.update(u_2.user_info.as_bytes());
	}

	let number_bytes = hasher.finalize();

	number_bytes.to_vec()
}

//__________________________________________________________________________________________________
//internally function

fn generate_key_pair_internally<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Keypair, Error>
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

#[cfg(test)]
mod test
{
	use super::*;
	use crate::error::Error::DataToSignTooShort;

	#[test]
	fn test_generate_keypair()
	{
		let out = generate_key_pair().unwrap();

		assert_eq!(out.alg, ED25519_OUTPUT);

		let sk = match out.sign_key {
			SignK::Ed25519(k) => k,
		};

		let vk = match out.verify_key {
			VerifyK::Ed25519(k) => k,
		};

		assert_eq!(sk.len(), 32);
		assert_eq!(vk.len(), 32);
	}

	#[test]
	fn test_sign_and_verify()
	{
		let out = generate_key_pair().unwrap();

		let text = "Hello world üöäéèßê°";

		let data_with_sig = sign(&out.sign_key, text.as_bytes()).unwrap();

		let (data, check) = verify(&out.verify_key, &data_with_sig).unwrap();

		assert!(check);
		assert_eq!(data, text.as_bytes());
	}

	#[test]
	fn test_wrong_verify()
	{
		let out = generate_key_pair().unwrap();
		let out1 = generate_key_pair().unwrap();

		let text = "Hello world üöäéèßê°";

		let data_with_sig = sign(&out.sign_key, text.as_bytes()).unwrap();

		let (data, check) = verify(&out1.verify_key, &data_with_sig).unwrap();

		assert!(!check);
		assert_eq!(data, text.as_bytes());
	}

	#[test]
	fn test_too_short_sig_bytes()
	{
		let out = generate_key_pair().unwrap();
		let text = "Hello world üöäéèßê°";

		let data_with_sig = sign(&out.sign_key, text.as_bytes()).unwrap();

		let data_with_sig = &data_with_sig[..31];

		let check_result = verify(&out.verify_key, data_with_sig);

		assert!(matches!(check_result, Err(DataToSignTooShort)));
	}

	#[test]
	fn test_wrong_sig_bytes()
	{
		let out = generate_key_pair().unwrap();
		let text = "Hello world üöäéèßê°";

		let data_with_sig = sign(&out.sign_key, text.as_bytes()).unwrap();

		let data_with_sig = &data_with_sig[..SIG_LENGTH + 2];

		let (_data, check) = verify(&out.verify_key, data_with_sig).unwrap();

		assert!(!check);
	}

	extern crate std;

	#[test]
	fn test_safety_number()
	{
		let u1 = generate_key_pair().unwrap();

		let number = safety_number(
			SafetyNumber {
				verify_key: &u1.verify_key,
				user_info: "123",
			},
			None,
		);

		assert_eq!(number.len(), 32);
	}

	#[test]
	fn test_combined_safety_number()
	{
		let u1 = generate_key_pair().unwrap();
		let u2 = generate_key_pair().unwrap();

		let number = safety_number(
			SafetyNumber {
				verify_key: &u1.verify_key,
				user_info: "123",
			},
			Some(SafetyNumber {
				verify_key: &u2.verify_key,
				user_info: "321",
			}),
		);

		assert_eq!(number.len(), 32);

		//test the other way around

		let number_2 = safety_number(
			SafetyNumber {
				verify_key: &u2.verify_key,
				user_info: "321",
			},
			Some(SafetyNumber {
				verify_key: &u1.verify_key,
				user_info: "123",
			}),
		);

		assert_eq!(number_2.len(), 32);

		assert_ne!(number, number_2);
	}
}
