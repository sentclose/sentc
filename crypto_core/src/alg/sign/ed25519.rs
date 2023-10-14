use alloc::vec::Vec;

use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use rand_core::{CryptoRng, RngCore};

use crate::error::Error;
use crate::{get_rand, Sig, SignK, SignOutput, VerifyK};

pub const SIGN_KEY_LENGTH: usize = 32;
pub const SIG_LENGTH: usize = 64;

pub const ED25519_OUTPUT: &str = "ED25519";

#[allow(unused)]
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
	let sig = sign_only_raw(sign_key, data)?;

	let mut output = Vec::with_capacity(sig.len() + data.len());
	output.extend(sig);
	output.extend(data);

	Ok(output)
}

pub(crate) fn sign_only(sign_key: &SignK, data: &[u8]) -> Result<Sig, Error>
{
	let sig = sign_only_raw(sign_key, data)?;

	Ok(Sig::Ed25519(sig))
}

pub(crate) fn sign_only_raw(sign_key: &SignK, data: &[u8]) -> Result<[u8; 64], Error>
{
	match sign_key {
		SignK::Ed25519(sk) => sign_internally(sk, data),
		_ => Err(Error::AlgNotFound),
	}
}

pub(crate) fn split_sig_and_data(data_with_sig: &[u8]) -> Result<(&[u8], &[u8]), Error>
{
	super::split_sig_and_data(data_with_sig, SIG_LENGTH)
}

pub(crate) fn verify<'a>(verify_key: &VerifyK, data_with_sig: &'a [u8]) -> Result<(&'a [u8], bool), Error>
{
	let (sig, data) = split_sig_and_data(data_with_sig)?;

	Ok((data, verify_only_raw(verify_key, sig, data)?))
}

pub(crate) fn verify_only(verify_key: &VerifyK, sig: &Sig, data: &[u8]) -> Result<bool, Error>
{
	let sig = match sig {
		Sig::Ed25519(s) => s,
		_ => return Err(Error::AlgNotFound),
	};

	verify_only_raw(verify_key, sig, data)
}

pub(crate) fn verify_only_raw(verify_key: &VerifyK, sig: &[u8], data: &[u8]) -> Result<bool, Error>
{
	match verify_key {
		VerifyK::Ed25519(k) => verify_internally(k, sig, data),
		_ => Err(Error::AlgNotFound),
	}
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
	//create the key pair like the from bytes functions but only from the select key not both to avoid select key leak
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
		let out = generate_key_pair().unwrap();

		assert_eq!(out.alg, ED25519_OUTPUT);

		let sk = match out.sign_key {
			SignK::Ed25519(k) => k,
			_ => panic!("Wrong alg"),
		};

		let vk = match out.verify_key {
			VerifyK::Ed25519(k) => k,
			_ => panic!("Wrong alg"),
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
