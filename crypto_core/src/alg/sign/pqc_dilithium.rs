use alloc::vec::Vec;

use pqc_dilithium_edit::{Keypair, PUBLICKEYBYTES, SECRETKEYBYTES, SIGNBYTES};
use rand_core::{CryptoRng, RngCore};

use crate::alg::sign::SignOutput;
use crate::{get_rand, Error, Sig, SignK, VerifyK};

pub const DILITHIUM_OUTPUT: &str = "DILITHIUM_3";

#[allow(unused)]
pub(crate) fn generate_key_pair() -> Result<SignOutput, Error>
{
	let (sk, pk) = generate_key_pair_internally(&mut get_rand())?;

	Ok(SignOutput {
		sign_key: SignK::Dilithium(sk),
		verify_key: VerifyK::Dilithium(pk),
		alg: DILITHIUM_OUTPUT,
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

	Ok(Sig::Dilithium(sig))
}

pub(crate) fn sign_only_raw(sign_key: &SignK, data: &[u8]) -> Result<[u8; SIGNBYTES], Error>
{
	let sign_key = match sign_key {
		SignK::Dilithium(sk) => sk,
		_ => return Err(Error::AlgNotFound),
	};

	let sig = pqc_dilithium_edit::sign(data, &mut get_rand(), sign_key).map_err(|_| Error::InitSignFailed)?;

	Ok(sig)
}

pub(crate) fn split_sig_and_data(data_with_sig: &[u8]) -> Result<(&[u8], &[u8]), Error>
{
	super::split_sig_and_data(data_with_sig, SIGNBYTES)
}

pub(crate) fn verify<'a>(verify_key: &VerifyK, data_with_sig: &'a [u8]) -> Result<(&'a [u8], bool), Error>
{
	let (sig, data) = split_sig_and_data(data_with_sig)?;

	Ok((data, verify_only_raw(verify_key, sig, data)?))
}

pub(crate) fn verify_only(verify_key: &VerifyK, sig: &Sig, data: &[u8]) -> Result<bool, Error>
{
	let sig = match sig {
		Sig::Dilithium(s) => s,
		_ => return Err(Error::AlgNotFound),
	};

	verify_only_raw(verify_key, sig, data)
}

pub(crate) fn verify_only_raw(verify_key: &VerifyK, sig: &[u8], data: &[u8]) -> Result<bool, Error>
{
	let vk = match verify_key {
		VerifyK::Dilithium(k) => k,
		_ => return Err(Error::AlgNotFound),
	};

	let result = pqc_dilithium_edit::verify(sig, data, vk);

	match result {
		Ok(()) => Ok(true),
		Err(_e) => Ok(false),
	}
}

//__________________________________________________________________________________________________
//internally function

pub(super) fn generate_key_pair_internally<R: CryptoRng + RngCore>(rng: &mut R) -> Result<([u8; SECRETKEYBYTES], [u8; PUBLICKEYBYTES]), Error>
{
	let keys = Keypair::generate(rng).map_err(|_| Error::KeyCreationFailed)?;

	Ok((keys.secret, keys.public))
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

		assert_eq!(out.alg, DILITHIUM_OUTPUT);

		let sk = match out.sign_key {
			SignK::Dilithium(k) => k,
			_ => panic!("Wrong alg"),
		};

		let vk = match out.verify_key {
			VerifyK::Dilithium(k) => k,
			_ => panic!("Wrong alg"),
		};

		assert_eq!(sk.len(), SECRETKEYBYTES);
		assert_eq!(vk.len(), PUBLICKEYBYTES);
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

		let data_with_sig = &data_with_sig[..SIGNBYTES + 2];

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
