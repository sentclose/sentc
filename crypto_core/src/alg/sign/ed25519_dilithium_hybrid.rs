use alloc::vec::Vec;

use pqc_dilithium_edit::SIGNBYTES;

use crate::alg::sign::SignOutput;
use crate::{get_rand, Error, Sig, SignK, VerifyK};

pub const ED25519_DILITHIUM_HYBRID_OUTPUT: &str = "ED25519_DILITHIUM_3";

#[allow(unused)]
pub(crate) fn generate_key_pair() -> Result<SignOutput, Error>
{
	let kp = super::ed25519::generate_key_pair_internally(&mut get_rand())?;
	let (sk, pk) = super::pqc_dilithium::generate_key_pair_internally(&mut get_rand())?;

	Ok(SignOutput {
		alg: ED25519_DILITHIUM_HYBRID_OUTPUT,
		sign_key: SignK::Ed25519DilithiumHybrid {
			x: kp.secret.to_bytes(),
			k: sk,
		},
		verify_key: VerifyK::Ed25519DilithiumHybrid {
			x: kp.public.to_bytes(),
			k: pk,
		},
	})
}

pub(crate) fn sign(sign_key: &SignK, data: &[u8]) -> Result<Vec<u8>, Error>
{
	let (sig_x, sig_k) = sign_only_raw(sign_key, data)?;

	let mut output = Vec::with_capacity(sig_x.len() + sig_k.len() + data.len());
	output.extend(sig_x);
	output.extend(sig_k);
	output.extend(data);

	Ok(output)
}

pub(crate) fn sign_only(sign_key: &SignK, data: &[u8]) -> Result<Sig, Error>
{
	let (x, k) = sign_only_raw(sign_key, data)?;

	Ok(Sig::Ed25519DilithiumHybrid {
		x,
		k,
	})
}

pub(crate) fn sign_only_raw(sign_key: &SignK, data: &[u8]) -> Result<([u8; 64], [u8; SIGNBYTES]), Error>
{
	let (x, k) = match sign_key {
		SignK::Ed25519DilithiumHybrid {
			x,
			k,
		} => (x, k),
		_ => return Err(Error::AlgNotFound),
	};

	//first sign the data with ed25519
	let sig_x = super::ed25519::sign_internally(x, data)?;

	//and then sign it including with the sign with dilithium
	let sig_k = super::pqc_dilithium::sign_internally(k, &[data, &sig_x].concat())?;

	Ok((sig_x, sig_k))
}

pub(crate) fn split_sig_and_data(data_with_sig: &[u8]) -> Result<(&[u8], &[u8]), Error>
{
	super::split_sig_and_data(data_with_sig, super::ed25519::SIG_LENGTH + SIGNBYTES)
}

pub(crate) fn verify<'a>(verify_key: &VerifyK, data_with_sig: &'a [u8]) -> Result<(&'a [u8], bool), Error>
{
	let (sig, data) = split_sig_and_data(data_with_sig)?;

	//now split the both sig
	let (sig_x, sig_k) = super::split_sig_and_data(sig, super::ed25519::SIG_LENGTH)?;

	Ok((data, verify_only_raw(verify_key, sig_x, sig_k, data)?))
}

pub(crate) fn verify_only(verify_key: &VerifyK, sig: &Sig, data: &[u8]) -> Result<bool, Error>
{
	let (sig_x, sig_k) = match sig {
		Sig::Ed25519DilithiumHybrid {
			x,
			k,
		} => (x, k),
		_ => return Err(Error::AlgNotFound),
	};

	verify_only_raw(verify_key, sig_x, sig_k, data)
}

pub(crate) fn verify_only_raw(verify_key: &VerifyK, sig_x: &[u8], sig_k: &[u8], data: &[u8]) -> Result<bool, Error>
{
	let (x, k) = match verify_key {
		VerifyK::Ed25519DilithiumHybrid {
			x,
			k,
		} => (x, k),
		_ => return Err(Error::AlgNotFound),
	};

	//first verify with dilithium with the data and the sig_x attached

	let res = super::pqc_dilithium::verify_internally(k, sig_k, &[data, sig_x].concat())?;

	if !res {
		return Ok(res);
	}

	//then verify with ed25519

	super::ed25519::verify_internally(x, sig_x, data)
}

#[cfg(test)]
mod test
{
	use pqc_dilithium_edit::{PUBLICKEYBYTES, SECRETKEYBYTES};

	use super::*;
	use crate::alg::sign::ed25519::SIG_LENGTH;
	use crate::alg::sign::safety_number;
	use crate::error::Error::DataToSignTooShort;
	use crate::SafetyNumber;

	#[test]
	fn test_generate_keypair()
	{
		let out = generate_key_pair().unwrap();

		assert_eq!(out.alg, ED25519_DILITHIUM_HYBRID_OUTPUT);

		match out.sign_key {
			SignK::Ed25519DilithiumHybrid {
				x,
				k,
			} => {
				assert_eq!(k.len(), SECRETKEYBYTES);
				assert_eq!(x.len(), 32);
			},
			_ => panic!("Wrong alg"),
		}

		match out.verify_key {
			VerifyK::Ed25519DilithiumHybrid {
				x,
				k,
			} => {
				assert_eq!(k.len(), PUBLICKEYBYTES);
				assert_eq!(x.len(), 32);
			},
			_ => panic!("Wrong alg"),
		}
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

		let data_with_sig = &data_with_sig[..SIGNBYTES + SIG_LENGTH + 2];

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
