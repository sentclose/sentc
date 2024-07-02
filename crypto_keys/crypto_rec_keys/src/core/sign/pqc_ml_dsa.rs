use digest::Digest;
use safe_oqs::sig;
use safe_oqs::sig::{PublicKey, SecretKey, Sig as OqsSig};
use sentc_crypto_core::cryptomat::{Sig, SignK, SignKeyPair, SymKey, VerifyK};
use sentc_crypto_core::{as_ref_bytes_single_value, crypto_alg_str_impl, from_bytes_owned_single_value, into_bytes_from_bytes_inner, Error};

use crate::core::sign::Signature;

pub const ML_DSA_REC_OUTPUT: &str = "ML_DSA_65_REC";
pub const SIG_LENGTH: usize = 3309; //from oqs::ffi::sig::OQS_SIG_ml_dsa_65_ipd_length_signature

pub struct MlDsaSig(Vec<u8>);
crypto_alg_str_impl!(MlDsaSig, ML_DSA_REC_OUTPUT);
into_bytes_from_bytes_inner!(MlDsaSig);
from_bytes_owned_single_value!(MlDsaSig);
as_ref_bytes_single_value!(MlDsaSig);

impl Into<Signature> for MlDsaSig
{
	fn into(self) -> Signature
	{
		Signature::MlDsa(self)
	}
}

impl Sig for MlDsaSig {}

//__________________________________________________________________________________________________

pub struct MlDsaVk(Vec<u8>);
crypto_alg_str_impl!(MlDsaVk, ML_DSA_REC_OUTPUT);
into_bytes_from_bytes_inner!(MlDsaVk);
from_bytes_owned_single_value!(MlDsaVk);
as_ref_bytes_single_value!(MlDsaVk);

impl VerifyK for MlDsaVk
{
	type Signature = MlDsaSig;

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
		hasher.update(self.0.as_slice())
	}
}

//__________________________________________________________________________________________________

pub struct MlDsaSk(Vec<u8>);
crypto_alg_str_impl!(MlDsaSk, ML_DSA_REC_OUTPUT);
into_bytes_from_bytes_inner!(MlDsaSk);
from_bytes_owned_single_value!(MlDsaSk);
as_ref_bytes_single_value!(MlDsaSk);

impl SignK for MlDsaSk
{
	type Signature = MlDsaSig;

	fn encrypt_by_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		master_key.encrypt(self.0.as_slice())
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

		Ok(MlDsaSig(sig))
	}
}

impl SignKeyPair for MlDsaSk
{
	type SignKey = Self;
	type VerifyKey = MlDsaVk;

	fn generate_key_pair() -> Result<(Self::SignKey, Self::VerifyKey), Error>
	{
		let (sk, vk) = generate_key_pair()?;

		Ok((Self(sk.into_vec()), MlDsaVk(vk.into_vec())))
	}
}

//__________________________________________________________________________________________________

pub(crate) fn split_sig_and_data(data_with_sig: &[u8]) -> Result<(&[u8], &[u8]), Error>
{
	sentc_crypto_core::split_sig_and_data(data_with_sig, SIG_LENGTH)
}

pub(super) fn generate_key_pair() -> Result<(SecretKey, PublicKey), Error>
{
	let sig_alg = get_oqs()?;

	let (vk, sk) = sig_alg.keypair().map_err(|_| Error::KeyCreationFailed)?;

	Ok((sk, vk))
}

pub(super) fn sign_internally(sk: &[u8], data: &[u8]) -> Result<Vec<u8>, Error>
{
	let sig_alg = get_oqs()?;
	let sk = sig_alg
		.secret_key_from_bytes(sk)
		.ok_or(Error::KeyDecryptFailed)?;

	let sig = sig_alg.sign(data, sk).map_err(|_| Error::InitSignFailed)?;

	Ok(sig.into_vec())
}

pub(super) fn verify_internally(vk: &[u8], sig: &[u8], data: &[u8]) -> Result<bool, Error>
{
	let sig_alg = get_oqs()?;
	let vk = sig_alg
		.public_key_from_bytes(vk)
		.ok_or(Error::KeyDecryptFailed)?;

	let sig = sig_alg
		.signature_from_bytes(sig)
		.ok_or(Error::KeyDecryptFailed)?;

	let msg = sig_alg.verify(data, sig, vk);

	Ok(msg.is_ok())
}

fn get_oqs() -> Result<OqsSig, Error>
{
	safe_oqs::init();
	OqsSig::new(sig::Algorithm::MlDsa65).map_err(|_| Error::KeyCreationFailed)
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
		let _ = MlDsaSk::generate_key_pair().unwrap();
	}

	#[test]
	fn test_sign_and_verify()
	{
		let (sk, vk) = MlDsaSk::generate_key_pair().unwrap();

		let text = "Hello world üöäéèßê°";

		let data_with_sig = sk.sign(text.as_bytes()).unwrap();

		let (data, check) = vk.verify(&data_with_sig).unwrap();

		assert!(check);
		assert_eq!(data, text.as_bytes());
	}

	#[test]
	fn test_wrong_verify()
	{
		let (_sk, vk) = MlDsaSk::generate_key_pair().unwrap();
		let (sk, _vk) = MlDsaSk::generate_key_pair().unwrap();

		let text = "Hello world üöäéèßê°";

		let data_with_sig = sk.sign(text.as_bytes()).unwrap();

		let (data, check) = vk.verify(&data_with_sig).unwrap();

		assert!(!check);
		assert_eq!(data, text.as_bytes());
	}

	#[test]
	fn test_too_short_sig_bytes()
	{
		let (sk, vk) = MlDsaSk::generate_key_pair().unwrap();
		let text = "Hello world üöäéèßê°";

		let data_with_sig = sk.sign(text.as_bytes()).unwrap();

		let data_with_sig = &data_with_sig[..31];

		let check_result = vk.verify(data_with_sig);

		assert!(matches!(check_result, Err(DataToSignTooShort)));
	}

	#[test]
	fn test_wrong_sig_bytes()
	{
		let (sk, vk) = MlDsaSk::generate_key_pair().unwrap();
		let text = "Hello world üöäéèßê°";

		let data_with_sig = sk.sign(text.as_bytes()).unwrap();

		let data_with_sig = &data_with_sig[..SIG_LENGTH + 2];

		let (_data, check) = vk.verify(data_with_sig).unwrap();

		assert!(!check);
	}

	#[test]
	fn test_safety_number()
	{
		let (_, vk) = MlDsaSk::generate_key_pair().unwrap();

		let number = safety_number(&vk, "123", None, None);

		assert_eq!(number.len(), 32);
	}

	#[test]
	fn test_combined_safety_number()
	{
		let (_, vk) = MlDsaSk::generate_key_pair().unwrap();
		let (_, vk1) = MlDsaSk::generate_key_pair().unwrap();

		let number = safety_number(&vk, "123", Some(&vk1), Some("321"));

		assert_eq!(number.len(), 32);

		//test the other way around

		let number_2 = safety_number(&vk1, "321", Some(&vk), Some("123"));

		assert_eq!(number_2.len(), 32);

		assert_ne!(number, number_2);
	}
}
