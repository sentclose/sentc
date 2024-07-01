use digest::Digest;
use pqcrypto_dilithium::dilithium3::{DetachedSignature, PublicKey, SecretKey};
use pqcrypto_dilithium::{dilithium3_detached_sign, dilithium3_keypair, dilithium3_verify_detached_signature};
use pqcrypto_traits::sign::{DetachedSignature as DsT, PublicKey as PkT, SecretKey as SkT};
use sentc_crypto_core::cryptomat::{Sig, SignK, SignKeyPair, SymKey, VerifyK};
use sentc_crypto_core::{as_ref_bytes_single_value, crypto_alg_str_impl, try_from_bytes_single_value, Error};

use crate::core::sign::Signature;
use crate::import_export_pqc;

pub const DILITHIUM_REC_OUTPUT: &str = "DILITHIUM_REC_3";
pub const SIG_LENGTH: usize = 3309;

pub struct DilithiumSig(Vec<u8>);
crypto_alg_str_impl!(DilithiumSig, DILITHIUM_REC_OUTPUT);
as_ref_bytes_single_value!(DilithiumSig);
try_from_bytes_single_value!(DilithiumSig);

impl Into<Vec<u8>> for DilithiumSig
{
	fn into(self) -> Vec<u8>
	{
		self.0
	}
}

impl From<Vec<u8>> for DilithiumSig
{
	fn from(value: Vec<u8>) -> Self
	{
		Self(value)
	}
}

impl Into<Signature> for DilithiumSig
{
	fn into(self) -> Signature
	{
		Signature::Dilithium(self)
	}
}

impl Sig for DilithiumSig {}

pub struct DilithiumVk(PublicKey);
crypto_alg_str_impl!(DilithiumVk, DILITHIUM_REC_OUTPUT);
import_export_pqc!(DilithiumVk, PublicKey);

impl VerifyK for DilithiumVk
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
		hasher.update(self.0.as_bytes())
	}
}

pub struct DilithiumSignK(SecretKey);
crypto_alg_str_impl!(DilithiumSignK, DILITHIUM_REC_OUTPUT);
import_export_pqc!(DilithiumSignK, SecretKey);

impl SignK for DilithiumSignK
{
	type Signature = DilithiumSig;

	fn encrypt_by_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		master_key.encrypt(self.0.as_bytes())
	}

	fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>
	{
		let sig = sign_internally(&self.0, data);

		let mut output = Vec::with_capacity(sig.len() + data.len());
		output.extend_from_slice(&sig);
		output.extend_from_slice(data);

		Ok(output)
	}

	fn sign_only<D: AsRef<[u8]>>(&self, data: D) -> Result<Self::Signature, Error>
	{
		let sig = sign_internally(&self.0, data.as_ref());

		Ok(DilithiumSig(sig))
	}
}

impl SignKeyPair for DilithiumSignK
{
	type SignKey = Self;
	type VerifyKey = DilithiumVk;

	fn generate_key_pair() -> Result<(Self::SignKey, Self::VerifyKey), Error>
	{
		let (pk, sk) = generate_key_pair();

		Ok((Self(sk), DilithiumVk(pk)))
	}
}

pub(crate) fn split_sig_and_data(data_with_sig: &[u8]) -> Result<(&[u8], &[u8]), Error>
{
	sentc_crypto_core::split_sig_and_data(data_with_sig, SIG_LENGTH)
}

//__________________________________________________________________________________________________

pub(super) fn generate_key_pair() -> (PublicKey, SecretKey)
{
	dilithium3_keypair()
}

pub(super) fn verify_internally(vk: &PublicKey, sig: &[u8], data: &[u8]) -> Result<bool, Error>
{
	let verified_msg = dilithium3_verify_detached_signature(
		&DetachedSignature::from_bytes(sig).map_err(|_| Error::InitVerifyFailed)?,
		data,
		vk,
	);

	Ok(verified_msg.is_ok())
}

pub(super) fn sign_internally(sk: &SecretKey, data: &[u8]) -> Vec<u8>
{
	let sig = dilithium3_detached_sign(data, sk);

	sig.as_bytes().to_vec()
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
		let _ = DilithiumSignK::generate_key_pair().unwrap();
	}

	#[test]
	fn test_sign_and_verify()
	{
		let (sk, vk) = DilithiumSignK::generate_key_pair().unwrap();

		let text = "Hello world üöäéèßê°";

		let data_with_sig = sk.sign(text.as_bytes()).unwrap();

		let (data, check) = vk.verify(&data_with_sig).unwrap();

		assert!(check);
		assert_eq!(data, text.as_bytes());
	}

	#[test]
	fn test_wrong_verify()
	{
		let (_sk, vk) = DilithiumSignK::generate_key_pair().unwrap();
		let (sk, _vk) = DilithiumSignK::generate_key_pair().unwrap();

		let text = "Hello world üöäéèßê°";

		let data_with_sig = sk.sign(text.as_bytes()).unwrap();

		let (data, check) = vk.verify(&data_with_sig).unwrap();

		assert!(!check);
		assert_eq!(data, text.as_bytes());
	}

	#[test]
	fn test_too_short_sig_bytes()
	{
		let (sk, vk) = DilithiumSignK::generate_key_pair().unwrap();
		let text = "Hello world üöäéèßê°";

		let data_with_sig = sk.sign(text.as_bytes()).unwrap();

		let data_with_sig = &data_with_sig[..31];

		let check_result = vk.verify(data_with_sig);

		assert!(matches!(check_result, Err(DataToSignTooShort)));
	}

	#[test]
	fn test_wrong_sig_bytes()
	{
		let (sk, vk) = DilithiumSignK::generate_key_pair().unwrap();
		let text = "Hello world üöäéèßê°";

		let data_with_sig = sk.sign(text.as_bytes()).unwrap();

		let data_with_sig = &data_with_sig[..SIG_LENGTH + 2];

		let (_data, check) = vk.verify(data_with_sig).unwrap();

		assert!(!check);
	}

	#[test]
	fn test_safety_number()
	{
		let (_, vk) = DilithiumSignK::generate_key_pair().unwrap();

		let number = safety_number(&vk, "123", None, None);

		assert_eq!(number.len(), 32);
	}

	#[test]
	fn test_combined_safety_number()
	{
		let (_, vk) = DilithiumSignK::generate_key_pair().unwrap();
		let (_, vk1) = DilithiumSignK::generate_key_pair().unwrap();

		let number = safety_number(&vk, "123", Some(&vk1), Some("321"));

		assert_eq!(number.len(), 32);

		//test the other way around

		let number_2 = safety_number(&vk1, "321", Some(&vk), Some("123"));

		assert_eq!(number_2.len(), 32);

		assert_ne!(number, number_2);
	}
}
