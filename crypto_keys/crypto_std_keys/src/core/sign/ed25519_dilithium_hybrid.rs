use alloc::vec::Vec;

use hmac::digest::Digest;
use pqc_dilithium_edit::{PUBLICKEYBYTES, SECRETKEYBYTES, SIGNBYTES};
use sentc_crypto_core::cryptomat::{Sig, SignK, SignKeyPair, SymKey, VerifyK};
use sentc_crypto_core::{crypto_alg_str_impl, Error};

use crate::core::sign::{SignKey, Signature, VerifyKey};
use crate::{get_rand, hybrid_key_import_export};

pub const ED25519_DILITHIUM_HYBRID_OUTPUT: &str = "ED25519_DILITHIUM_3";

pub struct Ed25519DilithiumHybridSig
{
	x: [u8; 64],
	k: [u8; SIGNBYTES],
}

crypto_alg_str_impl!(Ed25519DilithiumHybridSig, ED25519_DILITHIUM_HYBRID_OUTPUT);
hybrid_key_import_export!(Ed25519DilithiumHybridSig);

impl Into<Signature> for Ed25519DilithiumHybridSig
{
	fn into(self) -> Signature
	{
		Signature::Ed25519DilithiumHybrid(self)
	}
}

impl Into<Vec<u8>> for Ed25519DilithiumHybridSig
{
	fn into(self) -> Vec<u8>
	{
		let mut output = Vec::with_capacity(self.x.len() + self.k.len());
		output.extend_from_slice(&self.x);
		output.extend_from_slice(&self.k);

		output
	}
}

impl Sig for Ed25519DilithiumHybridSig
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

pub struct Ed25519DilithiumHybridVerifyKey
{
	x: [u8; 32],
	k: [u8; PUBLICKEYBYTES],
}

hybrid_key_import_export!(Ed25519DilithiumHybridVerifyKey);
crypto_alg_str_impl!(Ed25519DilithiumHybridVerifyKey, ED25519_DILITHIUM_HYBRID_OUTPUT);

impl Into<VerifyKey> for Ed25519DilithiumHybridVerifyKey
{
	fn into(self) -> VerifyKey
	{
		VerifyKey::Ed25519DilithiumHybrid(self)
	}
}

impl VerifyK for Ed25519DilithiumHybridVerifyKey
{
	type Signature = Ed25519DilithiumHybridSig;

	fn verify<'a>(&self, data_with_sig: &'a [u8]) -> Result<(&'a [u8], bool), Error>
	{
		let (sig, data) = split_sig_and_data(data_with_sig)?;

		//now split the both sig
		let (sig_x, sig_k) = sentc_crypto_core::split_sig_and_data(sig, super::ed25519::SIG_LENGTH)?;

		Ok((data, verify_internally(&self.x, &self.k, sig_x, sig_k, data)?))
	}

	fn verify_only(&self, sig: &Self::Signature, data: &[u8]) -> Result<bool, Error>
	{
		verify_internally(&self.x, &self.k, &sig.x, &sig.k, data)
	}

	fn create_hash<D: Digest>(&self, hasher: &mut D)
	{
		hasher.update(self.x);
		hasher.update(self.k);
	}
}

pub struct Ed25519DilithiumHybridSignK
{
	x: [u8; 32],
	k: [u8; SECRETKEYBYTES],
}

impl<'a> TryFrom<&'a [u8]> for Ed25519DilithiumHybridSignK
{
	type Error = Error;

	fn try_from(value: &'a [u8]) -> Result<Self, Self::Error>
	{
		let x = &value[..32];
		let k = &value[32..];

		Ok(Self {
			x: x.try_into().map_err(|_| Error::KeyDecryptFailed)?,
			k: k.try_into().map_err(|_| Error::KeyDecryptFailed)?,
		})
	}
}

hybrid_key_import_export!(Ed25519DilithiumHybridSignK);
crypto_alg_str_impl!(Ed25519DilithiumHybridSignK, ED25519_DILITHIUM_HYBRID_OUTPUT);

impl Into<SignKey> for Ed25519DilithiumHybridSignK
{
	fn into(self) -> SignKey
	{
		SignKey::Ed25519DilithiumHybrid(self)
	}
}

impl SignK for Ed25519DilithiumHybridSignK
{
	type Signature = Ed25519DilithiumHybridSig;

	fn encrypt_by_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		let key = [&self.x[..], &self.k].concat();

		master_key.encrypt(&key)
	}

	fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>
	{
		let (sig_x, sig_k) = sign_internal(&self.x, &self.k, data)?;

		let mut output = Vec::with_capacity(sig_x.len() + sig_k.len() + data.len());
		output.extend_from_slice(&sig_x);
		output.extend_from_slice(&sig_k);
		output.extend_from_slice(data);

		Ok(output)
	}

	fn sign_only<D: AsRef<[u8]>>(&self, data: D) -> Result<Self::Signature, Error>
	{
		let (x, k) = sign_internal(&self.x, &self.k, data.as_ref())?;

		Ok(Ed25519DilithiumHybridSig {
			x,
			k,
		})
	}
}

pub struct Ed25519DilithiumHybridKeyPair;

impl SignKeyPair for Ed25519DilithiumHybridKeyPair
{
	type SignKey = Ed25519DilithiumHybridSignK;
	type VerifyKey = Ed25519DilithiumHybridVerifyKey;

	fn generate_key_pair() -> Result<(Self::SignKey, Self::VerifyKey), Error>
	{
		let (xsk, xvk) = super::ed25519::generate_key_pair_internally(&mut get_rand())?;
		let (sk, pk) = super::pqc_dilithium::generate_key_pair_internally(&mut get_rand())?;

		Ok((
			Ed25519DilithiumHybridSignK {
				x: xsk,
				k: sk,
			},
			Ed25519DilithiumHybridVerifyKey {
				x: xvk,
				k: pk,
			},
		))
	}
}

pub(crate) fn split_sig_and_data(data_with_sig: &[u8]) -> Result<(&[u8], &[u8]), Error>
{
	sentc_crypto_core::split_sig_and_data(data_with_sig, super::ed25519::SIG_LENGTH + SIGNBYTES)
}

//__________________________________________________________________________________________________
//internally function

fn sign_internal(x: &[u8; 32], k: &[u8; SECRETKEYBYTES], data: &[u8]) -> Result<([u8; 64], [u8; SIGNBYTES]), Error>
{
	//first sign the data with ed25519
	let sig_x = super::ed25519::sign_internally(x, data)?;

	//and then sign it including with the sign with dilithium
	let sig_k = super::pqc_dilithium::sign_internally(k, &[data, &sig_x].concat())?;

	Ok((sig_x, sig_k))
}

#[allow(unused)]
fn split_sig(sig: &[u8]) -> (&[u8], &[u8])
{
	//the first is ed25519
	let ed25519_sig = &sig[..super::ed25519::SIG_LENGTH];
	let dilithium_sig = &sig[super::ed25519::SIG_LENGTH..];

	(ed25519_sig, dilithium_sig)
}

fn verify_internally(x: &[u8; 32], k: &[u8; PUBLICKEYBYTES], sig_x: &[u8], sig_k: &[u8], data: &[u8]) -> Result<bool, Error>
{
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
	use sentc_crypto_core::user::safety_number;
	use sentc_crypto_core::Error::DataToSignTooShort;

	use super::*;
	use crate::core::sign::ed25519::SIG_LENGTH;

	#[test]
	fn test_generate_keypair()
	{
		let _ = Ed25519DilithiumHybridKeyPair::generate_key_pair().unwrap();
	}

	#[test]
	fn test_sign_and_verify()
	{
		let (sk, vk) = Ed25519DilithiumHybridKeyPair::generate_key_pair().unwrap();

		let text = "Hello world üöäéèßê°";

		let data_with_sig = sk.sign(text.as_bytes()).unwrap();

		let (data, check) = vk.verify(&data_with_sig).unwrap();

		assert!(check);
		assert_eq!(data, text.as_bytes());
	}

	#[test]
	fn test_wrong_verify()
	{
		let (_sk, vk) = Ed25519DilithiumHybridKeyPair::generate_key_pair().unwrap();
		let (sk, _vk) = Ed25519DilithiumHybridKeyPair::generate_key_pair().unwrap();

		let text = "Hello world üöäéèßê°";

		let data_with_sig = sk.sign(text.as_bytes()).unwrap();

		let (data, check) = vk.verify(&data_with_sig).unwrap();

		assert!(!check);
		assert_eq!(data, text.as_bytes());
	}

	#[test]
	fn test_too_short_sig_bytes()
	{
		let (sk, vk) = Ed25519DilithiumHybridKeyPair::generate_key_pair().unwrap();
		let text = "Hello world üöäéèßê°";

		let data_with_sig = sk.sign(text.as_bytes()).unwrap();

		let data_with_sig = &data_with_sig[..31];

		let check_result = vk.verify(data_with_sig);

		assert!(matches!(check_result, Err(DataToSignTooShort)));
	}

	#[test]
	fn test_wrong_sig_bytes()
	{
		let (sk, vk) = Ed25519DilithiumHybridKeyPair::generate_key_pair().unwrap();
		let text = "Hello world üöäéèßê°";

		let data_with_sig = sk.sign(text.as_bytes()).unwrap();

		let data_with_sig = &data_with_sig[..SIGNBYTES + SIG_LENGTH + 2];

		let (_data, check) = vk.verify(data_with_sig).unwrap();

		assert!(!check);
	}

	#[test]
	fn test_safety_number()
	{
		let (_sk, vk) = Ed25519DilithiumHybridKeyPair::generate_key_pair().unwrap();

		let number = safety_number(&vk, "123", None, None);

		assert_eq!(number.len(), 32);
	}

	#[test]
	fn test_combined_safety_number()
	{
		let (_, vk) = Ed25519DilithiumHybridKeyPair::generate_key_pair().unwrap();
		let (_, vk1) = Ed25519DilithiumHybridKeyPair::generate_key_pair().unwrap();

		let number = safety_number(&vk, "123", Some(&vk1), Some("321"));

		assert_eq!(number.len(), 32);

		//test the other way around

		let number_2 = safety_number(&vk1, "321", Some(&vk), Some("123"));

		assert_eq!(number_2.len(), 32);

		assert_ne!(number, number_2);
	}
}
