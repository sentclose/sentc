use alloc::vec::Vec;

use sha2::Digest;

use crate::alg::sign::ed25519::Ed25519SignK;
use crate::alg::sign::ed25519_dilithium_hybrid::Ed25519DilithiumHybridSignK;
use crate::alg::sign::pqc_dilithium::{DilithiumSig, DilithiumSignKey, DilithiumVerifyKey};
use crate::cryptomat::{CryptoAlg, Sig, SignK, SignKeyComposer, SignKeyPair, SymKey, VerifyK};
use crate::{Ed25519DilithiumHybridSig, Ed25519DilithiumHybridVerifyKey, Ed25519Sig, Ed25519VerifyK, Error};

pub(crate) mod ed25519;
pub(crate) mod ed25519_dilithium_hybrid;
pub(crate) mod pqc_dilithium;

pub(crate) fn split_sig_and_data(data_with_sig: &[u8], len: usize) -> Result<(&[u8], &[u8]), Error>
{
	if data_with_sig.len() <= len {
		return Err(Error::DataToSignTooShort);
	}

	//split sign and data
	let sig = &data_with_sig[..len];
	let data = &data_with_sig[len..];

	Ok((sig, data))
}

macro_rules! deref_macro {
    ($self:expr, $method:ident $(, $args:expr)*) => {
        match $self {
            Self::Ed25519(inner) => inner.$method($($args),*),
            Self::Dilithium(inner) => inner.$method($($args),*),
			Self::Ed25519DilithiumHybrid(inner) => inner.$method($($args),*),
        }
    };
}

macro_rules! crypto_alg_impl {
	($name:ty) => {
		impl CryptoAlg for $name
		{
			fn get_alg_str(&self) -> &'static str
			{
				deref_macro!(self, get_alg_str)
			}
		}
	};
}

macro_rules! get_inner_key {
	($st:ty,$t:ident) => {
		impl $st
		{
			pub fn ed25519_from_bytes_owned(bytes: Vec<u8>) -> Result<Self, Error>
			{
				Ok(Self::Ed25519(bytes.try_into()?))
			}

			pub fn dilithium_from_bytes_owned(bytes: Vec<u8>) -> Result<Self, Error>
			{
				Ok(Self::Dilithium(bytes.try_into()?))
			}

			pub fn ed25519_dilithium_hybrid_from_bytes_owned(bytes_x: Vec<u8>, bytes_k: Vec<u8>) -> Result<Self, Error>
			{
				Ok(Self::Ed25519DilithiumHybrid($t::from_bytes_owned(bytes_x, bytes_k)?))
			}
		}
	};
}

pub enum SignKey
{
	Ed25519(Ed25519SignK),
	Dilithium(DilithiumSignKey),
	Ed25519DilithiumHybrid(Ed25519DilithiumHybridSignK),
}

impl SignKey
{
	pub fn from_bytes(bytes: &[u8], alg_str: &str) -> Result<Self, Error>
	{
		let key = match alg_str {
			ed25519::ED25519_OUTPUT => Self::Ed25519(bytes.try_into()?),
			pqc_dilithium::DILITHIUM_OUTPUT => Self::Dilithium(bytes.try_into()?),
			ed25519_dilithium_hybrid::ED25519_DILITHIUM_HYBRID_OUTPUT => Self::Ed25519DilithiumHybrid(bytes.try_into()?),
			_ => return Err(Error::AlgNotFound),
		};

		Ok(key)
	}
}

get_inner_key!(SignKey, Ed25519DilithiumHybridSignK);
crypto_alg_impl!(SignKey);

impl SignK for SignKey
{
	type Signature = Signature;

	fn encrypt_by_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		deref_macro!(self, encrypt_by_master_key, master_key)
	}

	fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>
	{
		deref_macro!(self, sign, data)
	}

	fn sign_only<D: AsRef<[u8]>>(&self, data: D) -> Result<Self::Signature, Error>
	{
		let out: Signature = match self {
			Self::Ed25519(inner) => inner.sign_only(data)?.into(),
			Self::Dilithium(inner) => inner.sign_only(data)?.into(),
			Self::Ed25519DilithiumHybrid(inner) => inner.sign_only(data)?.into(),
		};

		Ok(out)
	}
}

impl SignKeyPair for SignKey
{
	type SignKey = Self;
	type VerifyKey = VerifyKey;

	fn generate_key_pair() -> Result<(Self::SignKey, Self::VerifyKey), Error>
	{
		#[cfg(feature = "ed25519_dilithium_hybrid")]
		let (sk, vk) = ed25519_dilithium_hybrid::Ed25519DilithiumHybridKeyPair::generate_key_pair()?;

		#[cfg(feature = "ed25519")]
		let (sk, vk) = ed25519::Ed25519KeyPair::generate_key_pair()?;

		Ok((sk.into(), vk.into()))
	}
}

impl SignKeyComposer for SignKey
{
	type Key = Self;

	fn decrypt_by_master_key<M: SymKey>(master_key: &M, encrypted_key: &[u8], alg_str: &str) -> Result<Self::Key, Error>
	{
		let key = master_key.decrypt(encrypted_key)?;

		Self::from_bytes(&key, alg_str)
	}
}

pub enum VerifyKey
{
	Ed25519(Ed25519VerifyK),
	Dilithium(DilithiumVerifyKey),
	Ed25519DilithiumHybrid(Ed25519DilithiumHybridVerifyKey),
}

get_inner_key!(VerifyKey, Ed25519DilithiumHybridVerifyKey);
crypto_alg_impl!(VerifyKey);

impl VerifyK for VerifyKey
{
	type Signature = Signature;

	fn verify<'a>(&self, data_with_sig: &'a [u8]) -> Result<(&'a [u8], bool), Error>
	{
		deref_macro!(self, verify, data_with_sig)
	}

	fn verify_only(&self, sig: &Self::Signature, data: &[u8]) -> Result<bool, Error>
	{
		match (self, sig) {
			(Self::Ed25519(inner), Signature::Ed25519(s)) => inner.verify_only(s, data),
			(Self::Dilithium(inner), Signature::Dilithium(s)) => inner.verify_only(s, data),
			(Self::Ed25519DilithiumHybrid(inner), Signature::Ed25519DilithiumHybrid(s)) => inner.verify_only(s, data),
			_ => Err(Error::AlgNotFound),
		}
	}

	fn create_hash<D: Digest>(&self, hasher: &mut D)
	{
		deref_macro!(self, create_hash, hasher)
	}
}

pub enum Signature
{
	Ed25519(Ed25519Sig),
	Dilithium(DilithiumSig),
	Ed25519DilithiumHybrid(Ed25519DilithiumHybridSig),
}

impl Signature
{
	pub fn split_sig_and_data<'a>(alg: &str, data_with_sign: &'a [u8]) -> Result<(&'a [u8], &'a [u8]), Error>
	{
		match alg {
			ed25519::ED25519_OUTPUT => ed25519::split_sig_and_data(data_with_sign),
			pqc_dilithium::DILITHIUM_OUTPUT => pqc_dilithium::split_sig_and_data(data_with_sign),
			ed25519_dilithium_hybrid::ED25519_DILITHIUM_HYBRID_OUTPUT => ed25519_dilithium_hybrid::split_sig_and_data(data_with_sign),
			_ => Err(Error::AlgNotFound),
		}
	}
}

crypto_alg_impl!(Signature);
get_inner_key!(Signature, Ed25519DilithiumHybridSig);

impl Into<Vec<u8>> for Signature
{
	fn into(self) -> Vec<u8>
	{
		deref_macro!(self, into)
	}
}

impl Sig for Signature
{
	// fn split_sig_and_data<'a>(&self) -> Result<(&'a [u8], &'a [u8]), Error>
	// {
	// 	deref_macro!(self, split_sig_and_data)
	// }
	//
	// fn get_raw(&self) -> &[u8]
	// {
	// 	deref_macro!(self, get_raw)
	// }
}
