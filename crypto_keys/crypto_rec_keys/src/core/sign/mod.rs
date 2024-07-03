#![allow(clippy::large_enum_variant)]

use digest::Digest;
use sentc_crypto_core::cryptomat::{CryptoAlg, Sig, SignK, SignKeyComposer, SignKeyPair, SymKey, VerifyK};
use sentc_crypto_core::Error;
pub use sentc_crypto_fips_keys::core::sign::FIPS_OPENSSL_ED25519;
use sentc_crypto_fips_keys::core::sign::{Ed25519FIPSSig, Ed25519FIPSSignK, Ed25519FIPSVerifyK};

pub use crate::core::sign::ed25519_ml_dsa_hybrid::ED25519_ML_DSA_HYBRID_REC_OUTPUT;
use crate::core::sign::ed25519_ml_dsa_hybrid::{Ed25519MlDsaHybridSig, Ed25519MlDsaHybridSignK, Ed25519MlDsaHybridVerifyKey};
pub use crate::core::sign::pqc_ml_dsa::ML_DSA_REC_OUTPUT;
use crate::core::sign::pqc_ml_dsa::{MlDsaSig, MlDsaSk, MlDsaVk};

mod ed25519_ml_dsa_hybrid;
mod pqc_ml_dsa;

mod ed25519
{
	pub use sentc_crypto_fips_keys::core::sign::*;
}

macro_rules! deref_macro {
    ($self:expr, $method:ident $(, $args:expr)*) => {
        match $self {
            Self::Ed25519(inner) => inner.$method($($args),*),
            Self::MlDsa(inner) => inner.$method($($args),*),
			Self::Ed25519MlDsaHybrid(inner) => inner.$method($($args),*),
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

			pub fn ml_dsa_from_bytes_owned(bytes: Vec<u8>) -> Self
			{
				Self::MlDsa(bytes.into())
			}

			pub fn ed25519_ml_dsa_hybrid_from_bytes_owned(bytes_x: Vec<u8>, bytes_k: Vec<u8>) -> Result<Self, Error>
			{
				Ok(Self::Ed25519MlDsaHybrid($t::from_bytes(bytes_x, bytes_k)?))
			}
		}
	};
}

pub enum Signature
{
	Ed25519(Ed25519FIPSSig),
	MlDsa(MlDsaSig),
	Ed25519MlDsaHybrid(Ed25519MlDsaHybridSig),
}
crypto_alg_impl!(Signature);

impl Signature
{
	pub fn ed25519_from_bytes_owned(bytes: Vec<u8>) -> Self
	{
		Self::Ed25519(bytes.into())
	}

	pub fn ml_dsa_from_bytes_owned(bytes: Vec<u8>) -> Self
	{
		Self::MlDsa(bytes.into())
	}

	pub fn ed25519_ml_dsa_hybrid_from_bytes_owned(bytes_x: Vec<u8>, bytes_k: Vec<u8>) -> Self
	{
		Self::Ed25519MlDsaHybrid(Ed25519MlDsaHybridSig::from_bytes_owned(bytes_x, bytes_k))
	}

	pub fn split_sig_and_data<'a>(alg: &str, data_with_sign: &'a [u8]) -> Result<(&'a [u8], &'a [u8]), Error>
	{
		match alg {
			FIPS_OPENSSL_ED25519 => ed25519::split_sig_and_data(data_with_sign),
			ML_DSA_REC_OUTPUT => pqc_ml_dsa::split_sig_and_data(data_with_sign),
			ED25519_ML_DSA_HYBRID_REC_OUTPUT => ed25519_ml_dsa_hybrid::split_sig_and_data(data_with_sign),
			_ => Err(Error::AlgNotFound),
		}
	}
}

impl Into<Vec<u8>> for Signature
{
	fn into(self) -> Vec<u8>
	{
		deref_macro!(self, into)
	}
}

impl Sig for Signature {}

impl From<Ed25519FIPSSig> for Signature
{
	fn from(value: Ed25519FIPSSig) -> Self
	{
		Self::Ed25519(value)
	}
}

pub enum SignKey
{
	Ed25519(Ed25519FIPSSignK),
	MlDsa(MlDsaSk),
	Ed25519MlDsaHybrid(Ed25519MlDsaHybridSignK),
}
crypto_alg_impl!(SignKey);
get_inner_key!(SignKey, Ed25519MlDsaHybridSignK);

impl From<Ed25519FIPSSignK> for SignKey
{
	fn from(value: Ed25519FIPSSignK) -> Self
	{
		Self::Ed25519(value)
	}
}

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
			Self::MlDsa(inner) => inner.sign_only(data)?.into(),
			Self::Ed25519MlDsaHybrid(inner) => inner.sign_only(data)?.into(),
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
		#[cfg(feature = "ed25519_ml_dsa_hybrid")]
		let (sk, vk) = Ed25519MlDsaHybridSignK::generate_key_pair()?;

		#[cfg(feature = "ed25519")]
		let (sk, vk) = Ed25519FIPSSignK::generate_key_pair()?;

		Ok((sk.into(), vk.into()))
	}
}

impl SignKeyComposer for SignKey
{
	type Key = Self;

	fn decrypt_by_master_key<M: SymKey>(master_key: &M, encrypted_key: &[u8], alg_str: &str) -> Result<Self::Key, Error>
	{
		let key = master_key.decrypt(encrypted_key)?;

		let key = match alg_str {
			FIPS_OPENSSL_ED25519 => Self::Ed25519(key.try_into()?),
			ML_DSA_REC_OUTPUT => Self::MlDsa(key.into()),
			ED25519_ML_DSA_HYBRID_REC_OUTPUT => Self::Ed25519MlDsaHybrid(key.try_into()?),
			_ => return Err(Error::AlgNotFound),
		};

		Ok(key)
	}
}

pub enum VerifyKey
{
	Ed25519(Ed25519FIPSVerifyK),
	MlDsa(MlDsaVk),
	Ed25519MlDsaHybrid(Ed25519MlDsaHybridVerifyKey),
}
crypto_alg_impl!(VerifyKey);
get_inner_key!(VerifyKey, Ed25519MlDsaHybridVerifyKey);

impl From<Ed25519FIPSVerifyK> for VerifyKey
{
	fn from(value: Ed25519FIPSVerifyK) -> Self
	{
		Self::Ed25519(value)
	}
}

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
			(Self::MlDsa(inner), Signature::MlDsa(s)) => inner.verify_only(s, data),
			(Self::Ed25519MlDsaHybrid(inner), Signature::Ed25519MlDsaHybrid(s)) => inner.verify_only(s, data),
			_ => Err(Error::AlgNotFound),
		}
	}

	fn create_hash<D: Digest>(&self, hasher: &mut D)
	{
		deref_macro!(self, create_hash, hasher)
	}
}
