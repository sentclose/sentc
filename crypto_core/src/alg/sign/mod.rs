use alloc::vec::Vec;
use core::ops::Deref;

use sha2::{Digest, Sha256};

use crate::alg::sign::ed25519::Ed25519SignK;
use crate::alg::sign::ed25519_dilithium_hybrid::Ed25519DilithiumHybridSignK;
use crate::alg::sign::pqc_dilithium::{DilithiumSig, DilithiumSignKey, DilithiumVerifyKey};
use crate::cryptomat::{CryptoAlg, Sig, SignK, SignKeyPair, SymKey, VerifyK};
use crate::{Ed25519DilithiumHybridSig, Ed25519DilithiumHybridVerifyKey, Ed25519Sig, Ed25519VerifyK, Error};

pub(crate) mod ed25519;
pub(crate) mod ed25519_dilithium_hybrid;
pub(crate) mod pqc_dilithium;

pub fn generate_keys() -> Result<(impl SignK, impl VerifyK), Error>
{
	#[cfg(feature = "ed25519_dilithium_hybrid")]
	let (sk, vk) = ed25519_dilithium_hybrid::Ed25519DilithiumHybridKeyPair::generate_key_pair()?;

	#[cfg(feature = "ed25519")]
	let (sk, vk) = ed25519::Ed25519KeyPair::generate_key_pair()?;

	Ok((sk, vk))
}

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

pub struct SafetyNumber<'a, Vk: VerifyK>
{
	pub verify_key: &'a Vk,
	pub user_info: &'a str,
}

pub(crate) fn safety_number<Vk: VerifyK>(user_1: SafetyNumber<Vk>, user_2: Option<SafetyNumber<Vk>>) -> Vec<u8>
{
	let mut hasher = Sha256::new();

	user_1.verify_key.create_hash(&mut hasher);

	hasher.update(user_1.user_info.as_bytes());

	if let Some(u_2) = user_2 {
		u_2.verify_key.create_hash(&mut hasher);

		hasher.update(u_2.user_info.as_bytes());
	}

	let number_bytes = hasher.finalize();

	number_bytes.to_vec()
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

	pub fn decrypt_by_master_key<M: SymKey>(master_key: &M, encrypted_key: &[u8], alg_str: &str) -> Result<Self, Error>
	{
		let key = master_key.decrypt(encrypted_key)?;

		Self::from_bytes(&key, alg_str)
	}

	fn deref(&self) -> &impl SignK
	{
		match self {
			Self::Ed25519(k) => k,
			Self::Dilithium(k) => k,
			Self::Ed25519DilithiumHybrid(k) => k,
		}
	}
}

impl CryptoAlg for SignKey
{
	fn get_alg_str(&self) -> &'static str
	{
		self.deref().get_alg_str()
	}
}

impl SignK for SignKey
{
	fn encrypt_by_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		self.deref().encrypt_by_master_key(master_key)
	}

	fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>
	{
		self.deref().sign(data)
	}

	fn sign_only(&self, data: &[u8]) -> Result<impl Sig, Error>
	{
		self.deref().sign_only(data)
	}
}

pub enum VerifyKey
{
	Ed25519(Ed25519VerifyK),
	Dilithium(DilithiumVerifyKey),
	Ed25519DilithiumHybrid(Ed25519DilithiumHybridVerifyKey),
}

impl VerifyKey
{
	fn deref(&self) -> &impl VerifyK
	{
		match self {
			Self::Ed25519(k) => k,
			Self::Dilithium(k) => k,
			Self::Ed25519DilithiumHybrid(k) => k,
		}
	}
}

impl CryptoAlg for VerifyKey
{
	fn get_alg_str(&self) -> &'static str
	{
		self.deref().get_alg_str()
	}
}

impl VerifyK for VerifyKey
{
	fn verify<'a>(&self, data_with_sig: &'a [u8]) -> Result<(&'a [u8], bool), Error>
	{
		self.deref().verify(data_with_sig)
	}

	fn verify_only(&self, sig: &[u8], data: &[u8]) -> Result<bool, Error>
	{
		self.deref().verify_only(sig, data)
	}

	fn create_hash<D: Digest>(&self, hasher: &mut D)
	{
		self.deref().create_hash(hasher)
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
	fn deref(&self) -> &impl Sig
	{
		match self {
			Self::Ed25519(k) => k,
			Self::Dilithium(k) => k,
			Self::Ed25519DilithiumHybrid(k) => k,
		}
	}
}

impl CryptoAlg for Signature
{
	fn get_alg_str(&self) -> &'static str
	{
		self.deref().get_alg_str()
	}
}

impl Sig for Signature
{
	fn split_sig_and_data<'a>(&self) -> Result<(&'a [u8], &'a [u8]), Error>
	{
		self.deref().split_sig_and_data()
	}

	fn get_raw(&self) -> &[u8]
	{
		self.deref().get_raw()
	}
}
