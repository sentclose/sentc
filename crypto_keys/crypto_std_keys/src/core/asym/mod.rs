use alloc::vec::Vec;

use sentc_crypto_core::cryptomat::{CryptoAlg, Pk, SignK, Sk, SkComposer, StaticKeyPair, SymKey, VerifyK};
use sentc_crypto_core::Error;

use crate::core::asym::ecies::{EciesPk, EciesSk};
use crate::core::asym::ecies_kyber_hybrid::{EciesKyberHybridPk, EciesKyberHybridSk};
use crate::core::asym::pqc_kyber::{KyberPk, KyberSk};

pub(crate) mod ecies;
pub(crate) mod ecies_kyber_hybrid;
pub(crate) mod pqc_kyber;

macro_rules! deref_macro {
    ($self:expr, $method:ident $(, $args:expr)*) => {
        match $self {
            Self::Ecies(inner) => inner.$method($($args),*),
            Self::Kyber(inner) => inner.$method($($args),*),
			Self::EciesKyberHybrid(inner) => inner.$method($($args),*),
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
			pub fn ecies_from_bytes_owned(bytes: Vec<u8>) -> Result<Self, Error>
			{
				Ok(Self::Ecies(bytes.try_into()?))
			}

			pub fn kyber_from_bytes_owned(bytes: Vec<u8>) -> Result<Self, Error>
			{
				Ok(Self::Kyber(bytes.try_into()?))
			}

			pub fn ecies_kyber_hybrid_from_bytes_owned(bytes_x: Vec<u8>, bytes_k: Vec<u8>) -> Result<Self, Error>
			{
				Ok(Self::EciesKyberHybrid($t::from_bytes_owned(bytes_x, bytes_k)?))
			}
		}
	};
}

#[derive(Clone)]
pub enum PublicKey
{
	Ecies(EciesPk),
	Kyber(KyberPk),
	EciesKyberHybrid(EciesKyberHybridPk),
}

get_inner_key!(PublicKey, EciesKyberHybridPk);
crypto_alg_impl!(PublicKey);

impl Pk for PublicKey
{
	fn sign_public_key<S: SignK>(&self, sign_key: &S) -> Result<S::Signature, Error>
	{
		let out = match self {
			PublicKey::Ecies(k) => k.sign_public_key(sign_key)?,
			PublicKey::Kyber(k) => k.sign_public_key(sign_key)?,
			PublicKey::EciesKyberHybrid(k) => k.sign_public_key(sign_key)?,
		};

		Ok(out)
	}

	fn verify_public_key<V: VerifyK>(&self, verify_key: &V, sig: &V::Signature) -> Result<bool, Error>
	{
		deref_macro!(self, verify_public_key, verify_key, sig)
	}

	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>
	{
		deref_macro!(self, encrypt, data)
	}
}

pub enum SecretKey
{
	Ecies(EciesSk),
	Kyber(KyberSk),
	EciesKyberHybrid(EciesKyberHybridSk),
}

impl SecretKey
{
	pub fn from_bytes(bytes: &[u8], alg_str: &str) -> Result<Self, Error>
	{
		let key = match alg_str {
			ecies::ECIES_OUTPUT => Self::Ecies(bytes.try_into()?),
			pqc_kyber::KYBER_OUTPUT => Self::Kyber(bytes.try_into()?),
			ecies_kyber_hybrid::ECIES_KYBER_HYBRID_OUTPUT => Self::EciesKyberHybrid(bytes.try_into()?),
			_ => return Err(Error::AlgNotFound),
		};

		Ok(key)
	}
}

get_inner_key!(SecretKey, EciesKyberHybridSk);
crypto_alg_impl!(SecretKey);

impl Sk for SecretKey
{
	fn encrypt_by_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		deref_macro!(self, encrypt_by_master_key, master_key)
	}

	fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
	{
		deref_macro!(self, decrypt, ciphertext)
	}
}

impl SkComposer for SecretKey
{
	type SecretKey = Self;

	fn decrypt_by_master_key<M: SymKey>(master_key: &M, encrypted_key: &[u8], alg_str: &str) -> Result<Self::SecretKey, Error>
	{
		let decrypted_bytes = master_key.decrypt(encrypted_key)?;

		Self::from_bytes(&decrypted_bytes, alg_str)
	}
}

impl StaticKeyPair for SecretKey
{
	type SecretKey = Self;
	type PublicKey = PublicKey;

	fn generate_static_keypair() -> Result<(Self::SecretKey, Self::PublicKey), Error>
	{
		#[cfg(feature = "ecies_kyber_hybrid")]
		let (sk, pk) = ecies_kyber_hybrid::EciesKyberHybridKeyPair::generate_static_keypair()?;

		#[cfg(feature = "ecies")]
		let (sk, pk) = ecies::EciesKeyPair::generate_static_keypair()?;

		Ok((sk.into(), pk.into()))
	}
}
