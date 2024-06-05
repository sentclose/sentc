use alloc::vec::Vec;

use crate::alg::asym::ecies::{EciesPk, EciesSk};
use crate::alg::asym::ecies_kyber_hybrid::{EciesKyberHybridPk, EciesKyberHybridSk};
use crate::alg::asym::pqc_kyber::{KyberPk, KyberSk};
use crate::cryptomat::{CryptoAlg, Pk, Sig, SignK, Sk, StaticKeyPair, SymKey};
use crate::{Error, Signature};

pub(crate) mod ecies;
pub(crate) mod ecies_kyber_hybrid;
pub(crate) mod pqc_kyber;

pub fn generate_keys() -> Result<(impl Sk, impl Pk), Error>
{
	#[cfg(feature = "ecies_kyber_hybrid")]
	let (sk, pk) = ecies_kyber_hybrid::EciesKyberHybridKeyPair::generate_static_keypair()?;

	#[cfg(feature = "ecies")]
	let (sk, pk) = ecies::EciesKeyPair::generate_static_keypair()?;

	Ok((sk, pk))
}

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

pub enum PublicKey
{
	Ecies(EciesPk),
	Kyber(KyberPk),
	EciesKyberHybrid(EciesKyberHybridPk),
}

crypto_alg_impl!(PublicKey);

impl Pk for PublicKey
{
	fn sign_public_key<S: SignK>(&self, sign_key: &S) -> Result<impl Sig, Error>
	{
		let out: Signature = match self {
			PublicKey::Ecies(k) => k.sign_public_key(sign_key)?.into(),
			PublicKey::Kyber(k) => k.sign_public_key(sign_key)?.into(),
			PublicKey::EciesKyberHybrid(k) => k.sign_public_key(sign_key)?.into(),
		};

		Ok(out)
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

	pub fn decrypt_by_maser_key<M: SymKey>(master_key: &M, encrypted_key: &[u8], alg_str: &str) -> Result<Self, Error>
	{
		let decrypted_bytes = master_key.decrypt(encrypted_key)?;

		Self::from_bytes(&decrypted_bytes, alg_str)
	}
}

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
