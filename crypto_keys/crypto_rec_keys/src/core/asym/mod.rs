use sentc_crypto_core::cryptomat::{CryptoAlg, Pk, SignK, Sk, SkComposer, StaticKeyPair, SymKey, VerifyK};
use sentc_crypto_core::Error;

pub use crate::core::asym::ecies::ECIES_REC_OUTPUT;
use crate::core::asym::ecies::{EciesPk, EciesSk};
pub use crate::core::asym::ecies_ml_kem_hybrid::ECIES_ML_KEM_REC_HYBRID_OUTPUT;
use crate::core::asym::ecies_ml_kem_hybrid::{EciesMlKemHybridPk, EciesMlKemHybridSk};
pub use crate::core::asym::pqc_ml_kem::ML_KEM_REC_OUTPUT;
use crate::core::asym::pqc_ml_kem::{MlKemPk, MlKemSk};

mod ecies;
mod ecies_ml_kem_hybrid;
mod pqc_ml_kem;

macro_rules! deref_macro {
    ($self:expr, $method:ident $(, $args:expr)*) => {
        match $self {
            Self::Ecies(inner) => inner.$method($($args),*),
            Self::MlKem(inner) => inner.$method($($args),*),
			Self::EciesMlKemHybrid(inner) => inner.$method($($args),*),
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

			pub fn ml_kem_from_bytes_owned(bytes: Vec<u8>) -> Self
			{
				Self::MlKem(bytes.into())
			}

			pub fn ecies_ml_kem_hybrid_from_bytes_owned(bytes_x: Vec<u8>, bytes_k: Vec<u8>) -> Result<Self, Error>
			{
				Ok(Self::EciesMlKemHybrid($t::from_bytes(bytes_x, bytes_k)?))
			}
		}
	};
}

#[derive(Clone)]
pub enum PublicKey
{
	Ecies(EciesPk),
	MlKem(MlKemPk),
	EciesMlKemHybrid(EciesMlKemHybridPk),
}

crypto_alg_impl!(PublicKey);
get_inner_key!(PublicKey, EciesMlKemHybridPk);

impl Pk for PublicKey
{
	fn sign_public_key<S: SignK>(&self, sign_key: &S) -> Result<S::Signature, Error>
	{
		deref_macro!(self, sign_public_key, sign_key)
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
	MlKem(MlKemSk),
	EciesMlKemHybrid(EciesMlKemHybridSk),
}

crypto_alg_impl!(SecretKey);
get_inner_key!(SecretKey, EciesMlKemHybridSk);

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
		let bytes = master_key.decrypt(encrypted_key)?;

		let key = match alg_str {
			ECIES_REC_OUTPUT => Self::Ecies(bytes.try_into()?),
			ML_KEM_REC_OUTPUT => Self::MlKem(bytes.into()),
			ECIES_ML_KEM_REC_HYBRID_OUTPUT => Self::EciesMlKemHybrid(bytes.try_into()?),
			_ => return Err(Error::AlgNotFound),
		};

		Ok(key)
	}
}

impl StaticKeyPair for SecretKey
{
	type SecretKey = Self;
	type PublicKey = PublicKey;

	fn generate_static_keypair() -> Result<(Self::SecretKey, Self::PublicKey), Error>
	{
		#[cfg(feature = "ecies_ml_kem_hybrid")]
		let (sk, pk) = EciesMlKemHybridSk::generate_static_keypair()?;

		#[cfg(feature = "ecies")]
		let (sk, pk) = EciesSk::generate_static_keypair()?;

		Ok((sk.into(), pk.into()))
	}
}
