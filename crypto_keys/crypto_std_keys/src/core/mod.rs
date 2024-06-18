pub(crate) mod asym;
pub(crate) mod hmac;
pub(crate) mod pw_hash;
pub(crate) mod sign;
pub(crate) mod sortable;
pub(crate) mod sym;

pub use self::asym::ecies::{EciesKeyPair, EciesPk, EciesSk, ECIES_OUTPUT};
pub use self::asym::ecies_kyber_hybrid::{EciesKyberHybridKeyPair, EciesKyberHybridPk, EciesKyberHybridSk, ECIES_KYBER_HYBRID_OUTPUT};
pub use self::asym::pqc_kyber::{KyberKeyPair, KyberPk, KyberSk, KYBER_OUTPUT};
pub use self::asym::{PublicKey, SecretKey};
pub use self::hmac::hmac_sha256::{HmacSha256Key, HMAC_SHA256_OUTPUT};
pub use self::hmac::HmacKey;
pub use self::pw_hash::argon2::ARGON_2_OUTPUT;
pub use self::pw_hash::{
	ClientRandomValue,
	DeriveAuthKeyForAuth,
	DeriveMasterKeyForAuth,
	HashedAuthenticationKey,
	PasswordEncryptSalt,
	PwHasherGetter,
};
pub use self::sign::ed25519::{Ed25519KeyPair, Ed25519Sig, Ed25519SignK, Ed25519VerifyK, ED25519_OUTPUT};
pub use self::sign::ed25519_dilithium_hybrid::{
	Ed25519DilithiumHybridKeyPair,
	Ed25519DilithiumHybridSig,
	Ed25519DilithiumHybridSignK,
	Ed25519DilithiumHybridVerifyKey,
	ED25519_DILITHIUM_HYBRID_OUTPUT,
};
pub use self::sign::pqc_dilithium::DILITHIUM_OUTPUT;
pub use self::sign::{SignKey, Signature, VerifyKey};
pub use self::sortable::SortKeys;
pub use self::sym::aes_gcm::{Aes256GcmKey, AES_GCM_OUTPUT};
pub use self::sym::SymmetricKey;

#[macro_export]
macro_rules! try_from_bytes_single_value {
	($st:ty) => {
		impl<'a> TryFrom<&'a [u8]> for $st
		{
			type Error = sentc_crypto_core::Error;

			fn try_from(value: &'a [u8]) -> Result<Self, Self::Error>
			{
				Ok(Self(
					value
						.try_into()
						.map_err(|_| sentc_crypto_core::Error::KeyDecryptFailed)?,
				))
			}
		}
	};
}

#[macro_export]
macro_rules! try_from_bytes_owned_single_value {
	($st:ty) => {
		impl TryFrom<Vec<u8>> for $st
		{
			type Error = sentc_crypto_core::Error;

			fn try_from(value: Vec<u8>) -> Result<Self, Self::Error>
			{
				Ok(Self(
					value
						.try_into()
						.map_err(|_| sentc_crypto_core::Error::KeyDecryptFailed)?,
				))
			}
		}
	};
}

#[macro_export]
macro_rules! into_bytes_single_value {
	($st:ty) => {
		impl Into<Vec<u8>> for $st
		{
			fn into(self) -> Vec<u8>
			{
				Vec::from(self.0)
			}
		}
	};
}

#[macro_export]
macro_rules! as_ref_bytes_single_value {
	($st:ty) => {
		impl AsRef<[u8]> for $st
		{
			fn as_ref(&self) -> &[u8]
			{
				&self.0
			}
		}
	};
}

#[macro_export]
macro_rules! crypto_alg_str_impl {
	($st:ty,$alg:ident) => {
		impl CryptoAlg for $st
		{
			fn get_alg_str(&self) -> &'static str
			{
				$alg
			}
		}
	};
}

#[macro_export]
macro_rules! hybrid_key_import_export {
	($st:ty) => {
		impl $st
		{
			pub fn get_raw_keys(&self) -> (&[u8], &[u8])
			{
				(&self.x, &self.k)
			}

			pub fn from_bytes_owned(bytes_x: Vec<u8>, bytes_k: Vec<u8>) -> Result<Self, Error>
			{
				Ok(Self {
					x: bytes_x
						.try_into()
						.map_err(|_| sentc_crypto_core::Error::KeyDecryptFailed)?,
					k: bytes_k
						.try_into()
						.map_err(|_| sentc_crypto_core::Error::KeyDecryptFailed)?,
				})
			}
		}
	};
}
