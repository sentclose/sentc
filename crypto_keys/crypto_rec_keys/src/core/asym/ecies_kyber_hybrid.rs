#![allow(clippy::large_enum_variant)]

use openssl::pkey::{PKey, Private, Public};
use pqcrypto_kyber::kyber768::{PublicKey, SecretKey};
use pqcrypto_traits::kem::{PublicKey as PkT, SecretKey as SkT};
use sentc_crypto_core::cryptomat::{Pk, SignK, Sk, StaticKeyPair, SymKey, VerifyK};
use sentc_crypto_core::{crypto_alg_str_impl, Error};

use crate::core::asym::ecies::{import_pk, import_sk};
use crate::core::{export_pk, export_sk};
use crate::{hybrid_import_export, hybrid_sk_from_bytes};

pub const ECIES_KYBER_REC_HYBRID_OUTPUT: &str = "ECIES-ed25519_KYBER_768_REC";

#[derive(Clone)]
pub struct EciesKyberHybridPk
{
	x: PKey<Public>,
	k: PublicKey,
}

crypto_alg_str_impl!(EciesKyberHybridPk, ECIES_KYBER_REC_HYBRID_OUTPUT);
hybrid_import_export!(EciesKyberHybridPk, import_pk, export_pk, PublicKey);

impl Into<super::PublicKey> for EciesKyberHybridPk
{
	fn into(self) -> super::PublicKey
	{
		super::PublicKey::EciesKyberHybrid(self)
	}
}

impl Pk for EciesKyberHybridPk
{
	fn sign_public_key<S: SignK>(&self, sign_key: &S) -> Result<S::Signature, Error>
	{
		let k = [&export_pk(&self.x)?, self.k.as_bytes()].concat();

		sign_key.sign_only(k)
	}

	fn verify_public_key<V: VerifyK>(&self, verify_key: &V, sig: &V::Signature) -> Result<bool, Error>
	{
		let k = [&export_pk(&self.x)?, self.k.as_bytes()].concat();

		verify_key.verify_only(sig, &k)
	}

	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>
	{
		let encrypted = super::ecies::encrypt_internally(&self.x, data)?;

		let encrypted = super::pqc_kyber::encrypt_internally(&self.k, &encrypted)?;

		Ok(encrypted)
	}
}

pub struct EciesKyberHybridSk
{
	x: PKey<Private>,
	k: SecretKey,
}

crypto_alg_str_impl!(EciesKyberHybridSk, ECIES_KYBER_REC_HYBRID_OUTPUT);
hybrid_import_export!(EciesKyberHybridSk, import_sk, export_sk, SecretKey);
hybrid_sk_from_bytes!(EciesKyberHybridSk, import_sk, SecretKey);

impl Into<super::SecretKey> for EciesKyberHybridSk
{
	fn into(self) -> super::SecretKey
	{
		super::SecretKey::EciesKyberHybrid(self)
	}
}

impl Sk for EciesKyberHybridSk
{
	fn encrypt_by_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		let k = [&export_sk(&self.x)?, self.k.as_bytes()].concat();

		master_key.encrypt(&k)
	}

	fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
	{
		let decrypted = super::pqc_kyber::decrypt_internally(&self.k, ciphertext)?;

		let decrypted = super::ecies::decrypt_internally(&self.x, &decrypted)?;

		Ok(decrypted)
	}
}

impl StaticKeyPair for EciesKyberHybridSk
{
	type SecretKey = Self;
	type PublicKey = EciesKyberHybridPk;

	fn generate_static_keypair() -> Result<(Self::SecretKey, Self::PublicKey), Error>
	{
		let (x_pk, x_sk) = super::ecies::generate_key_pair()?;
		let (k_sk, k_pk) = super::pqc_kyber::generate_keypair();

		Ok((
			Self {
				x: x_sk,
				k: k_sk,
			},
			EciesKyberHybridPk {
				x: x_pk,
				k: k_pk,
			},
		))
	}
}

#[cfg(test)]
mod test
{
	use core::str::from_utf8;

	use sentc_crypto_core::Error::{DecryptionFailed, DecryptionFailedCiphertextShort};

	use super::*;

	#[test]
	fn test_key_gen()
	{
		let _ = EciesKyberHybridSk::generate_static_keypair().unwrap();
	}

	#[test]
	fn test_encrypt_and_decrypt()
	{
		let (sk, pk) = EciesKyberHybridSk::generate_static_keypair().unwrap();

		let text = "Hello world üöäéèßê°";

		let encrypted = pk.encrypt(text.as_bytes()).unwrap();

		let decrypted = sk.decrypt(&encrypted).unwrap();

		assert_eq!(text.as_bytes(), decrypted);

		let decrypted_text = from_utf8(&decrypted).unwrap();

		assert_eq!(text, decrypted_text);
	}

	#[test]
	fn test_not_decrypt_with_wrong_key()
	{
		let (_sk, pk) = EciesKyberHybridSk::generate_static_keypair().unwrap();

		let (sk, _pk) = EciesKyberHybridSk::generate_static_keypair().unwrap();

		let text = "Hello world üöäéèßê°";

		let encrypted = pk.encrypt(text.as_bytes()).unwrap();

		let decrypted_result = sk.decrypt(&encrypted);

		assert!(matches!(decrypted_result, Err(DecryptionFailed)));
	}

	#[test]
	fn test_not_decrypt_with_wrong_ciphertext()
	{
		let (sk, pk) = EciesKyberHybridSk::generate_static_keypair().unwrap();

		let text = "Hello world üöäéèßê°";

		let encrypted = pk.encrypt(text.as_bytes()).unwrap();

		//too short ciphertext: text must be min 32 long, output was 88 long
		let encrypted = &encrypted[..(encrypted.len() - 156)];

		let decrypted_result = sk.decrypt(encrypted);

		assert!(matches!(decrypted_result, Err(DecryptionFailedCiphertextShort)));
	}
}
