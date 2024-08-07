use alloc::vec::Vec;

use pqc_kyber_edit::{KYBER_PUBLICKEYBYTES, KYBER_SECRETKEYBYTES};
use sentc_crypto_core::cryptomat::{Pk, SignK, Sk, StaticKeyPair, SymKey, VerifyK};
use sentc_crypto_core::{crypto_alg_str_impl, Error};

use crate::core::asym::{PublicKey, SecretKey};
use crate::{get_rand, hybrid_key_import_export};

pub const ECIES_KYBER_HYBRID_OUTPUT: &str = "ECIES-ed25519_KYBER_768";

#[derive(Clone)]
pub struct EciesKyberHybridPk
{
	x: [u8; 32],
	k: [u8; KYBER_PUBLICKEYBYTES],
}

hybrid_key_import_export!(EciesKyberHybridPk);
crypto_alg_str_impl!(EciesKyberHybridPk, ECIES_KYBER_HYBRID_OUTPUT);

impl Into<PublicKey> for EciesKyberHybridPk
{
	fn into(self) -> PublicKey
	{
		PublicKey::EciesKyberHybrid(self)
	}
}

impl Pk for EciesKyberHybridPk
{
	fn sign_public_key<S: SignK>(&self, sign_key: &S) -> Result<S::Signature, Error>
	{
		let k = [&self.x[..], &self.k[..]].concat();

		sign_key.sign_only(k)
	}

	fn verify_public_key<V: VerifyK>(&self, verify_key: &V, sig: &V::Signature) -> Result<bool, Error>
	{
		let k = [&self.x[..], &self.k[..]].concat();

		verify_key.verify_only(sig, &k)
	}

	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>
	{
		//encrypt with ecies first then with kyber

		let encrypted = super::ecies::encrypt_internally(&self.x.into(), data, &mut get_rand())?;

		let encrypted = super::pqc_kyber::encrypt_internally(&self.k, &encrypted, &mut get_rand())?;

		Ok(encrypted)
	}
}

pub struct EciesKyberHybridSk
{
	x: [u8; 32],
	k: [u8; KYBER_SECRETKEYBYTES],
}

impl TryFrom<Vec<u8>> for EciesKyberHybridSk
{
	type Error = Error;

	fn try_from(value: Vec<u8>) -> Result<Self, Self::Error>
	{
		let x = &value[..32];
		let k = &value[32..];

		Ok(Self {
			x: x.try_into().map_err(|_| Error::KeyDecryptFailed)?,
			k: k.try_into().map_err(|_| Error::KeyDecryptFailed)?,
		})
	}
}

hybrid_key_import_export!(EciesKyberHybridSk);
crypto_alg_str_impl!(EciesKyberHybridSk, ECIES_KYBER_HYBRID_OUTPUT);

impl Into<SecretKey> for EciesKyberHybridSk
{
	fn into(self) -> SecretKey
	{
		SecretKey::EciesKyberHybrid(self)
	}
}

impl Sk for EciesKyberHybridSk
{
	fn encrypt_by_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		let private_key = [&self.x[..], &self.k].concat();

		master_key.encrypt(&private_key)
	}

	fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
	{
		let decrypted = super::pqc_kyber::decrypt_internally(&self.k, ciphertext)?;

		let decrypted = super::ecies::decrypt_internally(&self.x.into(), &decrypted)?;

		Ok(decrypted)
	}
}

pub struct EciesKyberHybridKeyPair;

impl StaticKeyPair for EciesKyberHybridKeyPair
{
	type SecretKey = EciesKyberHybridSk;
	type PublicKey = EciesKyberHybridPk;

	fn generate_static_keypair() -> Result<(Self::SecretKey, Self::PublicKey), Error>
	{
		let (x_sk, x_pk) = super::ecies::generate_static_keypair_internally(&mut get_rand());
		let (k_sk, k_pk) = super::pqc_kyber::generate_keypair_internally(&mut get_rand())?;

		Ok((
			EciesKyberHybridSk {
				x: x_sk.to_bytes(),
				k: k_sk,
			},
			EciesKyberHybridPk {
				x: x_pk.to_bytes(),
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
		let _ = EciesKyberHybridKeyPair::generate_static_keypair().unwrap();
	}

	#[test]
	fn test_encrypt_and_decrypt()
	{
		let (sk, pk) = EciesKyberHybridKeyPair::generate_static_keypair().unwrap();

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
		let (_sk, pk) = EciesKyberHybridKeyPair::generate_static_keypair().unwrap();

		let (sk, _pk) = EciesKyberHybridKeyPair::generate_static_keypair().unwrap();

		let text = "Hello world üöäéèßê°";

		let encrypted = pk.encrypt(text.as_bytes()).unwrap();

		let decrypted_result = sk.decrypt(&encrypted);

		assert!(matches!(decrypted_result, Err(DecryptionFailed)));
	}

	#[test]
	fn test_not_decrypt_with_wrong_ciphertext()
	{
		let (sk, pk) = EciesKyberHybridKeyPair::generate_static_keypair().unwrap();

		let text = "Hello world üöäéèßê°";

		let encrypted = pk.encrypt(text.as_bytes()).unwrap();

		//too short ciphertext: text must be min 32 long, output was 88 long
		let encrypted = &encrypted[..(encrypted.len() - 156)];

		let decrypted_result = sk.decrypt(encrypted);

		assert!(matches!(decrypted_result, Err(DecryptionFailedCiphertextShort)));
	}
}
