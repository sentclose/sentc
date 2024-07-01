use pqcrypto_kyber::ffi::PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES;
use pqcrypto_kyber::kyber768::{Ciphertext, PublicKey, SecretKey};
use pqcrypto_kyber::{kyber768_decapsulate, kyber768_encapsulate, kyber768_keypair};
use pqcrypto_traits::kem::{Ciphertext as CTT, PublicKey as PkT, SecretKey as SkT, SharedSecret};
use sentc_crypto_core::cryptomat::{Pk, SignK, Sk, StaticKeyPair, SymKey, VerifyK};
use sentc_crypto_core::{crypto_alg_str_impl, Error};

use crate::core::sym::{raw_decrypt, raw_encrypt};
use crate::import_export_pqc;

pub const KYBER_REC_OUTPUT: &str = "KYBER_REC_768";

#[derive(Clone)]
pub struct KyberPk(PublicKey);
crypto_alg_str_impl!(KyberPk, KYBER_REC_OUTPUT);
import_export_pqc!(KyberPk, PublicKey);

impl Into<super::PublicKey> for KyberPk
{
	fn into(self) -> super::PublicKey
	{
		super::PublicKey::Kyber(self)
	}
}

impl Pk for KyberPk
{
	fn sign_public_key<S: SignK>(&self, sign_key: &S) -> Result<S::Signature, Error>
	{
		sign_key.sign_only(self.0.as_bytes())
	}

	fn verify_public_key<V: VerifyK>(&self, verify_key: &V, sig: &V::Signature) -> Result<bool, Error>
	{
		verify_key.verify_only(sig, self.0.as_bytes())
	}

	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>
	{
		encrypt_internally(&self.0, data)
	}
}

pub struct KyberSk(SecretKey);
crypto_alg_str_impl!(KyberSk, KYBER_REC_OUTPUT);
import_export_pqc!(KyberSk, SecretKey);

impl Into<super::SecretKey> for KyberSk
{
	fn into(self) -> super::SecretKey
	{
		super::SecretKey::Kyber(self)
	}
}

impl Sk for KyberSk
{
	fn encrypt_by_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		master_key.encrypt(self.0.as_bytes())
	}

	fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
	{
		decrypt_internally(&self.0, ciphertext)
	}
}

impl StaticKeyPair for KyberSk
{
	type SecretKey = Self;
	type PublicKey = KyberPk;

	fn generate_static_keypair() -> Result<(Self::SecretKey, Self::PublicKey), Error>
	{
		let (sk, pk) = generate_keypair();

		Ok((Self(sk), KyberPk(pk)))
	}
}

//__________________________________________________________________________________________________

pub(super) fn generate_keypair() -> (SecretKey, PublicKey)
{
	let (pk, sk) = kyber768_keypair();

	(sk, pk)
}

pub(super) fn encrypt_internally(pk: &PublicKey, data: &[u8]) -> Result<Vec<u8>, Error>
{
	let (shared_secret, ciphertext) = kyber768_encapsulate(pk);

	let encrypted = raw_encrypt(shared_secret.as_bytes(), data)?;

	let mut cipher_text = Vec::with_capacity(PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES + encrypted.len());
	cipher_text.extend_from_slice(ciphertext.as_bytes());
	cipher_text.extend_from_slice(&encrypted);

	Ok(cipher_text)
}

pub(super) fn decrypt_internally(sk: &SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
{
	if ciphertext.len() <= PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES {
		return Err(Error::DecryptionFailedCiphertextShort);
	}

	let shared_secret = kyber768_decapsulate(
		&Ciphertext::from_bytes(&ciphertext[..PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES]).map_err(|_| Error::DecryptionFailed)?,
		sk,
	);

	let encrypted = &ciphertext[PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES..];
	let decrypted = raw_decrypt(shared_secret.as_bytes(), encrypted)?;

	Ok(decrypted)
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
		let _ = KyberSk::generate_static_keypair().unwrap();
	}

	#[test]
	fn test_encrypt_and_decrypt()
	{
		let (sk, pk) = KyberSk::generate_static_keypair().unwrap();

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
		let (_sk, pk) = KyberSk::generate_static_keypair().unwrap();

		let (sk, _pk) = KyberSk::generate_static_keypair().unwrap();

		let text = "Hello world üöäéèßê°";

		let encrypted = pk.encrypt(text.as_bytes()).unwrap();

		let decrypted_result = sk.decrypt(&encrypted);

		assert!(matches!(decrypted_result, Err(DecryptionFailed)));
	}

	#[test]
	fn test_not_decrypt_with_wrong_ciphertext()
	{
		let (sk, pk) = KyberSk::generate_static_keypair().unwrap();

		let text = "Hello world üöäéèßê°";

		let encrypted = pk.encrypt(text.as_bytes()).unwrap();

		//too short ciphertext: text must be min 32 long, output was 88 long
		let encrypted = &encrypted[..(encrypted.len() - 56)];

		let decrypted_result = sk.decrypt(encrypted);

		assert!(matches!(decrypted_result, Err(DecryptionFailedCiphertextShort)));
	}
}
