use openssl::pkey::{HasPrivate, HasPublic, Private, Public};
use openssl::rsa::{Padding, Rsa};
use sentc_crypto_core::cryptomat::{Pk, SignK, Sk, SkComposer, StaticKeyPair, SymKey, VerifyK};
use sentc_crypto_core::{crypto_alg_str_impl, Error};

use crate::core::sym;
use crate::import_export_openssl;

pub const FIPS_OPENSSL_RSA_OAEP_WRAP: &str = "fips_openssl_rsa_oaep_wrap";

pub const RSA_LENGTH: u32 = 2048;

#[derive(Clone)]
pub struct RsaPk(Rsa<Public>);

import_export_openssl!(RsaPk, import_pk, export_pk);
crypto_alg_str_impl!(RsaPk, FIPS_OPENSSL_RSA_OAEP_WRAP);

impl Pk for RsaPk
{
	fn sign_public_key<S: SignK>(&self, sign_key: &S) -> Result<S::Signature, Error>
	{
		sign_key.sign_only(export_pk(&self.0)?)
	}

	fn verify_public_key<V: VerifyK>(&self, verify_key: &V, sig: &V::Signature) -> Result<bool, Error>
	{
		verify_key.verify_only(sig, &export_pk(&self.0)?)
	}

	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>
	{
		let aes_key = sym::raw_generate()?;
		let encrypted = sym::raw_encrypt(&aes_key, data)?;

		//the module size of rsa is the size of the encrypted output
		let encrypted_aes_key_len = self.0.size() as usize;

		let mut encrypted_aes_key = vec![0u8; encrypted_aes_key_len];

		self.0
			.public_encrypt(&aes_key, &mut encrypted_aes_key, Padding::PKCS1_OAEP)
			.map_err(|_| Error::EncryptionFailed)?;

		//the module size of rsa is the size of the encrypted output
		let mut cipher_text = Vec::with_capacity(encrypted_aes_key_len + encrypted.len());
		cipher_text.extend_from_slice(&encrypted_aes_key);
		cipher_text.extend_from_slice(&encrypted);

		Ok(cipher_text)
	}
}

pub struct RsaSk(Rsa<Private>);

import_export_openssl!(RsaSk, import_sk, export_sk);
crypto_alg_str_impl!(RsaSk, FIPS_OPENSSL_RSA_OAEP_WRAP);

impl Sk for RsaSk
{
	fn encrypt_by_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		master_key.encrypt(&export_sk(&self.0)?)
	}

	fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
	{
		//the module size of rsa is the size of the encrypted output
		let encrypted_aes_key_len = self.0.size() as usize;

		if ciphertext.len() <= encrypted_aes_key_len {
			return Err(Error::DecryptionFailedCiphertextShort);
		}

		let encrypted_aes_key = &ciphertext[..encrypted_aes_key_len];
		let en = &ciphertext[encrypted_aes_key_len..];

		let mut aes_key = vec![0u8; encrypted_aes_key_len];

		self.0
			.private_decrypt(encrypted_aes_key, &mut aes_key, Padding::PKCS1_OAEP)
			.map_err(|_| Error::DecryptionFailed)?;

		//use only the bytes for the aes key. the rest is zero
		sym::raw_decrypt(&aes_key[..32], en)
	}
}

impl SkComposer for RsaSk
{
	type SecretKey = Self;

	fn decrypt_by_master_key<M: SymKey>(master_key: &M, encrypted_key: &[u8], alg_str: &str) -> Result<Self::SecretKey, Error>
	{
		if alg_str != FIPS_OPENSSL_RSA_OAEP_WRAP {
			return Err(Error::AlgNotFound);
		}

		let decrypted_bytes = master_key.decrypt(encrypted_key)?;

		Ok(Self(import_sk(&decrypted_bytes)?))
	}
}

impl StaticKeyPair for RsaSk
{
	type SecretKey = Self;
	type PublicKey = RsaPk;

	fn generate_static_keypair() -> Result<(Self::SecretKey, Self::PublicKey), Error>
	{
		let rsa_private = Rsa::generate(RSA_LENGTH).map_err(|_| Error::KeyCreationFailed)?;

		let pub_k = RsaPk(import_pk(&export_pk(&rsa_private)?)?);

		Ok((Self(rsa_private), pub_k))
	}
}

//__________________________________________________________________________________________________

fn export_sk<T: HasPrivate>(key: &Rsa<T>) -> Result<Vec<u8>, Error>
{
	key.private_key_to_pem()
		.map_err(|_e| Error::KeyCreationFailed)
}

fn import_sk(key: &[u8]) -> Result<Rsa<Private>, Error>
{
	Rsa::<Private>::private_key_from_pem(key).map_err(|_e| Error::KeyCreationFailed)
}

fn export_pk<T: HasPublic>(key: &Rsa<T>) -> Result<Vec<u8>, Error>
{
	key.public_key_to_pem()
		.map_err(|_e| Error::KeyCreationFailed)
}

fn import_pk(key: &[u8]) -> Result<Rsa<Public>, Error>
{
	Rsa::<Public>::public_key_from_pem(key).map_err(|_e| Error::KeyCreationFailed)
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
		openssl::provider::Provider::load(None, "fips").unwrap();
		let _ = RsaSk::generate_static_keypair().unwrap();
	}

	#[test]
	fn test_encrypt_and_decrypt()
	{
		openssl::provider::Provider::load(None, "fips").unwrap();

		let (sk, pk) = RsaSk::generate_static_keypair().unwrap();

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
		openssl::provider::Provider::load(None, "fips").unwrap();

		let (_sk, pk) = RsaSk::generate_static_keypair().unwrap();

		let (sk, _pk) = RsaSk::generate_static_keypair().unwrap();

		let text = "Hello world üöäéèßê°";

		let encrypted = pk.encrypt(text.as_bytes()).unwrap();

		let decrypted_result = sk.decrypt(&encrypted);

		assert!(matches!(decrypted_result, Err(DecryptionFailed)));
	}

	#[test]
	fn test_not_decrypt_with_wrong_ciphertext()
	{
		openssl::provider::Provider::load(None, "fips").unwrap();

		let (sk, pk) = RsaSk::generate_static_keypair().unwrap();

		let text = "Hello world üöäéèßê°";

		let encrypted = pk.encrypt(text.as_bytes()).unwrap();

		//too short ciphertext: text must be min 32 long, output was 88 long
		let encrypted = &encrypted[..(encrypted.len() - 56)];

		let decrypted_result = sk.decrypt(encrypted);

		assert!(matches!(decrypted_result, Err(DecryptionFailedCiphertextShort)));
	}
}
