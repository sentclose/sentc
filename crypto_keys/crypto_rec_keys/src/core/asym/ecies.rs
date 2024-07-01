use openssl::derive::Deriver;
use openssl::pkey::{HasPrivate, HasPublic, Id, PKey, Private, Public};
use sentc_crypto_core::cryptomat::{Pk, SignK, Sk, StaticKeyPair, SymKey, VerifyK};
use sentc_crypto_core::{crypto_alg_str_impl, Error};
use sentc_crypto_fips_keys::core::sym::{raw_decrypt, raw_encrypt};
use sentc_crypto_fips_keys::import_export_openssl; //use always openssl impl

use crate::core::{export_pk, export_sk};

pub const ECIES_REC_OUTPUT: &str = "ECIES-Rec-ed25519";
const PUBLIC_KEY_LENGTH: usize = 32;

#[derive(Clone)]
pub struct EciesPk(PKey<Public>);

crypto_alg_str_impl!(EciesPk, ECIES_REC_OUTPUT);

import_export_openssl!(EciesPk, import_pk, export_pk);

impl Into<super::PublicKey> for EciesPk
{
	fn into(self) -> super::PublicKey
	{
		super::PublicKey::Ecies(self)
	}
}

impl Pk for EciesPk
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
		encrypt_internally(&self.0, data)
	}
}

pub struct EciesSk(PKey<Private>);

import_export_openssl!(EciesSk, import_sk, export_sk);

crypto_alg_str_impl!(EciesSk, ECIES_REC_OUTPUT);

impl Into<super::SecretKey> for EciesSk
{
	fn into(self) -> super::SecretKey
	{
		super::SecretKey::Ecies(self)
	}
}

impl Sk for EciesSk
{
	fn encrypt_by_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		master_key.encrypt(&export_sk(&self.0)?)
	}

	fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
	{
		decrypt_internally(&self.0, ciphertext)
	}
}

impl StaticKeyPair for EciesSk
{
	type SecretKey = Self;
	type PublicKey = EciesPk;

	fn generate_static_keypair() -> Result<(Self::SecretKey, Self::PublicKey), Error>
	{
		let (pk, sk) = generate_key_pair()?;

		Ok((Self(sk), EciesPk(pk)))
	}
}

//__________________________________________________________________________________________________

pub(super) fn generate_key_pair() -> Result<(PKey<Public>, PKey<Private>), Error>
{
	let k = PKey::generate_x25519().map_err(|_| Error::KeyCreationFailed)?;

	Ok((import_pk(&export_pk(&k)?)?, k))
}

pub(super) fn import_sk(key: &[u8]) -> Result<PKey<Private>, Error>
{
	PKey::private_key_from_raw_bytes(key, Id::X25519).map_err(|_e| Error::KeyCreationFailed)
}

pub(super) fn import_pk(key: &[u8]) -> Result<PKey<Public>, Error>
{
	PKey::public_key_from_raw_bytes(key, Id::X25519).map_err(|_e| Error::KeyCreationFailed)
}

pub(super) fn encrypt_internally<T: HasPublic>(receiver_pub: &PKey<T>, data: &[u8]) -> Result<Vec<u8>, Error>
{
	let (ep_pk, ep_sk) = generate_key_pair()?;

	let mut deriver = Deriver::new(&ep_sk).map_err(|_| Error::EncryptionFailed)?;
	deriver
		.set_peer(receiver_pub)
		.map_err(|_| Error::EncryptionFailed)?;

	let aes_key = deriver
		.derive_to_vec()
		.map_err(|_| Error::EncryptionFailed)?;

	let encrypted = raw_encrypt(&aes_key, data)?;

	let mut cipher_text = Vec::with_capacity(PUBLIC_KEY_LENGTH + encrypted.len());
	cipher_text.extend_from_slice(&export_pk(&ep_pk)?);
	cipher_text.extend_from_slice(&encrypted);

	Ok(cipher_text)
}

pub(super) fn decrypt_internally<T: HasPrivate>(receiver_sec: &PKey<T>, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
{
	if ciphertext.len() <= PUBLIC_KEY_LENGTH {
		return Err(Error::DecryptionFailedCiphertextShort);
	}

	//get the ephemeral public key which we put in front of the encrypted data
	//should not panic because we checked the length
	let public_key = import_pk(&ciphertext[..PUBLIC_KEY_LENGTH]).map_err(|_| Error::DecryptionFailed)?;

	let encrypted = &ciphertext[PUBLIC_KEY_LENGTH..];

	let mut deriver = Deriver::new(receiver_sec).map_err(|_| Error::DecryptionFailed)?;
	deriver
		.set_peer(&public_key)
		.map_err(|_| Error::DecryptionFailed)?;

	let aes_key = deriver
		.derive_to_vec()
		.map_err(|_| Error::DecryptionFailed)?;

	raw_decrypt(&aes_key, encrypted)
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
		let _ = EciesSk::generate_static_keypair().unwrap();
	}

	#[test]
	fn test_encrypt_and_decrypt()
	{
		let (sk, pk) = EciesSk::generate_static_keypair().unwrap();

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
		let (_sk, pk) = EciesSk::generate_static_keypair().unwrap();

		let (sk, _pk) = EciesSk::generate_static_keypair().unwrap();

		let text = "Hello world üöäéèßê°";

		let encrypted = pk.encrypt(text.as_bytes()).unwrap();

		let decrypted_result = sk.decrypt(&encrypted);

		assert!(matches!(decrypted_result, Err(DecryptionFailed)));
	}

	#[test]
	fn test_not_decrypt_with_wrong_ciphertext()
	{
		let (sk, pk) = EciesSk::generate_static_keypair().unwrap();

		let text = "Hello world üöäéèßê°";

		let encrypted = pk.encrypt(text.as_bytes()).unwrap();

		//too short ciphertext: text must be min 32 long, output was 88 long
		let encrypted = &encrypted[..(encrypted.len() - 56)];

		let decrypted_result = sk.decrypt(encrypted);

		assert!(matches!(decrypted_result, Err(DecryptionFailedCiphertextShort)));
	}
}
