use alloc::vec::Vec;

use pqc_kyber::{decapsulate, encapsulate, keypair, PublicKey, SecretKey, KYBER_CIPHERTEXTBYTES, KYBER_PUBLICKEYBYTES, KYBER_SECRETKEYBYTES};
use rand_core::{CryptoRng, RngCore};

use crate::alg::sym::aes_gcm::{raw_decrypt as aes_decrypt, raw_encrypt as aes_encrypt};
use crate::cryptomat::{CryptoAlg, Pk, Sig, SignK, Sk, StaticKeyPair, SymKey};
use crate::{get_rand, try_from_bytes_single_value, Error};

pub const KYBER_OUTPUT: &str = "KYBER_768";

pub struct KyberPk([u8; KYBER_PUBLICKEYBYTES]);

try_from_bytes_single_value!(KyberPk);

impl CryptoAlg for KyberPk
{
	fn get_alg_str(&self) -> &'static str
	{
		KYBER_OUTPUT
	}
}

impl Into<crate::PublicKey> for KyberPk
{
	fn into(self) -> crate::PublicKey
	{
		crate::PublicKey::Kyber(self)
	}
}

impl Pk for KyberPk
{
	fn sign_public_key<S: SignK>(&self, sign_key: &S) -> Result<impl Sig, Error>
	{
		sign_key.sign_only(&self.0)
	}

	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>
	{
		encrypt_internally(&self.0, data, &mut get_rand())
	}
}

pub struct KyberSk([u8; KYBER_SECRETKEYBYTES]);

impl CryptoAlg for KyberSk
{
	fn get_alg_str(&self) -> &'static str
	{
		KYBER_OUTPUT
	}
}

try_from_bytes_single_value!(KyberSk);

impl Into<crate::SecretKey> for KyberSk
{
	fn into(self) -> crate::SecretKey
	{
		crate::SecretKey::Kyber(self)
	}
}

impl Sk for KyberSk
{
	fn encrypt_by_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		master_key.encrypt(&self.0)
	}

	fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
	{
		decrypt_internally(&self.0, ciphertext)
	}
}

pub struct KyberKeyPair;

impl StaticKeyPair for KyberKeyPair
{
	fn generate_static_keypair() -> Result<(impl Sk, impl Pk), Error>
	{
		let (sk, pk) = generate_keypair_internally(&mut get_rand())?;

		Ok((KyberSk(sk), KyberPk(pk)))
	}
}

//__________________________________________________________________________________________________

pub(super) fn generate_keypair_internally<R: CryptoRng + RngCore>(rng: &mut R) -> Result<(SecretKey, PublicKey), Error>
{
	let keys = keypair(rng).map_err(|_| Error::KeyCreationFailed)?;

	Ok((keys.secret, keys.public))
}

pub(super) fn encrypt_internally<R: CryptoRng + RngCore>(receiver_pub: &PublicKey, data: &[u8], rng: &mut R) -> Result<Vec<u8>, Error>
{
	let (ciphertext, shared_secret_alice) = encapsulate(receiver_pub, rng).map_err(|_| Error::EncryptionFailed)?;

	let encrypted = aes_encrypt(&shared_secret_alice, data)?;

	let mut cipher_text = Vec::with_capacity(KYBER_CIPHERTEXTBYTES + encrypted.len());
	cipher_text.extend_from_slice(&ciphertext);
	cipher_text.extend_from_slice(&encrypted);

	Ok(cipher_text)
}

pub(super) fn decrypt_internally(receiver_sec: &SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
{
	if ciphertext.len() <= KYBER_CIPHERTEXTBYTES {
		return Err(Error::DecryptionFailedCiphertextShort);
	}

	let ep_pk_bytes: [u8; KYBER_CIPHERTEXTBYTES] = match ciphertext[..KYBER_CIPHERTEXTBYTES].try_into() {
		Err(_e) => return Err(Error::DecryptionFailedCiphertextShort),
		Ok(bytes) => bytes,
	};

	let encrypted = &ciphertext[KYBER_CIPHERTEXTBYTES..];

	let shared_secret_bob = decapsulate(&ep_pk_bytes, receiver_sec).map_err(|_| Error::DecryptionFailed)?;

	let decrypted = aes_decrypt(&shared_secret_bob, encrypted)?;

	Ok(decrypted)
}

#[cfg(test)]
mod test
{
	use core::str::from_utf8;

	use super::*;
	use crate::error::Error::{DecryptionFailed, DecryptionFailedCiphertextShort};

	#[test]
	fn test_key_gen()
	{
		let _ = KyberKeyPair::generate_static_keypair().unwrap();
	}

	#[test]
	fn test_encrypt_and_decrypt()
	{
		let (sk, pk) = KyberKeyPair::generate_static_keypair().unwrap();

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
		let (_sk, pk) = KyberKeyPair::generate_static_keypair().unwrap();

		let (sk, _pk) = KyberKeyPair::generate_static_keypair().unwrap();

		let text = "Hello world üöäéèßê°";

		let encrypted = pk.encrypt(text.as_bytes()).unwrap();

		let decrypted_result = sk.decrypt(&encrypted);

		assert!(matches!(decrypted_result, Err(DecryptionFailed)));
	}

	#[test]
	fn test_not_decrypt_with_wrong_ciphertext()
	{
		let (sk, pk) = KyberKeyPair::generate_static_keypair().unwrap();

		let text = "Hello world üöäéèßê°";

		let encrypted = pk.encrypt(text.as_bytes()).unwrap();

		//too short ciphertext: text must be min 32 long, output was 88 long
		let encrypted = &encrypted[..(encrypted.len() - 56)];

		let decrypted_result = sk.decrypt(encrypted);

		assert!(matches!(decrypted_result, Err(DecryptionFailedCiphertextShort)));
	}
}
