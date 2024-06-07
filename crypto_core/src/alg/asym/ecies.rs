use alloc::vec::Vec;

use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::alg::sym::aes_gcm::{raw_decrypt as aes_decrypt, raw_encrypt as aes_encrypt, AesKey};
use crate::cryptomat::{CryptoAlg, Pk, SignK, Sk, StaticKeyPair, SymKey, VerifyK};
use crate::error::Error;
use crate::{as_ref_bytes_single_value, crypto_alg_str_impl, get_rand, try_from_bytes_owned_single_value, try_from_bytes_single_value, SecretKey};

pub const ECIES_OUTPUT: &str = "ECIES-ed25519";

const HKDF_INFO: &[u8; 13] = b"ecies-ed25519";

const PUBLIC_KEY_LENGTH: usize = 32;

#[derive(Clone)]
pub struct EciesPk([u8; 32]);

try_from_bytes_single_value!(EciesPk);
try_from_bytes_owned_single_value!(EciesPk);
crypto_alg_str_impl!(EciesPk, ECIES_OUTPUT);
as_ref_bytes_single_value!(EciesPk);

impl Into<crate::PublicKey> for EciesPk
{
	fn into(self) -> crate::PublicKey
	{
		crate::PublicKey::Ecies(self)
	}
}

impl Pk for EciesPk
{
	fn sign_public_key<S: SignK>(&self, sign_key: &S) -> Result<S::Signature, Error>
	{
		sign_key.sign_only(&self.0)
	}

	fn verify_public_key<V: VerifyK>(&self, verify_key: &V, sig: &V::Signature) -> Result<bool, Error>
	{
		verify_key.verify_only(sig, &self.0)
	}

	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>
	{
		encrypt_internally(&self.0.into(), data, &mut get_rand())
	}
}

pub struct EciesSk([u8; 32]);

try_from_bytes_single_value!(EciesSk);
try_from_bytes_owned_single_value!(EciesSk);
crypto_alg_str_impl!(EciesSk, ECIES_OUTPUT);
as_ref_bytes_single_value!(EciesSk);

impl Into<SecretKey> for EciesSk
{
	fn into(self) -> SecretKey
	{
		SecretKey::Ecies(self)
	}
}

impl Sk for EciesSk
{
	fn encrypt_by_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>
	{
		master_key.encrypt(&self.0)
	}

	fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
	{
		decrypt_internally(&self.0.into(), ciphertext)
	}
}

pub struct EciesKeyPair;

impl StaticKeyPair for EciesKeyPair
{
	type SecretKey = EciesSk;
	type PublicKey = EciesPk;

	fn generate_static_keypair() -> Result<(Self::SecretKey, Self::PublicKey), Error>
	{
		let (sk, pk) = generate_static_keypair_internally(&mut get_rand());

		Ok((EciesSk(sk.to_bytes()), EciesPk(pk.to_bytes())))
	}
}

//__________________________________________________________________________________________________
//internally function

pub(super) fn generate_static_keypair_internally<R: CryptoRng + RngCore>(rng: &mut R) -> (StaticSecret, PublicKey)
{
	let sk = StaticSecret::new(rng);
	let pk = PublicKey::from(&sk);

	(sk, pk)
}

fn generate_keypair_internally<R: CryptoRng + RngCore>(rng: &mut R) -> (EphemeralSecret, PublicKey)
{
	let sk = EphemeralSecret::new(rng);
	let pk = PublicKey::from(&sk);

	(sk, pk)
}

pub(super) fn encrypt_internally<R: CryptoRng + RngCore>(receiver_pub: &PublicKey, data: &[u8], rng: &mut R) -> Result<Vec<u8>, Error>
{
	let (ep_sk, ep_pk) = generate_keypair_internally(rng);

	let aes_key = encapsulate(ep_sk, receiver_pub);

	let encrypted = aes_encrypt(&aes_key, data)?;

	//put the ephemeral public key in front of the aes encrypt, so we can use it later for decrypt
	let mut cipher_text = Vec::with_capacity(PUBLIC_KEY_LENGTH + encrypted.len());
	cipher_text.extend_from_slice(&ep_pk.to_bytes());
	cipher_text.extend_from_slice(&encrypted);

	Ok(cipher_text)
}

pub(super) fn decrypt_internally(receiver_sec: &StaticSecret, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
{
	if ciphertext.len() <= PUBLIC_KEY_LENGTH {
		return Err(Error::DecryptionFailedCiphertextShort);
	}

	//get the ephemeral public key which we put in front of the encrypted data
	//should not panic because we checked the length
	let ep_pk_bytes: [u8; 32] = match ciphertext[..PUBLIC_KEY_LENGTH].try_into() {
		Err(_e) => return Err(Error::DecryptionFailedCiphertextShort),
		Ok(bytes) => bytes,
	};

	let ep_pk = PublicKey::from(ep_pk_bytes);

	let encrypted = &ciphertext[PUBLIC_KEY_LENGTH..];

	//this works because we used the receiver static public key for encrypt
	let aes_key = decapsulate(receiver_sec, &ep_pk);

	let decrypted = aes_decrypt(&aes_key, encrypted)?;

	Ok(decrypted)
}

fn encapsulate(ep_sk: EphemeralSecret, peer_pk: &PublicKey) -> AesKey
{
	//use here the ephemeral and only once!
	let shared = ep_sk.diffie_hellman(peer_pk);

	hkdf_sha256(shared.as_bytes())
}

fn decapsulate(sk: &StaticSecret, ep_pk: &PublicKey) -> AesKey
{
	let shared = sk.diffie_hellman(ep_pk);

	hkdf_sha256(shared.as_bytes())
}

fn hkdf_sha256(ikm: &[u8]) -> AesKey
{
	let h = Hkdf::<Sha256>::new(None, ikm);
	let mut out = [0u8; 32];

	h.expand(HKDF_INFO, &mut out).unwrap();

	out
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
		let _ = EciesKeyPair::generate_static_keypair().unwrap();
	}

	#[test]
	fn test_encrypt_and_decrypt()
	{
		let (sk, pk) = EciesKeyPair::generate_static_keypair().unwrap();

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
		let (_sk, pk) = EciesKeyPair::generate_static_keypair().unwrap();

		let (sk, _pk) = EciesKeyPair::generate_static_keypair().unwrap();

		let text = "Hello world üöäéèßê°";

		let encrypted = pk.encrypt(text.as_bytes()).unwrap();

		let decrypted_result = sk.decrypt(&encrypted);

		assert!(matches!(decrypted_result, Err(DecryptionFailed)));
	}

	#[test]
	fn test_not_decrypt_with_wrong_ciphertext()
	{
		let (sk, pk) = EciesKeyPair::generate_static_keypair().unwrap();

		let text = "Hello world üöäéèßê°";

		let encrypted = pk.encrypt(text.as_bytes()).unwrap();

		//too short ciphertext: text must be min 32 long, output was 88 long
		let encrypted = &encrypted[..(encrypted.len() - 56)];

		let decrypted_result = sk.decrypt(encrypted);

		assert!(matches!(decrypted_result, Err(DecryptionFailedCiphertextShort)));
	}
}
