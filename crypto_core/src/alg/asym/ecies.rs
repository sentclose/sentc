use alloc::vec::Vec;

use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::alg::sym::aes_gcm::{decrypt_with_generated_key as aes_decrypt, encrypt_with_generated_key as aes_encrypt, AesKey};
use crate::error::Error;
use crate::{get_rand, AsymKeyOutput, Pk, Sk};

pub const ECIES_OUTPUT: &str = "ECIES-ed25519";

const HKDF_INFO: &[u8; 13] = b"ecies-ed25519";

const PUBLIC_KEY_LENGTH: usize = 32;

pub(crate) fn generate_static_keypair() -> AsymKeyOutput
{
	let (sk, pk) = generate_static_keypair_internally(&mut get_rand());

	AsymKeyOutput {
		alg: ECIES_OUTPUT,
		pk: Pk::Ecies(pk.to_bytes()),
		sk: Sk::Ecies(sk.to_bytes()),
	}
}

pub(crate) fn encrypt(receiver_pub: &Pk, data: &[u8]) -> Result<Vec<u8>, Error>
{
	let receiver_pub = match receiver_pub {
		Pk::Ecies(pk) => PublicKey::from(*pk),
		_ => return Err(Error::AlgNotFound),
	};

	encrypt_internally(&receiver_pub, data, &mut get_rand())
}

pub(crate) fn decrypt(receiver_sec: &Sk, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
{
	let receiver_sec = match receiver_sec {
		Sk::Ecies(sk) => StaticSecret::from(*sk),
		_ => return Err(Error::AlgNotFound),
	};

	decrypt_internally(&receiver_sec, ciphertext)
}

//__________________________________________________________________________________________________
//internally function

fn generate_static_keypair_internally<R: CryptoRng + RngCore>(rng: &mut R) -> (StaticSecret, PublicKey)
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

fn encrypt_internally<R: CryptoRng + RngCore>(receiver_pub: &PublicKey, data: &[u8], rng: &mut R) -> Result<Vec<u8>, Error>
{
	let (ep_sk, ep_pk) = generate_keypair_internally(rng);

	let aes_key = encapsulate(ep_sk, receiver_pub);

	let encrypted = aes_encrypt(&aes_key, data)?;

	//put the ephemeral public key in front of the aes encrypt, so we can use it later for decrypt
	let mut cipher_text = Vec::with_capacity(PUBLIC_KEY_LENGTH + encrypted.len());
	cipher_text.extend(ep_pk.to_bytes().iter());
	cipher_text.extend(encrypted);

	Ok(cipher_text)
}

fn decrypt_internally(receiver_sec: &StaticSecret, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
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

	fn test_key_gen_output(out: &AsymKeyOutput)
	{
		assert_eq!(out.alg, ECIES_OUTPUT);

		let pk = match out.pk {
			Pk::Ecies(p) => p,
			_ => panic!("alg not found"),
		};

		let sk = match out.sk {
			Sk::Ecies(s) => s,
			_ => panic!("alg not found"),
		};

		assert_eq!(pk.len(), 32);
		assert_eq!(sk.len(), 32);
	}

	#[test]
	fn test_key_gen()
	{
		let out = generate_static_keypair();

		test_key_gen_output(&out);
	}

	#[test]
	fn test_encrypt_and_decrypt()
	{
		let out = generate_static_keypair();
		let sk = out.sk;
		let pk = out.pk;

		let text = "Hello world üöäéèßê°";

		let encrypted = encrypt(&pk, text.as_bytes()).unwrap();

		let decrypted = decrypt(&sk, &encrypted).unwrap();

		assert_eq!(text.as_bytes(), decrypted);

		let decrypted_text = from_utf8(&decrypted).unwrap();

		assert_eq!(text, decrypted_text);
	}

	#[test]
	fn test_not_decrypt_with_wrong_key()
	{
		let out = generate_static_keypair();
		let pk = out.pk;

		let out1 = generate_static_keypair();
		let sk1 = out1.sk;

		let text = "Hello world üöäéèßê°";

		let encrypted = encrypt(&pk, text.as_bytes()).unwrap();

		let decrypted_result = decrypt(&sk1, &encrypted);

		assert!(matches!(decrypted_result, Err(DecryptionFailed)));
	}

	#[test]
	fn test_not_decrypt_with_wrong_ciphertext()
	{
		let out = generate_static_keypair();
		let sk = out.sk;
		let pk = out.pk;

		let text = "Hello world üöäéèßê°";

		let encrypted = encrypt(&pk, text.as_bytes()).unwrap();

		//too short ciphertext: text must be min 32 long, output was 88 long
		let encrypted = &encrypted[..(encrypted.len() - 56)];

		let decrypted_result = decrypt(&sk, encrypted);

		assert!(matches!(decrypted_result, Err(DecryptionFailedCiphertextShort)));
	}
}
