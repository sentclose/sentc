use alloc::vec::Vec;

use pqc_kyber::{decapsulate, encapsulate, keypair, PublicKey, SecretKey, KYBER_CIPHERTEXTBYTES};
use rand_core::{CryptoRng, RngCore};

use crate::alg::asym::AsymKeyOutput;
use crate::alg::sym::aes_gcm::{decrypt_with_generated_key as aes_decrypt, encrypt_with_generated_key as aes_encrypt};
use crate::{get_rand, Error, Pk, Sk};

pub const KYBER_OUTPUT: &str = "KYBER_768";

#[allow(unused)]
pub(crate) fn generate_static_keypair() -> Result<AsymKeyOutput, Error>
{
	let (sk, pk) = generate_keypair_internally(&mut get_rand())?;

	Ok(AsymKeyOutput {
		alg: KYBER_OUTPUT,
		pk: Pk::Kyber(pk),
		sk: Sk::Kyber(sk),
	})
}

pub(crate) fn encrypt(receiver_pub: &Pk, data: &[u8]) -> Result<Vec<u8>, Error>
{
	let receiver_pub = match receiver_pub {
		Pk::Kyber(pk) => pk,
		_ => return Err(Error::AlgNotFound),
	};

	encrypt_internally(receiver_pub, data, &mut get_rand())
}

pub(crate) fn decrypt(receiver_sec: &Sk, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
{
	let receiver_sec = match receiver_sec {
		Sk::Kyber(sk) => sk,
		_ => return Err(Error::AlgNotFound),
	};

	decrypt_internally(receiver_sec, ciphertext)
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
	cipher_text.extend(ciphertext.iter());
	cipher_text.extend(encrypted);

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

	use pqc_kyber::{KYBER_PUBLICKEYBYTES, KYBER_SECRETKEYBYTES};

	use super::*;
	use crate::alg::asym::AsymKeyOutput;
	use crate::error::Error::{DecryptionFailed, DecryptionFailedCiphertextShort};

	fn test_key_gen_output(out: &AsymKeyOutput)
	{
		assert_eq!(out.alg, KYBER_OUTPUT);

		let pk = match out.pk {
			Pk::Kyber(p) => p,
			_ => panic!("alg not found"),
		};

		let sk = match out.sk {
			Sk::Kyber(s) => s,
			_ => panic!("alg not found"),
		};

		assert_eq!(pk.len(), KYBER_PUBLICKEYBYTES);
		assert_eq!(sk.len(), KYBER_SECRETKEYBYTES);
	}

	#[test]
	fn test_key_gen()
	{
		let out = generate_static_keypair().unwrap();

		test_key_gen_output(&out);
	}

	#[test]
	fn test_encrypt_and_decrypt()
	{
		let out = generate_static_keypair().unwrap();
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
		let out = generate_static_keypair().unwrap();
		let pk = out.pk;

		let out1 = generate_static_keypair().unwrap();
		let sk1 = out1.sk;

		let text = "Hello world üöäéèßê°";

		let encrypted = encrypt(&pk, text.as_bytes()).unwrap();

		let decrypted_result = decrypt(&sk1, &encrypted);

		assert!(matches!(decrypted_result, Err(DecryptionFailed)));
	}

	#[test]
	fn test_not_decrypt_with_wrong_ciphertext()
	{
		let out = generate_static_keypair().unwrap();
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
