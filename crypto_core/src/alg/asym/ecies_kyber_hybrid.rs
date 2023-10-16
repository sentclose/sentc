use alloc::vec::Vec;

use x25519_dalek::{PublicKey, StaticSecret};

use crate::alg::asym::AsymKeyOutput;
use crate::{get_rand, Error, Pk, Sk};

pub const ECIES_KYBER_HYBRID_OUTPUT: &str = "ECIES-ed25519_KYBER_768";

pub(crate) fn generate_static_keypair() -> Result<AsymKeyOutput, Error>
{
	let (x_sk, x_pk) = super::ecies::generate_static_keypair_internally(&mut get_rand());
	let (k_sk, k_pk) = super::pqc_kyber::generate_keypair_internally(&mut get_rand())?;

	Ok(AsymKeyOutput {
		pk: Pk::EciesKyberHybrid {
			x: x_pk.to_bytes(),
			k: k_pk,
		},
		sk: Sk::EciesKyberHybrid {
			x: x_sk.to_bytes(),
			k: k_sk,
		},
		alg: ECIES_KYBER_HYBRID_OUTPUT,
	})
}

pub(crate) fn encrypt(receiver_pub: &Pk, data: &[u8]) -> Result<Vec<u8>, Error>
{
	//encrypt with ecies first then with kyber

	let (x_pk, k_pk) = match receiver_pub {
		Pk::EciesKyberHybrid {
			k,
			x,
		} => (PublicKey::from(*x), k),
		_ => return Err(Error::AlgNotFound),
	};

	let encrypted = super::ecies::encrypt_internally(&x_pk, data, &mut get_rand())?;

	let encrypted = super::pqc_kyber::encrypt_internally(k_pk, &encrypted, &mut get_rand())?;

	Ok(encrypted)
}

pub(crate) fn decrypt(receiver_sec: &Sk, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
{
	//decrypt with kyber first then with ecies

	let (x_sk, k_sk) = match receiver_sec {
		Sk::EciesKyberHybrid {
			k,
			x,
		} => (StaticSecret::from(*x), k),
		_ => return Err(Error::AlgNotFound),
	};

	let decrypted = super::pqc_kyber::decrypt_internally(k_sk, ciphertext)?;

	let decrypted = super::ecies::decrypt_internally(&x_sk, &decrypted)?;

	Ok(decrypted)
}

#[cfg(test)]
mod test
{
	use core::str::from_utf8;

	use pqc_kyber::{KYBER_PUBLICKEYBYTES, KYBER_SECRETKEYBYTES};

	use super::*;
	use crate::error::Error::{DecryptionFailed, DecryptionFailedCiphertextShort};

	fn test_key_gen_output(out: &AsymKeyOutput)
	{
		assert_eq!(out.alg, ECIES_KYBER_HYBRID_OUTPUT);

		let (x, k) = match out.pk {
			Pk::EciesKyberHybrid {
				x,
				k,
			} => (x, k),
			_ => panic!("alg not found"),
		};

		assert_eq!(k.len(), KYBER_PUBLICKEYBYTES);
		assert_eq!(x.len(), 32);

		let (x, k) = match out.sk {
			Sk::EciesKyberHybrid {
				x,
				k,
			} => (x, k),
			_ => panic!("alg not found"),
		};

		assert_eq!(k.len(), KYBER_SECRETKEYBYTES);
		assert_eq!(x.len(), 32);
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
		let encrypted = &encrypted[..(encrypted.len() - 156)];

		let decrypted_result = decrypt(&sk, encrypted);

		assert!(matches!(decrypted_result, Err(DecryptionFailedCiphertextShort)));
	}
}
