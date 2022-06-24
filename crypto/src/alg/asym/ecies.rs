use hkdf::Hkdf;
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::alg::sym::aes_gcm::{decrypt_with_generated_key as aes_decrypt, encrypt_with_generated_key as aes_encrypt, AesKey};
use crate::error::Error;
use crate::{AsymKeyOutput, Pk, Sk};

pub const ECIES_OUTPUT: &'static str = "ECIES-ed25519";

const HKDF_INFO: &[u8; 13] = b"ecies-ed25519";

const PUBLIC_KEY_LENGTH: usize = 32;

pub(crate) fn generate_static_keypair() -> AsymKeyOutput
{
	let (sk, pk) = generate_static_keypair_internally(&mut OsRng);

	AsymKeyOutput {
		alg: ECIES_OUTPUT,
		pk: Pk::Ecies(pk.to_bytes()),
		sk: Sk::Ecies(sk.to_bytes()),
	}
}

pub(crate) fn encrypt(receiver_pub: &Pk, data: &[u8]) -> Result<Vec<u8>, Error>
{
	let receiver_pub = match receiver_pub {
		Pk::Ecies(pk) => PublicKey::from(pk.clone()),
	};

	encrypt_internally(&receiver_pub, data, &mut OsRng)
}

pub(crate) fn decrypt(receiver_sec: &Sk, ciphertext: &[u8]) -> Result<Vec<u8>, Error>
{
	let receiver_sec = match receiver_sec {
		Sk::Ecies(sk) => StaticSecret::from(sk.clone()),
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
	let aes_key = decapsulate(&receiver_sec, &ep_pk);

	let decrypted = aes_decrypt(&aes_key, &encrypted)?;

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
