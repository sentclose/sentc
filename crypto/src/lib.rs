use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or `Aes128Gcm`
use p256::ecdh::EphemeralSecret;
use p256::{EncodedPoint, PublicKey};
use rand_core::OsRng; // requires 'getrandom' feature

pub fn aes() -> String
{
	//aes
	aes_intern(b"an example very very secret key.")
}

fn aes_intern(key: &[u8]) -> String
{
	let key = Key::from_slice(key);

	let cipher = Aes256Gcm::new(key);

	let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message

	let ciphertext = cipher
		.encrypt(nonce, b"plaintext message".as_ref())
		.expect("encryption failure!"); // NOTE: handle this error to avoid panics!

	let plaintext = cipher
		.decrypt(nonce, ciphertext.as_ref())
		.expect("decryption failure!"); // NOTE: handle this error to avoid panics!

	assert_eq!(&plaintext, b"plaintext message");

	std::str::from_utf8(&plaintext).unwrap().to_owned()
}

pub fn ecdh() -> String
{
	// Alice
	let alice_secret = EphemeralSecret::random(&mut OsRng);
	let alice_pk_bytes = EncodedPoint::from(alice_secret.public_key());

	// Bob
	let bob_secret = EphemeralSecret::random(&mut OsRng);
	let bob_pk_bytes = EncodedPoint::from(bob_secret.public_key());

	// Alice decodes Bob's serialized public key and computes a shared secret from it
	let bob_public = PublicKey::from_sec1_bytes(bob_pk_bytes.as_ref()).expect("bob's public key is invalid!"); // In real usage, don't panic, handle this!

	let alice_shared = alice_secret.diffie_hellman(&bob_public);

	// Bob deocdes Alice's serialized public key and computes the same shared secret
	let alice_public = PublicKey::from_sec1_bytes(alice_pk_bytes.as_ref()).expect("alice's public key is invalid!"); // In real usage, don't panic, handle this!

	let bob_shared = bob_secret.diffie_hellman(&alice_public);

	// Both participants arrive on the same shared secret
	assert_eq!(alice_shared.raw_secret_bytes(), bob_shared.raw_secret_bytes());

	//get a key for aes
	let key = alice_shared.extract::<sha2::Sha256>(None);

	let mut okm = [0u8; 32]; //32 bytes for sha256

	key.expand(&vec![], &mut okm).expect("TODO: panic message");

	aes_intern(&okm)
}

#[cfg(test)]
mod test
{
	use super::*;

	#[test]
	fn test_aes()
	{
		let str = aes();

		assert_eq!(str, "plaintext message");
	}

	#[test]
	fn test_ecdh()
	{
		let str = ecdh();

		assert_eq!(str, "plaintext message");
	}
}
