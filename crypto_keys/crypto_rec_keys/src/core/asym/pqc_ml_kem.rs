use safe_oqs::kem;
use safe_oqs::kem::{Kem, PublicKey, SecretKey};
use sentc_crypto_core::cryptomat::{Pk, SignK, Sk, StaticKeyPair, SymKey, VerifyK};
use sentc_crypto_core::{as_ref_bytes_single_value, crypto_alg_str_impl, from_bytes_owned_single_value, into_bytes_from_bytes_inner, Error};
use sentc_crypto_fips_keys::core::sym::raw_decrypt;

use crate::core::sym::raw_encrypt;

pub const ML_KEM_REC_OUTPUT: &str = "ML_KEM_REC_768";

const CT_LEN: usize = 1088; //from oqs::ffi::kem::OQS_KEM_ml_kem_768_length_ciphertext

#[derive(Clone)]
pub struct MlKemPk(Vec<u8>);
crypto_alg_str_impl!(MlKemPk, ML_KEM_REC_OUTPUT);
into_bytes_from_bytes_inner!(MlKemPk);
from_bytes_owned_single_value!(MlKemPk);
as_ref_bytes_single_value!(MlKemPk);

impl Pk for MlKemPk
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
		encrypt_internally(&self.0, data)
	}
}

impl Into<super::PublicKey> for MlKemPk
{
	fn into(self) -> super::PublicKey
	{
		super::PublicKey::MlKem(self)
	}
}

pub struct MlKemSk(Vec<u8>);
crypto_alg_str_impl!(MlKemSk, ML_KEM_REC_OUTPUT);
into_bytes_from_bytes_inner!(MlKemSk);
from_bytes_owned_single_value!(MlKemSk);
as_ref_bytes_single_value!(MlKemSk);

impl Sk for MlKemSk
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

impl Into<super::SecretKey> for MlKemSk
{
	fn into(self) -> super::SecretKey
	{
		super::SecretKey::MlKem(self)
	}
}

impl StaticKeyPair for MlKemSk
{
	type SecretKey = Self;
	type PublicKey = MlKemPk;

	fn generate_static_keypair() -> Result<(Self::SecretKey, Self::PublicKey), Error>
	{
		let (sk, pk) = generate_keypair()?;

		Ok((Self(sk.into_vec()), MlKemPk(pk.into_vec())))
	}
}

//__________________________________________________________________________________________________

pub(super) fn generate_keypair() -> Result<(SecretKey, PublicKey), Error>
{
	let kem_alg = get_oqs()?;

	let (pk, sk) = kem_alg.keypair().map_err(|_| Error::KeyCreationFailed)?;

	Ok((sk, pk))
}

pub(super) fn encrypt_internally(pk: &[u8], data: &[u8]) -> Result<Vec<u8>, Error>
{
	let kem_alg = get_oqs()?;
	let pk = kem_alg
		.public_key_from_bytes(pk)
		.ok_or(Error::KeyDecryptFailed)?;

	let (ciphertext, shared_secret) = kem_alg
		.encapsulate(pk)
		.map_err(|_| Error::EncryptionFailed)?;

	let encrypted = raw_encrypt(shared_secret.as_ref(), data)?;

	let mut cipher_text = Vec::with_capacity(CT_LEN + encrypted.len());
	cipher_text.extend_from_slice(ciphertext.as_ref());
	cipher_text.extend_from_slice(&encrypted);

	Ok(cipher_text)
}

pub(super) fn decrypt_internally(sk: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error>
{
	if ciphertext.len() <= CT_LEN {
		return Err(Error::DecryptionFailedCiphertextShort);
	}

	let kem_alg = get_oqs()?;

	let sk = kem_alg
		.secret_key_from_bytes(sk)
		.ok_or(Error::KeyDecryptFailed)?;

	let ct = kem_alg
		.ciphertext_from_bytes(&ciphertext[..CT_LEN])
		.ok_or(Error::DecryptionFailedCiphertextShort)?;

	let shared_secret = kem_alg
		.decapsulate(sk, ct)
		.map_err(|_| Error::DecryptionFailed)?;

	let encrypted = &ciphertext[CT_LEN..];

	raw_decrypt(shared_secret.as_ref(), encrypted)
}

fn get_oqs() -> Result<Kem, Error>
{
	safe_oqs::init();
	Kem::new(kem::Algorithm::MlKem768).map_err(|_| Error::KeyCreationFailed)
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
		let _ = MlKemSk::generate_static_keypair().unwrap();
	}

	#[test]
	fn test_encrypt_and_decrypt()
	{
		let (sk, pk) = MlKemSk::generate_static_keypair().unwrap();

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
		let (_sk, pk) = MlKemSk::generate_static_keypair().unwrap();

		let (sk, _pk) = MlKemSk::generate_static_keypair().unwrap();

		let text = "Hello world üöäéèßê°";

		let encrypted = pk.encrypt(text.as_bytes()).unwrap();

		let decrypted_result = sk.decrypt(&encrypted);

		assert!(matches!(decrypted_result, Err(DecryptionFailed)));
	}

	#[test]
	fn test_not_decrypt_with_wrong_ciphertext()
	{
		let (sk, pk) = MlKemSk::generate_static_keypair().unwrap();

		let text = "Hello world üöäéèßê°";

		let encrypted = pk.encrypt(text.as_bytes()).unwrap();

		//too short ciphertext: text must be min 32 long, output was 88 long
		let encrypted = &encrypted[..(encrypted.len() - 56)];

		let decrypted_result = sk.decrypt(encrypted);

		assert!(matches!(decrypted_result, Err(DecryptionFailedCiphertextShort)));
	}
}
