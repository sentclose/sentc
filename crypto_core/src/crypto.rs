use alloc::vec::Vec;

use crate::{alg, Error, PasswordEncryptOutput, Pk, SignK, Sk, SymKey, SymKeyOutput, VerifyK};

pub fn generate_symmetric() -> Result<SymKeyOutput, Error>
{
	#[cfg(feature = "argon2_aes_ecies_ed25519")]
	alg::sym::aes_gcm::generate_key()
}

pub fn encrypt_symmetric(key: &SymKey, data: &[u8]) -> Result<Vec<u8>, Error>
{
	match key {
		SymKey::Aes(k) => alg::sym::aes_gcm::encrypt_with_generated_key(k, data),
	}
}

pub fn decrypt_symmetric(key: &SymKey, encrypted_data: &[u8]) -> Result<Vec<u8>, Error>
{
	match key {
		SymKey::Aes(k) => alg::sym::aes_gcm::decrypt_with_generated_key(k, encrypted_data),
	}
}

pub fn encrypt_asymmetric(public_key: &Pk, data: &[u8]) -> Result<Vec<u8>, Error>
{
	match public_key {
		Pk::Ecies(_) => alg::asym::ecies::encrypt(public_key, data),
	}
}

pub fn decrypt_asymmetric(private_key: &Sk, encrypted_data: &[u8]) -> Result<Vec<u8>, Error>
{
	match private_key {
		Sk::Ecies(_) => alg::asym::ecies::decrypt(private_key, encrypted_data),
	}
}

pub fn sign(sign_key: &SignK, data_to_sign: &[u8]) -> Result<Vec<u8>, Error>
{
	match sign_key {
		SignK::Ed25519(_) => alg::sign::ed25519::sign(sign_key, data_to_sign),
	}
}

pub fn verify<'a>(verify_key: &VerifyK, data_with_sign: &'a [u8]) -> Result<(&'a [u8], bool), Error>
{
	match verify_key {
		VerifyK::Ed25519(_) => alg::sign::ed25519::verify(verify_key, data_with_sign),
	}
}

pub fn split_sig_and_data<'a>(alg: &str, data_with_sign: &'a [u8]) -> Result<(&'a [u8], &'a [u8]), Error>
{
	match alg {
		alg::sign::ed25519::ED25519_OUTPUT => alg::sign::ed25519::split_sig_and_data(data_with_sign),
		_ => Err(Error::AlgNotFound),
	}
}

pub fn prepare_password_encrypt(password: &str) -> Result<(PasswordEncryptOutput, SymKey), Error>
{
	#[cfg(feature = "argon2_aes_ecies_ed25519")]
	alg::pw_hash::argon2::password_to_encrypt(password.as_bytes())
}

pub fn prepare_password_decrypt(password: &str, salt: &[u8], alg: &str) -> Result<SymKey, Error>
{
	match alg {
		alg::pw_hash::argon2::ARGON_2_OUTPUT => {
			let key = alg::pw_hash::argon2::password_to_decrypt(password.as_bytes(), salt)?;

			Ok(SymKey::Aes(key))
		},
		_ => Err(Error::AlgNotFound),
	}
}
