use alloc::vec::Vec;

use crate::{alg, Error, Pk, SignK, Sk, SymKey, VerifyK};

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

pub fn verify(verify_key: &VerifyK, data_with_sign: &[u8]) -> Result<(Vec<u8>, bool), Error>
{
	match verify_key {
		VerifyK::Ed25519(_) => alg::sign::ed25519::verify(verify_key, data_with_sign),
	}
}
