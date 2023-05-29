use alloc::vec::Vec;

use crate::{alg, Error, HmacKey, PasswordEncryptOutput, Pk, Sig, SignK, Sk, SymKey, SymKeyOutput, VerifyK};

pub fn generate_symmetric() -> Result<SymKeyOutput, Error>
{
	#[cfg(feature = "argon2_aes_ecies_ed25519")]
	alg::sym::aes_gcm::generate_key()
}

/**
Generates a new sym key (defined by the used alg).

Encrypt the new key by the given master key
*/
pub fn generate_symmetric_with_master_key(master_key: &SymKey) -> Result<(Vec<u8>, &'static str, SymKey), Error>
{
	let out = generate_symmetric()?;

	let encrypted_sym_key = match out.key {
		SymKey::Aes(k) => encrypt_symmetric(master_key, &k)?,
	};

	Ok((encrypted_sym_key, out.alg, out.key))
}

/**
Decrypt and return a sym key by another sym key
*/
pub fn get_symmetric_key_from_master_key(master_key: &SymKey, encrypted_symmetric_key: &[u8], alg: &str) -> Result<SymKey, Error>
{
	let decrypted_symmetric_key = decrypt_symmetric(master_key, encrypted_symmetric_key)?;

	let key = match alg {
		alg::sym::aes_gcm::AES_GCM_OUTPUT => {
			SymKey::Aes(
				decrypted_symmetric_key
					.try_into()
					.map_err(|_| Error::KeyDecryptFailed)?,
			)
		},
		_ => return Err(Error::AlgNotFound),
	};

	Ok(key)
}

/**
Generate a sym key and encrypt it with a public key
*/
pub fn generate_symmetric_with_public_key(public_key: &Pk) -> Result<(Vec<u8>, &'static str, SymKey), Error>
{
	let out = generate_symmetric()?;

	let encrypted_sym_key = match &out.key {
		SymKey::Aes(k) => encrypt_asymmetric(public_key, k)?,
	};

	//need to return the key because this can't be fetched
	Ok((encrypted_sym_key, out.alg, out.key))
}

/**
Decrypt and a sym key by private key
*/
pub fn get_symmetric_key_from_private_key(private_key: &Sk, encrypted_symmetric_key: &[u8], alg: &str) -> Result<SymKey, Error>
{
	let decrypted_symmetric_key = decrypt_asymmetric(private_key, encrypted_symmetric_key)?;

	let key = match alg {
		alg::sym::aes_gcm::AES_GCM_OUTPUT => {
			SymKey::Aes(
				decrypted_symmetric_key
					.try_into()
					.map_err(|_| Error::KeyDecryptFailed)?,
			)
		},
		_ => return Err(Error::AlgNotFound),
	};

	Ok(key)
}

//__________________________________________________________________________________________________

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

pub fn sign_only(sign_key: &SignK, data_to_sign: &[u8]) -> Result<Sig, Error>
{
	match sign_key {
		SignK::Ed25519(_) => alg::sign::ed25519::sign_only(sign_key, data_to_sign),
	}
}

pub fn verify<'a>(verify_key: &VerifyK, data_with_sign: &'a [u8]) -> Result<(&'a [u8], bool), Error>
{
	match verify_key {
		VerifyK::Ed25519(_) => alg::sign::ed25519::verify(verify_key, data_with_sign),
	}
}

pub fn verify_only(verify_key: &VerifyK, sig: &Sig, data: &[u8]) -> Result<bool, Error>
{
	match verify_key {
		VerifyK::Ed25519(_) => alg::sign::ed25519::verify_only(verify_key, sig, data),
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

//__________________________________________________________________________________________________
//searchable encryption

pub fn encrypt_searchable(key: &HmacKey, data: &[u8]) -> Result<Vec<u8>, Error>
{
	match key {
		HmacKey::HmacSha256(k) => alg::hmac::hmac_sha256::auth_with_generated_key(k, data),
	}
}

pub fn verify_encrypted_searchable(key: &HmacKey, data: &[u8], check_mac: &[u8]) -> Result<bool, Error>
{
	match key {
		HmacKey::HmacSha256(k) => alg::hmac::hmac_sha256::verify_with_generated_key(k, data, check_mac),
	}
}
