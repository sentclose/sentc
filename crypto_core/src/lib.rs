//! # Sentclose crypto crate
//! This create is non_std with alloc
//!    
//! used alg:
//! - Password hashing
//! 	- argon2
//! - symmetric encryption:
//! 	- aes gcm
//! - asymmetric encryption:
//! 	- ecies based on x25519
//! - signing
//! 	- ed25519
//! - hmac
//! 	- hmac sha256
//!
//! This create can be used as stand alone version without the sentclose api

#![no_std]
#![allow(clippy::infallible_destructuring_match, clippy::tabs_in_doc_comments)]

extern crate alloc;

mod alg;
pub mod crypto;
mod error;
pub mod group;
pub mod user;

use alloc::vec::Vec;

use rand_core::{CryptoRng, OsRng, RngCore};

pub use self::alg::asym::ecies::ECIES_OUTPUT;
pub(crate) use self::alg::asym::AsymKeyOutput;
pub use self::alg::asym::{getting_alg_from_private_key, getting_alg_from_public_key, Pk, Sk};
pub use self::alg::hmac::hmac_sha256::HMAC_SHA256_OUTPUT;
pub(crate) use self::alg::hmac::HmacKeyOutput;
pub use self::alg::hmac::{getting_alg_from_hmac_key, HmacKey};
pub use self::alg::pw_hash::argon2::ARGON_2_OUTPUT;
pub use self::alg::pw_hash::{
	ClientRandomValue,
	DeriveAuthKeyForAuth,
	DeriveKeyOutput,
	DeriveKeysForAuthOutput,
	DeriveMasterKeyForAuth,
	HashedAuthenticationKey,
	MasterKeyInfo,
	PasswordEncryptOutput,
	PasswordEncryptSalt,
};
pub use self::alg::sign::ed25519::ED25519_OUTPUT;
pub(crate) use self::alg::sign::SignOutput;
pub use self::alg::sign::{get_alg_from_sig, get_alg_from_sign_key, get_alg_from_verify_key, SafetyNumber, Sig, SignK, VerifyK};
pub use self::alg::sortable::{getting_alg_from_sortable_key, SortableKey};
pub use self::alg::sym::aes_gcm::AES_GCM_OUTPUT;
pub use self::alg::sym::{getting_alg_from_sym_key, SymKey, SymKeyOutput};
pub use self::error::Error;

pub fn generate_salt(client_random_value: ClientRandomValue, add_str: &str) -> Vec<u8>
{
	match client_random_value {
		ClientRandomValue::Argon2(v) => alg::pw_hash::argon2::generate_salt(v, add_str),
	}
}

pub fn hash_auth_key(auth_key: &DeriveAuthKeyForAuth) -> Result<HashedAuthenticationKey, Error>
{
	match auth_key {
		DeriveAuthKeyForAuth::Argon2(k) => alg::pw_hash::argon2::get_hashed_auth_key(k),
	}
}

fn get_rand() -> impl CryptoRng + RngCore
{
	#[cfg(feature = "default_env")]
	OsRng
}

pub fn decrypt_private_key(encrypted_private_key: &[u8], master_key: &SymKey, keypair_encrypt_alg: &str) -> Result<Sk, Error>
{
	let private_key = match master_key {
		SymKey::Aes(k) => alg::sym::aes_gcm::decrypt_with_generated_key(k, encrypted_private_key)?,
	};

	match keypair_encrypt_alg {
		ECIES_OUTPUT => {
			let private = private_key
				.try_into()
				.map_err(|_| Error::DecodePrivateKeyFailed)?;

			Ok(Sk::Ecies(private))
		},
		_ => Err(Error::AlgNotFound),
	}
}

pub fn decrypt_sign_key(encrypted_sign_key: &[u8], master_key: &SymKey, keypair_sign_alg: &str) -> Result<SignK, Error>
{
	let sign_key = match master_key {
		SymKey::Aes(k) => alg::sym::aes_gcm::decrypt_with_generated_key(k, encrypted_sign_key)?,
	};

	match keypair_sign_alg {
		ED25519_OUTPUT => {
			let sign = sign_key
				.try_into()
				.map_err(|_| Error::DecodePrivateKeyFailed)?;

			Ok(SignK::Ed25519(sign))
		},
		_ => Err(Error::AlgNotFound),
	}
}

pub fn generate_user_register_data() -> Result<([u8; 20], [u8; 40]), Error>
{
	let mut identifier = [0u8; 20];
	let mut password = [0u8; 40];

	let mut rng = get_rand();

	rng.try_fill_bytes(&mut identifier)
		.map_err(|_| Error::KeyCreationFailed)?;

	rng.try_fill_bytes(&mut password)
		.map_err(|_| Error::KeyCreationFailed)?;

	Ok((identifier, password))
}
