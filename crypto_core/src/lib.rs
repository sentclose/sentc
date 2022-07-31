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
//!
//! This create can be used as stand alone version without the sentclose api

#![no_std]

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
pub use self::alg::sign::{get_alg_from_sign_key, get_alg_from_verify_key, SignK, VerifyK};
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
