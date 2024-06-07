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
//! This create can be used as stand-alone version without the sentclose api

#![no_std]
#![allow(clippy::infallible_destructuring_match, clippy::tabs_in_doc_comments)]

extern crate alloc;

mod alg;
pub mod cryptomat;
mod error;
pub mod group;
pub mod user;

use alloc::vec::Vec;

use rand_core::{CryptoRng, OsRng, RngCore};

pub use self::alg::asym::ecies::{EciesKeyPair, EciesPk, EciesSk, ECIES_OUTPUT};
pub use self::alg::asym::ecies_kyber_hybrid::{EciesKyberHybridKeyPair, EciesKyberHybridPk, EciesKyberHybridSk, ECIES_KYBER_HYBRID_OUTPUT};
pub use self::alg::asym::pqc_kyber::{KyberKeyPair, KyberPk, KyberSk, KYBER_OUTPUT};
pub use self::alg::asym::{PublicKey, SecretKey};
pub use self::alg::hmac::hmac_sha256::{HmacSha256Key, HMAC_SHA256_OUTPUT};
pub use self::alg::hmac::HmacKey;
pub use self::alg::pw_hash::argon2::ARGON_2_OUTPUT;
pub use self::alg::pw_hash::{
	ClientRandomValue,
	DeriveAuthKeyForAuth,
	DeriveMasterKeyForAuth,
	HashedAuthenticationKey,
	PasswordEncryptSalt,
	PwHasherGetter,
};
pub use self::alg::sign::ed25519::{Ed25519KeyPair, Ed25519Sig, Ed25519SignK, Ed25519VerifyK, ED25519_OUTPUT};
pub use self::alg::sign::ed25519_dilithium_hybrid::{
	Ed25519DilithiumHybridKeyPair,
	Ed25519DilithiumHybridSig,
	Ed25519DilithiumHybridSignK,
	Ed25519DilithiumHybridVerifyKey,
	ED25519_DILITHIUM_HYBRID_OUTPUT,
};
pub use self::alg::sign::pqc_dilithium::DILITHIUM_OUTPUT;
pub use self::alg::sign::{SafetyNumber, SignKey, Signature, VerifyKey};
pub use self::alg::sortable::SortKeys;
pub use self::alg::sym::aes_gcm::{Aes256GcmKey, AES_GCM_OUTPUT};
pub use self::alg::sym::SymmetricKey;
pub use self::error::Error;

pub fn generate_salt(client_random_value: ClientRandomValue, add_str: &str) -> Vec<u8>
{
	client_random_value.generate_salt(add_str)
}

fn get_rand() -> impl CryptoRng + RngCore
{
	#[cfg(feature = "default_env")]
	OsRng
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
