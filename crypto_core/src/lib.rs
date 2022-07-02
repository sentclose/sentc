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

pub use self::alg::asym::ecies::ECIES_OUTPUT;
pub(crate) use self::alg::asym::AsymKeyOutput;
pub use self::alg::asym::{Pk, Sk};
pub use self::alg::pw_hash::argon2::ARGON_2_OUTPUT;
pub use self::alg::pw_hash::{
	ClientRandomValue,
	DeriveAuthKeyForAuth,
	DeriveKeyOutput,
	DeriveKeysForAuthOutput,
	DeriveMasterKeyForAuth,
	HashedAuthenticationKey,
	MasterKeyInfo,
};
pub use self::alg::sign::ed25519::ED25519_OUTPUT;
pub(crate) use self::alg::sign::SignOutput;
pub use self::alg::sign::{SignK, VerifyK};
pub use self::alg::sym::aes_gcm::AES_GCM_OUTPUT;
pub use self::alg::sym::SymKey;
pub(crate) use self::alg::sym::SymKeyOutput;
pub use self::error::Error;

pub fn generate_salt(client_random_value: ClientRandomValue) -> Vec<u8>
{
	match client_random_value {
		ClientRandomValue::Argon2(v) => alg::pw_hash::argon2::generate_salt(v),
	}
}
