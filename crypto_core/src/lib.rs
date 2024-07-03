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
#![allow(clippy::infallible_destructuring_match, clippy::tabs_in_doc_comments, clippy::from_over_into)]

extern crate alloc;

pub mod cryptomat;
mod error;
pub mod group;
pub mod user;

use rand_core::{CryptoRng, OsRng, RngCore};

pub use self::error::Error;

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

pub fn split_sig_and_data(data_with_sig: &[u8], len: usize) -> Result<(&[u8], &[u8]), Error>
{
	if data_with_sig.len() <= len {
		return Err(Error::DataToSignTooShort);
	}

	//split sign and data
	let sig = &data_with_sig[..len];
	let data = &data_with_sig[len..];

	Ok((sig, data))
}
