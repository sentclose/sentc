use alloc::vec::Vec;

use crate::alg::pw_hash::argon2::{Argon2PwHash, ARGON_2_OUTPUT};
use crate::cryptomat::{PwHash, SymKey};
use crate::Error;

pub(crate) mod argon2;

macro_rules! prepare_export_single_value {
	($st:ty) => {
		impl $st
		{
			pub fn prepare_export(&self) -> &[u8]
			{
				match self {
					Self::Argon2(v) => v,
				}
			}

			pub fn get_alg_str(&self) -> &'static str
			{
				match self {
					Self::Argon2(_) => ARGON_2_OUTPUT,
				}
			}
		}
	};
}

pub(crate) fn get_hasher() -> impl PwHash
{
	#[cfg(feature = "argon2_hash")]
	Argon2PwHash
}

pub(crate) fn get_hasher_from_alg(alg: &str) -> Result<impl PwHash, Error>
{
	match alg {
		ARGON_2_OUTPUT => Ok(Argon2PwHash),
		_ => Err(Error::AlgNotFound),
	}
}

pub enum ClientRandomValue
{
	Argon2([u8; 16]),
}

impl ClientRandomValue
{
	pub fn generate_salt(self, add_str: &str) -> Vec<u8>
	{
		match self {
			ClientRandomValue::Argon2(v) => argon2::generate_salt(v, add_str),
		}
	}
}

prepare_export_single_value!(ClientRandomValue);

pub enum HashedAuthenticationKey
{
	Argon2([u8; 16]), //16 bytes of the org. hashed key
}

prepare_export_single_value!(HashedAuthenticationKey);

pub enum DeriveMasterKeyForAuth
{
	Argon2([u8; 32]),
}

impl DeriveMasterKeyForAuth
{
	pub fn get_master_key(&self, encrypted_master_key: &[u8]) -> Result<impl SymKey, Error>
	{
		match self {
			DeriveMasterKeyForAuth::Argon2(k) => argon2::get_master_key(k, encrypted_master_key),
		}
	}
}

prepare_export_single_value!(DeriveMasterKeyForAuth);

pub enum DeriveAuthKeyForAuth
{
	Argon2([u8; 32]),
}

impl DeriveAuthKeyForAuth
{
	pub fn hash_auth_key(&self) -> Result<HashedAuthenticationKey, Error>
	{
		match self {
			DeriveAuthKeyForAuth::Argon2(k) => argon2::get_hashed_auth_key(k),
		}
	}
}

prepare_export_single_value!(DeriveAuthKeyForAuth);

pub enum PasswordEncryptSalt
{
	Argon2([u8; 16]), //export salt as enum because we can't know the length for every alg
}

prepare_export_single_value!(PasswordEncryptSalt);
