use alloc::vec::Vec;

use crate::alg::pw_hash::argon2::ARGON_2_OUTPUT;
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

			pub fn argon2_from_bytes_owned(bytes: Vec<u8>) -> Result<Self, Error>
			{
				Ok(Self::Argon2(bytes.try_into().map_err(|_| Error::KeyDecryptFailed)?))
			}
		}
	};
}

pub struct PwHasherGetter;

impl PwHash for PwHasherGetter
{
	fn derived_keys_from_password<M: SymKey>(
		password: &[u8],
		master_key: &M,
		alg: Option<&str>,
	) -> Result<(ClientRandomValue, HashedAuthenticationKey, Vec<u8>, &'static str), Error>
	{
		if let Some(alg) = alg {
			match alg {
				ARGON_2_OUTPUT => argon2::derived_keys_from_password(password, master_key),
				_ => Err(Error::AlgNotFound),
			}
		} else {
			argon2::derived_keys_from_password(password, master_key)
		}
	}

	fn derive_keys_for_auth(password: &[u8], salt_bytes: &[u8], alg: &str) -> Result<(DeriveMasterKeyForAuth, DeriveAuthKeyForAuth), Error>
	{
		match alg {
			ARGON_2_OUTPUT => argon2::derive_keys_for_auth(password, salt_bytes),
			_ => Err(Error::AlgNotFound),
		}
	}

	fn password_to_encrypt(password: &[u8]) -> Result<(PasswordEncryptSalt, impl SymKey), Error>
	{
		argon2::password_to_encrypt(password)
	}

	fn password_to_decrypt(password: &[u8], salt: &[u8]) -> Result<impl SymKey, Error>
	{
		argon2::password_to_decrypt(password, salt)
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
