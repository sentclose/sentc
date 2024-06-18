use alloc::vec::Vec;

use sentc_crypto_core::cryptomat::{ClientRandomValueComposer, CryptoAlg, PwHash, PwPrepareExport, SymKey};
use sentc_crypto_core::{cryptomat, Error};

use crate::core::pw_hash::argon2::ARGON_2_OUTPUT;
use crate::crypto_alg_str_impl;

pub(crate) mod argon2;

macro_rules! prepare_export_single_value {
	($st:ty) => {
		impl $st
		{
			pub fn argon2_from_bytes_owned(bytes: Vec<u8>) -> Result<Self, Error>
			{
				Ok(Self::Argon2(bytes.try_into().map_err(|_| Error::KeyDecryptFailed)?))
			}
		}
	};
}

macro_rules! prepare_export {
	($st:ty) => {
		impl PwPrepareExport for $st
		{
			fn prepare_export(&self) -> &[u8]
			{
				match self {
					Self::Argon2(v) => v,
				}
			}
		}
	};
}

pub struct PwHasherGetter;

impl PwHash for PwHasherGetter
{
	type CRV = ClientRandomValue;
	type HAK = HashedAuthenticationKey;
	type DMK = DeriveMasterKeyForAuth;
	type DAK = DeriveAuthKeyForAuth;
	type PWS = PasswordEncryptSalt;

	fn derived_keys_from_password<M: SymKey>(
		password: &[u8],
		master_key: &M,
		alg: Option<&str>,
	) -> Result<(Self::CRV, Self::HAK, Vec<u8>, &'static str), Error>
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

	fn derive_keys_for_auth(password: &[u8], salt_bytes: &[u8], alg: &str) -> Result<(Self::DMK, Self::DAK), Error>
	{
		match alg {
			ARGON_2_OUTPUT => argon2::derive_keys_for_auth(password, salt_bytes),
			_ => Err(Error::AlgNotFound),
		}
	}

	fn password_to_encrypt(password: &[u8]) -> Result<(Self::PWS, impl SymKey), Error>
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

crypto_alg_str_impl!(ClientRandomValue, ARGON_2_OUTPUT);

prepare_export!(ClientRandomValue);
prepare_export_single_value!(ClientRandomValue);

impl cryptomat::ClientRandomValue for ClientRandomValue
{
	fn generate_salt(self, add_str: &str) -> Vec<u8>
	{
		match self {
			ClientRandomValue::Argon2(v) => argon2::generate_salt(v, add_str),
		}
	}
}

impl ClientRandomValueComposer for ClientRandomValue
{
	type Value = Self;

	fn from_bytes(vec: Vec<u8>, alg: &str) -> Result<Self::Value, Error>
	{
		match alg {
			ARGON_2_OUTPUT => {
				let v = vec.try_into().map_err(|_| Error::KeyDecryptFailed)?;

				Ok(Self::Argon2(v))
			},
			_ => Err(Error::AlgNotFound),
		}
	}
}

pub enum HashedAuthenticationKey
{
	Argon2([u8; 16]), //16 bytes of the org. hashed key
}

prepare_export!(HashedAuthenticationKey);
prepare_export_single_value!(HashedAuthenticationKey);

impl cryptomat::HashedAuthenticationKey for HashedAuthenticationKey {}

pub enum DeriveMasterKeyForAuth
{
	Argon2([u8; 32]),
}

prepare_export!(DeriveMasterKeyForAuth);
prepare_export_single_value!(DeriveMasterKeyForAuth);

impl cryptomat::DeriveMasterKeyForAuth for DeriveMasterKeyForAuth
{
	fn get_master_key(&self, encrypted_master_key: &[u8]) -> Result<impl SymKey, Error>
	{
		match self {
			DeriveMasterKeyForAuth::Argon2(k) => argon2::get_master_key(k, encrypted_master_key),
		}
	}
}

pub enum DeriveAuthKeyForAuth
{
	Argon2([u8; 32]),
}

prepare_export!(DeriveAuthKeyForAuth);
prepare_export_single_value!(DeriveAuthKeyForAuth);

impl cryptomat::DeriveAuthKeyForAuth for DeriveAuthKeyForAuth
{
	fn hash_auth_key(&self) -> Result<Vec<u8>, Error>
	{
		match self {
			DeriveAuthKeyForAuth::Argon2(k) => argon2::get_hashed_auth_key(k),
		}
	}
}

impl cryptomat::DeriveAuthKeyForAuthComposer for DeriveAuthKeyForAuth
{
	type Value = Self;

	fn from_bytes(vec: Vec<u8>, alg: &str) -> Result<Self::Value, Error>
	{
		match alg {
			ARGON_2_OUTPUT => {
				let v = vec.try_into().map_err(|_| Error::KeyDecryptFailed)?;

				Ok(Self::Argon2(v))
			},
			_ => Err(Error::AlgNotFound),
		}
	}
}

pub enum PasswordEncryptSalt
{
	Argon2([u8; 16]), //export salt as enum because we can't know the length for every alg
}

prepare_export!(PasswordEncryptSalt);
prepare_export_single_value!(PasswordEncryptSalt);

impl cryptomat::PasswordEncryptSalt for PasswordEncryptSalt {}
