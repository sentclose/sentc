use alloc::vec::Vec;

use pqc_dilithium_edit::{PUBLICKEYBYTES, SECRETKEYBYTES, SIGNBYTES};
use sha2::{Digest, Sha256};

use crate::{Error, DILITHIUM_OUTPUT, ED25519_OUTPUT};

pub(crate) mod ed25519;
pub(crate) mod pqc_dilithium;

#[allow(clippy::large_enum_variant)]
pub enum SignK
{
	Ed25519([u8; 32]),
	Dilithium([u8; SECRETKEYBYTES]),
}

#[allow(clippy::large_enum_variant)]
pub enum VerifyK
{
	Ed25519([u8; 32]),
	Dilithium([u8; PUBLICKEYBYTES]),
}

#[allow(clippy::large_enum_variant)]
pub enum Sig
{
	Ed25519([u8; 64]),
	Dilithium([u8; SIGNBYTES]),
}

pub(crate) struct SignOutput
{
	pub alg: &'static str,
	pub sign_key: SignK,
	pub verify_key: VerifyK,
}

pub struct SafetyNumber<'a>
{
	pub verify_key: &'a VerifyK,
	pub user_info: &'a str,
}

pub fn get_alg_from_sign_key(key: &SignK) -> &'static str
{
	match key {
		SignK::Ed25519(_) => ED25519_OUTPUT,
		SignK::Dilithium(_) => DILITHIUM_OUTPUT,
	}
}

pub fn get_alg_from_verify_key(key: &VerifyK) -> &'static str
{
	match key {
		VerifyK::Ed25519(_) => ED25519_OUTPUT,
		VerifyK::Dilithium(_) => DILITHIUM_OUTPUT,
	}
}

pub fn get_alg_from_sig(sig: &Sig) -> &'static str
{
	match sig {
		Sig::Ed25519(_) => ED25519_OUTPUT,
		Sig::Dilithium(_) => DILITHIUM_OUTPUT,
	}
}

pub(crate) fn split_sig_and_data(data_with_sig: &[u8], len: usize) -> Result<(&[u8], &[u8]), Error>
{
	if data_with_sig.len() <= len {
		return Err(Error::DataToSignTooShort);
	}

	//split sign and data
	let sig = &data_with_sig[..len];
	let data = &data_with_sig[len..];

	Ok((sig, data))
}

pub(crate) fn safety_number(user_1: SafetyNumber, user_2: Option<SafetyNumber>) -> Vec<u8>
{
	let mut hasher = Sha256::new();

	match user_1.verify_key {
		VerifyK::Ed25519(k) => hasher.update(k),
		VerifyK::Dilithium(k) => hasher.update(k),
	}

	hasher.update(user_1.user_info.as_bytes());

	if let Some(u_2) = user_2 {
		match u_2.verify_key {
			VerifyK::Ed25519(k) => hasher.update(k),
			VerifyK::Dilithium(k) => hasher.update(k),
		}

		hasher.update(u_2.user_info.as_bytes());
	}

	let number_bytes = hasher.finalize();

	number_bytes.to_vec()
}
