use alloc::string::String;

use sendclose_crypto_core::{Pk, SignK, Sk, SymKey, VerifyK};

pub struct PrivateKeyFormat
{
	pub key: Sk,
	pub key_id: String,
}

pub struct PublicKeyFormat
{
	pub key: Pk,
	pub key_id: String,
}

pub struct SignKeyFormat
{
	pub key: SignK,
	pub key_id: String,
}

pub struct VerifyKeyFormat
{
	pub key: VerifyK,
	pub key_id: String,
}

/**
# key storage structure for the rust feature

It can be used with other rust programs.

The different to the internally DoneLoginOutput ist that,
the KeyFormat is sued for each where, were the key id is saved too
 */
pub struct KeyData
{
	pub private_key: PrivateKeyFormat,
	pub sign_key: SignKeyFormat,
	pub public_key: PublicKeyFormat,
	pub verify_key: VerifyKeyFormat,
}

pub struct SymKeyFormat
{
	pub key: SymKey,
	pub key_id: String,
}
