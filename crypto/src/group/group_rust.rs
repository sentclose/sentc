use alloc::string::String;

use sendclose_crypto_common::group::KeyRotationInput;
use sendclose_crypto_core::{Error, SymKey};

use crate::group::{done_key_rotation_internally, key_rotation_internally, prepare_create_internally};
use crate::user::{PrivateKeyFormat, PublicKeyFormat};

pub struct SymKeyFormat
{
	pub key: SymKey,
	pub key_id: String,
}

pub fn prepare_create(creators_public_key: &PublicKeyFormat) -> Result<String, Error>
{
	prepare_create_internally(&creators_public_key.key, creators_public_key.key_id.clone())
}

pub fn key_rotation(previous_group_key: &SymKeyFormat, invoker_public_key: &PublicKeyFormat) -> Result<String, Error>
{
	key_rotation_internally(
		&previous_group_key.key,
		&invoker_public_key.key,
		previous_group_key.key_id.clone(),
		invoker_public_key.key_id.clone(),
	)
}

pub fn done_key_rotation(
	private_key: &PrivateKeyFormat,
	public_key: &PublicKeyFormat,
	previous_group_key: &SymKeyFormat,
	server_output: &KeyRotationInput,
) -> Result<String, Error>
{
	done_key_rotation_internally(
		&private_key.key,
		&public_key.key,
		&previous_group_key.key,
		server_output,
		public_key.key_id.clone(),
	)
}

//TODO export the group sym key for get group
