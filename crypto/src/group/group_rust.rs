use alloc::string::String;

use sendclose_crypto_common::group::{GroupServerOutput, KeyRotationInput};
use sendclose_crypto_core::Error;

use crate::group::{done_key_rotation_internally, get_group_internally, key_rotation_internally, prepare_create_internally};
use crate::util::{PublicKeyFormat, SymKeyFormat};
use crate::PrivateKeyFormat;

pub struct GroupData
{
	pub private_group_key: PrivateKeyFormat,
	pub public_group_key: PublicKeyFormat,
	pub group_key: SymKeyFormat,
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

pub fn get_group(private_key: &PrivateKeyFormat, server_output: &GroupServerOutput) -> Result<GroupData, Error>
{
	let out = get_group_internally(&private_key.key, server_output)?;

	Ok(GroupData {
		private_group_key: PrivateKeyFormat {
			key: out.private_group_key,
			key_id: out.key_pair_id.clone(),
		},
		public_group_key: PublicKeyFormat {
			key: out.public_group_key,
			key_id: out.key_pair_id,
		},
		group_key: SymKeyFormat {
			key: out.group_key,
			key_id: out.group_key_id,
		},
	})
}
