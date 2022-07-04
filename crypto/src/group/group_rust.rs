use alloc::string::String;
use alloc::vec::Vec;

use sendclose_crypto_common::group::{GroupKeyServerOutput, KeyRotationInput};
use sendclose_crypto_core::Error;

use crate::group::{
	done_key_rotation_internally,
	get_group_keys_internally,
	key_rotation_internally,
	prepare_create_internally,
	prepare_group_keys_for_new_member_internally,
};
use crate::util::{PrivateKeyFormat, PublicKeyFormat, SymKeyFormat};

pub struct GroupData
{
	pub private_group_key: PrivateKeyFormat,
	pub public_group_key: PublicKeyFormat,
	pub group_key: SymKeyFormat,
}

pub fn prepare_create(creators_public_key: &PublicKeyFormat) -> Result<String, Error>
{
	prepare_create_internally(&creators_public_key.key, creators_public_key.key_id.as_str())
}

pub fn key_rotation(previous_group_key: &SymKeyFormat, invoker_public_key: &PublicKeyFormat) -> Result<String, Error>
{
	key_rotation_internally(
		&previous_group_key.key,
		&invoker_public_key.key,
		previous_group_key.key_id.as_str(),
		invoker_public_key.key_id.as_str(),
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
		public_key.key_id.as_str(),
	)
}

pub fn get_group_keys(private_key: &PrivateKeyFormat, server_output: &GroupKeyServerOutput) -> Result<GroupData, Error>
{
	let out = get_group_keys_internally(&private_key.key, server_output)?;

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

pub fn prepare_group_keys_for_new_member(requester_public_key: &PublicKeyFormat, group_keys: &[SymKeyFormat]) -> Result<String, Error>
{
	let mut split_group_keys = Vec::with_capacity(group_keys.len());
	let mut group_key_ids = Vec::with_capacity(group_keys.len());

	for group_key in group_keys {
		split_group_keys.push(&group_key.key);
		group_key_ids.push(group_key.key_id.as_str())
	}

	prepare_group_keys_for_new_member_internally(
		&requester_public_key.key,
		&split_group_keys,
		&group_key_ids,
		requester_public_key.key_id.as_str(),
	)
}
