use alloc::string::String;
use alloc::vec::Vec;

use sendclose_crypto_common::group::{GroupKeyServerOutput, GroupServerData, KeyRotationInput};
use sendclose_crypto_core::Error;

use crate::group::{
	done_key_rotation_internally,
	get_group_keys_internally,
	key_rotation_internally,
	prepare_create_internally,
	prepare_group_keys_for_new_member_internally,
	GroupKeyData,
};
use crate::util::{PrivateKeyFormat, PrivateKeyFormatInt, PublicKeyFormat, SymKeyFormat};

pub struct GroupOutData
{
	pub keys: Vec<GroupKeyData>,
	pub group_id: String,
}

pub fn prepare_create(creators_public_key: &PublicKeyFormat) -> Result<String, Error>
{
	prepare_create_internally(&creators_public_key)
}

pub fn key_rotation(previous_group_key: &SymKeyFormat, invoker_public_key: &PublicKeyFormat) -> Result<String, Error>
{
	key_rotation_internally(&previous_group_key, &invoker_public_key)
}

pub fn done_key_rotation(
	private_key: &PrivateKeyFormat,
	public_key: &PublicKeyFormat,
	previous_group_key: &SymKeyFormat,
	server_output: &KeyRotationInput,
) -> Result<String, Error>
{
	done_key_rotation_internally(&private_key, &public_key, &previous_group_key, server_output)
}

fn get_group_keys(private_key: &PrivateKeyFormatInt, server_output: &GroupKeyServerOutput) -> Result<GroupKeyData, Error>
{
	get_group_keys_internally(private_key, server_output)
}

pub fn get_group_data(private_key: &PrivateKeyFormat, server_output: &GroupServerData) -> Result<GroupOutData, Error>
{
	let mut keys = Vec::with_capacity(server_output.keys.len());

	for key in &server_output.keys {
		keys.push(get_group_keys(private_key, key)?);
	}

	Ok(GroupOutData {
		keys,
		group_id: server_output.group_id.clone(),
	})
}

pub fn prepare_group_keys_for_new_member(requester_public_key: &PublicKeyFormat, group_keys: &[&SymKeyFormat]) -> Result<String, Error>
{
	prepare_group_keys_for_new_member_internally(&requester_public_key, group_keys)
}
