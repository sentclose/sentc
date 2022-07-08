use alloc::string::String;
use alloc::vec::Vec;

use sendclose_crypto_common::group::{GroupKeyServerOutput, GroupNewMemberPublicKeyData, GroupServerData, KeyRotationInput};
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

#[cfg(feature = "rust")]
pub fn prepare_create(creators_public_key: &PublicKeyFormat) -> Result<String, Error>
{
	#[cfg(feature = "rust")]
	prepare_create_internally(&creators_public_key)
}

#[cfg(feature = "rust")]
pub fn key_rotation(previous_group_key: &SymKeyFormat, invoker_public_key: &PublicKeyFormat) -> Result<String, Error>
{
	#[cfg(feature = "rust")]
	key_rotation_internally(&previous_group_key, &invoker_public_key)
}

#[cfg(feature = "rust")]
pub fn done_key_rotation(
	private_key: &PrivateKeyFormat,
	public_key: &PublicKeyFormat,
	previous_group_key: &SymKeyFormat,
	server_output: &KeyRotationInput,
) -> Result<String, Error>
{
	#[cfg(feature = "rust")]
	done_key_rotation_internally(&private_key, &public_key, &previous_group_key, server_output)
}

#[cfg(feature = "rust")]
fn get_group_keys(private_key: &PrivateKeyFormatInt, server_output: &GroupKeyServerOutput) -> Result<GroupKeyData, Error>
{
	#[cfg(feature = "rust")]
	get_group_keys_internally(private_key, server_output)
}

#[cfg(feature = "rust")]
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

#[cfg(feature = "rust")]
pub fn prepare_group_keys_for_new_member(
	requester_public_key_data: &GroupNewMemberPublicKeyData,
	group_keys: &[&SymKeyFormat],
) -> Result<String, Error>
{
	#[cfg(feature = "rust")]
	prepare_group_keys_for_new_member_internally(requester_public_key_data, group_keys)
}

#[cfg(test)]
mod test
{
	use alloc::string::ToString;
	use alloc::vec;

	use sendclose_crypto_common::group::CreateData;

	use super::*;
	use crate::test::create_user;

	#[test]
	fn test_create_group()
	{
		//create a rust dummy user
		let user = create_user();

		let group = prepare_create(&user.public_key).unwrap();
		let group = CreateData::from_string(group.as_bytes()).unwrap();

		assert_eq!(group.creator_public_key_id, user.public_key.key_id);
	}

	#[test]
	fn test_create_and_get_group()
	{
		//test here only basic functions, if function panics. the key test is done in crypto mod

		let user = create_user();

		let group = prepare_create(&user.public_key).unwrap();
		let group = CreateData::from_string(group.as_bytes()).unwrap();

		let group_server_output = GroupKeyServerOutput {
			encrypted_group_key: group.encrypted_group_key,
			group_key_alg: group.group_key_alg,
			group_key_id: "123".to_string(),
			encrypted_private_group_key: group.encrypted_private_group_key,
			public_group_key: group.public_group_key,
			keypair_encrypt_alg: group.keypair_encrypt_alg,
			key_pair_id: "123".to_string(),
			user_public_key_id: "123".to_string(),
		};

		let group_server_output = GroupServerData {
			group_id: "123".to_string(),
			keys: vec![group_server_output],
			keys_page: 0,
		};

		let data = get_group_data(&user.private_key, &group_server_output).unwrap();

		assert_eq!(data.group_id, "123".to_string());
	}
}
