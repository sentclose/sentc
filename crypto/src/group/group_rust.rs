use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::group::{GroupKeyServerOutput, GroupServerData, KeyRotationInput};
use sentc_crypto_common::user::UserPublicKeyData;
use sentc_crypto_common::GroupId;

use crate::group::{
	done_key_rotation_internally,
	get_group_keys_internally,
	key_rotation_internally,
	prepare_create_internally,
	prepare_group_keys_for_new_member_internally,
	GroupKeyData,
};
use crate::util::{PrivateKeyFormat, PrivateKeyFormatInt, PublicKeyFormat, SymKeyFormat};
use crate::util_pub::handle_server_response;
use crate::SdkError;

pub struct GroupOutData
{
	pub keys: Vec<GroupKeyData>,
	pub group_id: String,
}

pub fn prepare_create(creators_public_key: &PublicKeyFormat, parent_group_id: Option<GroupId>) -> Result<String, SdkError>
{
	prepare_create_internally(&creators_public_key, parent_group_id)
}

pub fn key_rotation(previous_group_key: &SymKeyFormat, invoker_public_key: &PublicKeyFormat) -> Result<String, SdkError>
{
	key_rotation_internally(&previous_group_key, &invoker_public_key)
}

pub fn done_key_rotation(
	private_key: &PrivateKeyFormat,
	public_key: &PublicKeyFormat,
	previous_group_key: &SymKeyFormat,
	server_output: &KeyRotationInput,
) -> Result<String, SdkError>
{
	done_key_rotation_internally(&private_key, &public_key, &previous_group_key, server_output)
}

fn get_group_keys(private_key: &PrivateKeyFormatInt, server_output: &GroupKeyServerOutput) -> Result<GroupKeyData, SdkError>
{
	get_group_keys_internally(private_key, server_output)
}

pub fn get_group_data(private_key: &PrivateKeyFormat, server_output: &str) -> Result<GroupOutData, SdkError>
{
	let server_output: GroupServerData = handle_server_response(server_output)?;

	let mut keys = Vec::with_capacity(server_output.keys.len());

	for key in &server_output.keys {
		keys.push(get_group_keys(private_key, key)?);
	}

	Ok(GroupOutData {
		keys,
		group_id: server_output.group_id.clone(),
	})
}

pub fn prepare_group_keys_for_new_member(requester_public_key_data: &UserPublicKeyData, group_keys: &[&SymKeyFormat]) -> Result<String, SdkError>
{
	prepare_group_keys_for_new_member_internally(requester_public_key_data, group_keys)
}

#[cfg(test)]
mod test
{
	use alloc::string::ToString;
	use alloc::vec;

	use base64ct::{Base64, Encoding};
	use sentc_crypto_common::group::{CreateData, DoneKeyRotationData, GroupKeysForNewMemberServerInput, KeyRotationData};
	use sentc_crypto_common::ServerOutput;
	use sentc_crypto_core::crypto::encrypt_asymmetric as encrypt_asymmetric_core;
	use sentc_crypto_core::SymKey;

	use super::*;
	use crate::group::test_fn::create_group;
	use crate::user::test_fn::create_user;

	#[test]
	fn test_create_group()
	{
		//create a rust dummy user
		let user = create_user();

		let group = prepare_create(&user.public_key, None).unwrap();
		let group = CreateData::from_string(group.as_str()).unwrap();

		assert_eq!(group.creator_public_key_id, user.public_key.key_id);
	}

	#[test]
	fn test_create_and_get_group()
	{
		//test here only basic functions, if function panics. the key test is done in crypto mod

		let user = create_user();

		let (data, _) = create_group(&user);

		assert_eq!(data.group_id, "123".to_string());
	}

	#[test]
	fn test_prepare_group_keys_for_new_member()
	{
		let user = create_user();
		let user1 = create_user();

		let group_create = prepare_create(&user.public_key, None).unwrap();
		let group_create = CreateData::from_string(group_create.as_str()).unwrap();

		let group_server_output_user_0 = GroupKeyServerOutput {
			encrypted_group_key: group_create.encrypted_group_key.to_string(),
			group_key_alg: group_create.group_key_alg.to_string(),
			group_key_id: "123".to_string(),
			encrypted_private_group_key: group_create.encrypted_private_group_key.to_string(),
			public_group_key: group_create.public_group_key.to_string(),
			keypair_encrypt_alg: group_create.keypair_encrypt_alg.to_string(),
			key_pair_id: "123".to_string(),
			user_public_key_id: "123".to_string(),
		};

		let group_server_output_user_0 = GroupServerData {
			group_id: "123".to_string(),
			parent_group_id: None,
			keys: vec![group_server_output_user_0],
			key_update: false,
			rank: 0,
			created_time: 0,
			joined_time: 0,
		};

		let server_output = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(group_server_output_user_0),
		};

		let group_data_user_0 = get_group_data(&user.private_key, server_output.to_string().unwrap().as_str()).unwrap();

		//prepare the keys for user 1
		let out = prepare_group_keys_for_new_member(&user1.exported_public_key, &[&group_data_user_0.keys[0].group_key]).unwrap();
		let out = GroupKeysForNewMemberServerInput::from_string(out.as_str()).unwrap();
		let out_group_1 = &out.0[0]; //this group only got one key

		let group_server_output_user_1 = GroupKeyServerOutput {
			encrypted_group_key: out_group_1.encrypted_group_key.to_string(),
			group_key_alg: out_group_1.alg.to_string(),
			group_key_id: out_group_1.key_id.to_string(),
			encrypted_private_group_key: group_create.encrypted_private_group_key,
			public_group_key: group_create.public_group_key,
			keypair_encrypt_alg: group_create.keypair_encrypt_alg,
			key_pair_id: "123".to_string(),
			user_public_key_id: "123".to_string(),
		};

		let group_server_output_user_1 = GroupServerData {
			group_id: "123".to_string(),
			parent_group_id: None,
			keys: vec![group_server_output_user_1],
			key_update: false,
			rank: 0,
			created_time: 0,
			joined_time: 0,
		};

		let server_output = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(group_server_output_user_1),
		};

		let group_data_user_1 = get_group_data(&user1.private_key, server_output.to_string().unwrap().as_str()).unwrap();

		assert_eq!(
			group_data_user_0.keys[0].group_key.key_id,
			group_data_user_1.keys[0].group_key.key_id
		);

		match (
			&group_data_user_0.keys[0].group_key.key,
			&group_data_user_1.keys[0].group_key.key,
		) {
			(SymKey::Aes(k0), SymKey::Aes(k1)) => {
				assert_eq!(*k0, *k1);
			},
		}
	}

	#[test]
	fn test_key_rotation()
	{
		let user = create_user();

		let (data, group_server_out) = create_group(&user);

		let rotation_out = key_rotation(&data.keys[0].group_key, &user.public_key).unwrap();
		let rotation_out = KeyRotationData::from_string(rotation_out.as_str()).unwrap();

		//get the new group key directly because for the invoker the key is already encrypted by the own public key
		let server_key_output_direct = GroupKeyServerOutput {
			encrypted_group_key: rotation_out.encrypted_group_key_by_user.to_string(),
			group_key_alg: group_server_out.keys[0].group_key_alg.to_string(),
			group_key_id: group_server_out.keys[0].group_key_id.to_string(),
			encrypted_private_group_key: rotation_out.encrypted_private_group_key.to_string(),
			public_group_key: rotation_out.public_group_key.to_string(),
			keypair_encrypt_alg: rotation_out.keypair_encrypt_alg.to_string(),
			key_pair_id: "new_key_id_from_server".to_string(),
			user_public_key_id: user.public_key.key_id.to_string(),
		};

		let new_group_key_direct = get_group_keys(&user.private_key, &server_key_output_direct).unwrap();

		//simulate server key rotation encrypt. encrypt the ephemeral_key (encrypted by the previous room key) with the public keys of all users
		let encrypted_ephemeral_key = Base64::decode_vec(rotation_out.encrypted_ephemeral_key.as_str()).unwrap();
		let encrypted_ephemeral_key_by_group_key_and_public_key = encrypt_asymmetric_core(&user.public_key.key, &encrypted_ephemeral_key).unwrap();

		let server_output = KeyRotationInput {
			encrypted_ephemeral_key_by_group_key_and_public_key: Base64::encode_string(&encrypted_ephemeral_key_by_group_key_and_public_key),
			encrypted_group_key_by_ephemeral: rotation_out.encrypted_group_key_by_ephemeral.to_string(),
			ephemeral_alg: rotation_out.ephemeral_alg.to_string(),
			previous_group_key_id: rotation_out.previous_group_key_id.to_string(),
		};

		let done_key_rotation = done_key_rotation(
			&user.private_key,
			&user.public_key,
			&data.keys[0].group_key,
			&server_output,
		)
		.unwrap();
		let done_key_rotation = DoneKeyRotationData::from_string(done_key_rotation.as_str()).unwrap();

		//get the new group keys
		let server_key_output = GroupKeyServerOutput {
			encrypted_group_key: done_key_rotation.encrypted_new_group_key.to_string(),
			group_key_alg: group_server_out.keys[0].group_key_alg.to_string(),
			group_key_id: group_server_out.keys[0].group_key_id.to_string(),
			encrypted_private_group_key: rotation_out.encrypted_private_group_key.to_string(),
			public_group_key: rotation_out.public_group_key.to_string(),
			keypair_encrypt_alg: rotation_out.keypair_encrypt_alg.to_string(),
			key_pair_id: "new_key_id_from_server".to_string(),
			user_public_key_id: done_key_rotation.public_key_id.to_string(),
		};

		let out = get_group_keys(&user.private_key, &server_key_output).unwrap();

		//the new group key must be different after key rotation
		match (&data.keys[0].group_key.key, &out.group_key.key) {
			(SymKey::Aes(k_old), SymKey::Aes(k_new)) => {
				assert_ne!(*k_old, *k_new);
			},
		}

		match (&new_group_key_direct.group_key.key, &out.group_key.key) {
			(SymKey::Aes(k_0), SymKey::Aes(k_1)) => {
				//should be the same for all users
				assert_eq!(*k_0, *k_1);
			},
		}
	}
}
