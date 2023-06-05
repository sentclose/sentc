use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::group::{CreateData, GroupHmacData, GroupKeyServerOutput, GroupKeysForNewMemberServerInput, KeyRotationInput};
use sentc_crypto_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto_common::UserId;

use crate::entities::group::{GroupKeyData, GroupOutData, GroupOutDataLight};
use crate::entities::keys::{HmacKeyFormatInt, PrivateKeyFormatInt, PublicKeyFormatInt, SignKeyFormatInt, SymKeyFormatInt};
use crate::group::{
	decrypt_group_hmac_key_internally,
	decrypt_group_keys_internally,
	done_key_rotation_internally,
	get_done_key_rotation_server_input_internally,
	get_group_data_internally,
	get_group_key_from_server_output_internally,
	get_group_keys_from_server_output_internally,
	get_group_light_data_internally,
	key_rotation_internally,
	prepare_change_rank_internally,
	prepare_create_internally,
	prepare_create_typed_internally,
	prepare_group_keys_for_new_member_internally,
	prepare_group_keys_for_new_member_internally_with_group_public_key,
	prepare_group_keys_for_new_member_typed_internally,
	prepare_group_keys_for_new_member_via_session_internally,
};
use crate::SdkError;

pub fn prepare_create_typed(creators_public_key: &PublicKeyFormatInt) -> Result<CreateData, SdkError>
{
	let out = prepare_create_typed_internally(creators_public_key)?;

	Ok(out.0)
}

pub fn prepare_create(creators_public_key: &PublicKeyFormatInt) -> Result<String, SdkError>
{
	let out = prepare_create_internally(creators_public_key)?;

	Ok(out.0)
}

pub fn prepare_create_batch_typed(creators_public_key: &PublicKeyFormatInt) -> Result<(CreateData, PublicKeyFormatInt, SymKeyFormatInt), SdkError>
{
	prepare_create_typed_internally(creators_public_key)
}

pub fn prepare_create_batch(creators_public_key: &PublicKeyFormatInt) -> Result<(String, PublicKeyFormatInt, SymKeyFormatInt), SdkError>
{
	prepare_create_internally(creators_public_key)
}

pub fn key_rotation(
	previous_group_key: &SymKeyFormatInt,
	invoker_public_key: &PublicKeyFormatInt,
	user_group: bool,
	sign_key: Option<&SignKeyFormatInt>,
	starter: UserId,
) -> Result<String, SdkError>
{
	key_rotation_internally(previous_group_key, invoker_public_key, user_group, sign_key, starter)
}

pub fn get_done_key_rotation_server_input(server_output: &str) -> Result<KeyRotationInput, SdkError>
{
	get_done_key_rotation_server_input_internally(server_output)
}

pub fn done_key_rotation(
	private_key: &PrivateKeyFormatInt,
	public_key: &PublicKeyFormatInt,
	previous_group_key: &SymKeyFormatInt,
	server_output: KeyRotationInput,
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<String, SdkError>
{
	done_key_rotation_internally(private_key, public_key, previous_group_key, server_output, verify_key)
}

pub fn decrypt_group_hmac_key(key: &SymKeyFormatInt, server_output: GroupHmacData) -> Result<HmacKeyFormatInt, SdkError>
{
	decrypt_group_hmac_key_internally(key, server_output)
}

pub fn decrypt_group_keys(private_key: &PrivateKeyFormatInt, server_output: GroupKeyServerOutput) -> Result<GroupKeyData, SdkError>
{
	decrypt_group_keys_internally(private_key, server_output)
}

pub fn get_group_keys_from_server_output(server_output: &str) -> Result<Vec<GroupKeyServerOutput>, SdkError>
{
	get_group_keys_from_server_output_internally(server_output)
}

pub fn get_group_key_from_server_output(server_output: &str) -> Result<GroupKeyServerOutput, SdkError>
{
	get_group_key_from_server_output_internally(server_output)
}

pub fn get_group_light_data(server_output: &str) -> Result<GroupOutDataLight, SdkError>
{
	get_group_light_data_internally(server_output)
}

pub fn get_group_data(server_output: &str) -> Result<GroupOutData, SdkError>
{
	get_group_data_internally(server_output)
}

pub fn prepare_group_keys_for_new_member_with_group_public_key(
	requester_public_key: &PublicKeyFormatInt,
	group_keys: &[&SymKeyFormatInt],
	key_session: bool,
	rank: Option<i32>,
) -> Result<GroupKeysForNewMemberServerInput, SdkError>
{
	//the same like the other fn but with the public key format and not the exported public key from server fetch
	prepare_group_keys_for_new_member_internally_with_group_public_key(requester_public_key, group_keys, key_session, rank)
}

pub fn prepare_group_keys_for_new_member_typed(
	requester_public_key_data: &UserPublicKeyData,
	group_keys: &[&SymKeyFormatInt],
	key_session: bool,
	rank: Option<i32>,
) -> Result<GroupKeysForNewMemberServerInput, SdkError>
{
	prepare_group_keys_for_new_member_typed_internally(requester_public_key_data, group_keys, key_session, rank)
}

pub fn prepare_group_keys_for_new_member(
	requester_public_key_data: &UserPublicKeyData,
	group_keys: &[&SymKeyFormatInt],
	key_session: bool,
	rank: Option<i32>,
) -> Result<String, SdkError>
{
	prepare_group_keys_for_new_member_internally(requester_public_key_data, group_keys, key_session, rank)
}

pub fn prepare_group_keys_for_new_member_via_session(
	requester_public_key_data: &UserPublicKeyData,
	group_keys: &[&SymKeyFormatInt],
) -> Result<String, SdkError>
{
	prepare_group_keys_for_new_member_via_session_internally(requester_public_key_data, group_keys)
}

pub fn prepare_change_rank(user_id: &str, new_rank: i32, admin_rank: i32) -> Result<String, SdkError>
{
	prepare_change_rank_internally(user_id, new_rank, admin_rank)
}

#[cfg(test)]
mod test
{
	use alloc::string::ToString;
	use alloc::vec;

	use base64ct::{Base64, Encoding};
	use sentc_crypto_common::group::{
		CreateData,
		DoneKeyRotationData,
		GroupKeysForNewMember,
		GroupKeysForNewMemberServerInput,
		GroupServerData,
		GroupUserAccessBy,
		KeyRotationData,
	};
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
		let user_keys = &user.user_keys[0];

		let group = prepare_create(&user_keys.public_key).unwrap();
		let group = CreateData::from_string(group.as_str()).unwrap();

		assert_eq!(group.creator_public_key_id, user_keys.public_key.key_id);
	}

	#[test]
	fn test_create_and_get_group()
	{
		//test here only basic functions, if function panics. the key test is done in crypto mod

		let user = create_user();

		let (data, _, _, _) = create_group(&user.user_keys[0]);

		assert_eq!(data.group_id, "123".to_string());
	}

	#[test]
	fn test_get_group_data_and_keys()
	{
		let user = create_user();
		let user_keys = &user.user_keys[0];

		let (_, key_data, group_server_out, _) = create_group(user_keys);

		let keys = group_server_out.keys;

		//server output for one key
		let single_fetch = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(&keys[0]),
		};
		let single_fetch = serde_json::to_string(&single_fetch).unwrap();

		//server output for multiple keys
		let server_key_out = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(keys),
		};

		let server_key_out = server_key_out.to_string().unwrap();

		let group_keys_from_server_out = get_group_keys_from_server_output(server_key_out.as_str()).unwrap();

		let mut group_keys = Vec::with_capacity(group_keys_from_server_out.len());

		for k in group_keys_from_server_out {
			group_keys.push(decrypt_group_keys(&user_keys.private_key, k).unwrap());
		}

		match (&key_data[0].group_key.key, &group_keys[0].group_key.key) {
			(SymKey::Aes(k1), SymKey::Aes(k2)) => {
				assert_eq!(*k1, *k2);
			},
		}

		//fetch the key single
		let key = get_group_key_from_server_output(single_fetch.as_str()).unwrap();

		let group_keys_from_single_server_out = decrypt_group_keys(&user_keys.private_key, key).unwrap();

		match (
			&key_data[0].group_key.key,
			&group_keys_from_single_server_out.group_key.key,
		) {
			(SymKey::Aes(k1), SymKey::Aes(k2)) => {
				assert_eq!(*k1, *k2);
			},
		}
	}

	#[test]
	fn test_prepare_group_keys_for_new_member()
	{
		let user = create_user();
		let user_keys = &user.user_keys[0];

		let user1 = create_user();
		let user_keys1 = &user1.user_keys[0];

		let group_create = prepare_create(&user_keys.public_key).unwrap();
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
			time: 0,
			encrypted_sign_key: None,
			verify_key: None,
			keypair_sign_alg: None,
			keypair_sign_id: None,
			public_key_sig: None,
			public_key_sig_key_id: None,
		};

		let group_server_output_user_0 = GroupServerData {
			group_id: "123".to_string(),
			parent_group_id: None,
			keys: vec![group_server_output_user_0],
			key_update: false,
			rank: 0,
			created_time: 0,
			joined_time: 0,
			access_by: GroupUserAccessBy::User,
			is_connected_group: false,
			hmac_keys: vec![GroupHmacData {
				id: "123".to_string(),
				encrypted_hmac_encryption_key_id: "".to_string(),
				encrypted_hmac_key: group_create.encrypted_hmac_key.clone(),
				encrypted_hmac_alg: group_create.encrypted_hmac_alg.clone(),
				time: 0,
			}],
		};

		let server_output = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(group_server_output_user_0),
		};

		let group_data_user_0 = get_group_data(server_output.to_string().unwrap().as_str()).unwrap();

		let mut group_keys = Vec::with_capacity(group_data_user_0.keys.len());

		for key in group_data_user_0.keys {
			group_keys.push(decrypt_group_keys(&user_keys.private_key, key).unwrap());
		}

		//prepare the keys for user 1
		let out = prepare_group_keys_for_new_member(
			&user_keys1.exported_public_key,
			&[&group_keys[0].group_key],
			false,
			None,
		)
		.unwrap();
		let out = GroupKeysForNewMemberServerInput::from_string(out.as_str()).unwrap();
		let out_group_1 = &out.keys[0]; //this group only got one key

		let group_server_output_user_1 = GroupKeyServerOutput {
			encrypted_group_key: out_group_1.encrypted_group_key.to_string(),
			group_key_alg: out_group_1.alg.to_string(),
			group_key_id: out_group_1.key_id.to_string(),
			encrypted_private_group_key: group_create.encrypted_private_group_key,
			public_group_key: group_create.public_group_key,
			keypair_encrypt_alg: group_create.keypair_encrypt_alg,
			key_pair_id: "123".to_string(),
			user_public_key_id: "123".to_string(),
			time: 0,
			encrypted_sign_key: None,
			verify_key: None,
			keypair_sign_alg: None,
			keypair_sign_id: None,
			public_key_sig: None,
			public_key_sig_key_id: None,
		};

		let group_server_output_user_1 = GroupServerData {
			group_id: "123".to_string(),
			parent_group_id: None,
			keys: vec![group_server_output_user_1],
			key_update: false,
			rank: 0,
			created_time: 0,
			joined_time: 0,
			access_by: GroupUserAccessBy::User,
			is_connected_group: false,
			hmac_keys: vec![GroupHmacData {
				id: "123".to_string(),
				encrypted_hmac_encryption_key_id: "".to_string(),
				encrypted_hmac_key: group_create.encrypted_hmac_key,
				encrypted_hmac_alg: group_create.encrypted_hmac_alg,
				time: 0,
			}],
		};

		let server_output = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(group_server_output_user_1),
		};

		let group_data_user_1 = get_group_data(server_output.to_string().unwrap().as_str()).unwrap();

		let mut group_keys_u2 = Vec::with_capacity(group_data_user_1.keys.len());

		for key in group_data_user_1.keys {
			group_keys_u2.push(decrypt_group_keys(&user_keys1.private_key, key).unwrap());
		}

		assert_eq!(group_keys_u2[0].group_key.key_id, group_keys_u2[0].group_key.key_id);

		match (&group_keys[0].group_key.key, &group_keys_u2[0].group_key.key) {
			(SymKey::Aes(k0), SymKey::Aes(k1)) => {
				assert_eq!(*k0, *k1);
			},
		}
	}

	/**
	The same test as before but this time with prepare_group_keys_for_new_member_via_session
	*/
	#[test]
	fn test_prepare_group_keys_for_new_member_via_session()
	{
		let user = create_user();

		let user1 = create_user();

		let group_create = prepare_create(&user.user_keys[0].public_key).unwrap();
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
			time: 0,
			encrypted_sign_key: None,
			verify_key: None,
			keypair_sign_alg: None,
			keypair_sign_id: None,
			public_key_sig: None,
			public_key_sig_key_id: None,
		};

		let group_server_output_user_0 = GroupServerData {
			group_id: "123".to_string(),
			parent_group_id: None,
			keys: vec![group_server_output_user_0],
			key_update: false,
			rank: 0,
			created_time: 0,
			joined_time: 0,
			access_by: GroupUserAccessBy::User,
			is_connected_group: false,
			hmac_keys: vec![GroupHmacData {
				id: "123".to_string(),
				encrypted_hmac_encryption_key_id: "".to_string(),
				encrypted_hmac_key: group_create.encrypted_hmac_key.clone(),
				encrypted_hmac_alg: group_create.encrypted_hmac_alg.clone(),
				time: 0,
			}],
		};

		let server_output = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(group_server_output_user_0),
		};

		let group_data_user_0 = get_group_data(server_output.to_string().unwrap().as_str()).unwrap();

		let mut group_keys_u0 = Vec::with_capacity(group_data_user_0.keys.len());

		for key in group_data_user_0.keys {
			group_keys_u0.push(decrypt_group_keys(&user.user_keys[0].private_key, key).unwrap());
		}

		//prepare the keys for user 1
		let out = prepare_group_keys_for_new_member_via_session(
			&user1.user_keys[0].exported_public_key,
			&[&group_keys_u0[0].group_key],
		)
		.unwrap();

		let out: Vec<GroupKeysForNewMember> = serde_json::from_str(out.as_str()).unwrap();
		let out_group_1 = &out[0]; //this group only got one key

		let group_server_output_user_1 = GroupKeyServerOutput {
			encrypted_group_key: out_group_1.encrypted_group_key.to_string(),
			group_key_alg: out_group_1.alg.to_string(),
			group_key_id: out_group_1.key_id.to_string(),
			encrypted_private_group_key: group_create.encrypted_private_group_key,
			public_group_key: group_create.public_group_key,
			keypair_encrypt_alg: group_create.keypair_encrypt_alg,
			key_pair_id: "123".to_string(),
			user_public_key_id: "123".to_string(),
			time: 0,
			encrypted_sign_key: None,
			verify_key: None,
			keypair_sign_alg: None,
			keypair_sign_id: None,
			public_key_sig: None,
			public_key_sig_key_id: None,
		};

		let group_server_output_user_1 = GroupServerData {
			group_id: "123".to_string(),
			parent_group_id: None,
			keys: vec![group_server_output_user_1],
			key_update: false,
			rank: 0,
			created_time: 0,
			joined_time: 0,
			access_by: GroupUserAccessBy::User,
			is_connected_group: false,
			hmac_keys: vec![GroupHmacData {
				id: "123".to_string(),
				encrypted_hmac_encryption_key_id: "".to_string(),
				encrypted_hmac_key: group_create.encrypted_hmac_key,
				encrypted_hmac_alg: group_create.encrypted_hmac_alg,
				time: 0,
			}],
		};

		let server_output = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(group_server_output_user_1),
		};

		let group_data_user_1 = get_group_data(server_output.to_string().unwrap().as_str()).unwrap();

		let mut group_keys_u1 = Vec::with_capacity(group_data_user_1.keys.len());

		for key in group_data_user_1.keys {
			group_keys_u1.push(decrypt_group_keys(&user1.user_keys[0].private_key, key).unwrap());
		}

		assert_eq!(group_keys_u0[0].group_key.key_id, group_keys_u1[0].group_key.key_id);

		match (&group_keys_u0[0].group_key.key, &group_keys_u1[0].group_key.key) {
			(SymKey::Aes(k0), SymKey::Aes(k1)) => {
				assert_eq!(*k0, *k1);
			},
		}
	}

	#[test]
	fn test_key_rotation()
	{
		let user = create_user();

		let (_data, key_data, group_server_out, _) = create_group(&user.user_keys[0]);

		let rotation_out = key_rotation(
			&key_data[0].group_key,
			&user.user_keys[0].public_key,
			false,
			None,
			Default::default(),
		)
		.unwrap();
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
			user_public_key_id: user.user_keys[0].public_key.key_id.to_string(),
			time: 0,
			encrypted_sign_key: None,
			verify_key: None,
			keypair_sign_alg: None,
			keypair_sign_id: None,
			public_key_sig: None,
			public_key_sig_key_id: None,
		};

		let new_group_key_direct = decrypt_group_keys(&user.user_keys[0].private_key, server_key_output_direct).unwrap();

		//simulate server key rotation encrypt. encrypt the ephemeral_key (encrypted by the previous room key) with the public keys of all users
		let encrypted_ephemeral_key = Base64::decode_vec(rotation_out.encrypted_ephemeral_key.as_str()).unwrap();
		let encrypted_ephemeral_key_by_group_key_and_public_key =
			encrypt_asymmetric_core(&user.user_keys[0].public_key.key, &encrypted_ephemeral_key).unwrap();

		let server_output = KeyRotationInput {
			encrypted_ephemeral_key_by_group_key_and_public_key: Base64::encode_string(&encrypted_ephemeral_key_by_group_key_and_public_key),
			encrypted_group_key_by_ephemeral: rotation_out.encrypted_group_key_by_ephemeral.to_string(),
			ephemeral_alg: rotation_out.ephemeral_alg.to_string(),
			encrypted_eph_key_key_id: "".to_string(),
			previous_group_key_id: rotation_out.previous_group_key_id.to_string(),
			time: 0,
			new_group_key_id: "abc".to_string(),
			error: None,

			signed_by_user_id: None,
			signed_by_user_sign_key_id: None,
			signed_by_user_sign_key_alg: None,
		};

		let done_key_rotation = done_key_rotation(
			&user.user_keys[0].private_key,
			&user.user_keys[0].public_key,
			&key_data[0].group_key,
			server_output,
			None,
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
			keypair_encrypt_alg: rotation_out.keypair_encrypt_alg,
			key_pair_id: "new_key_id_from_server".to_string(),
			user_public_key_id: done_key_rotation.public_key_id,
			time: 0,
			encrypted_sign_key: None,
			verify_key: None,
			keypair_sign_alg: None,
			keypair_sign_id: None,
			public_key_sig: None,
			public_key_sig_key_id: None,
		};

		let out = decrypt_group_keys(&user.user_keys[0].private_key, server_key_output).unwrap();

		//the new group key must be different after key rotation
		match (&key_data[0].group_key.key, &out.group_key.key) {
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

	#[test]
	fn test_signed_key_rotation()
	{
		let user = create_user();

		let (_data, key_data, group_server_out, _) = create_group(&user.user_keys[0]);

		let rotation_out = key_rotation(
			&key_data[0].group_key,
			&user.user_keys[0].public_key,
			false,
			Some(&user.user_keys[0].sign_key),
			user.user_id.clone(),
		)
		.unwrap();
		let rotation_out = KeyRotationData::from_string(rotation_out.as_str()).unwrap();

		assert_eq!(rotation_out.signed_by_user_id.as_ref(), Some(&user.user_id));
		assert_eq!(
			rotation_out.signed_by_user_sign_key_id.as_ref(),
			Some(&user.user_keys[0].sign_key.key_id)
		);

		//__________________________________________________________________________________________
		//get the new group key directly because for the invoker the key is already encrypted by the own public key
		let server_key_output_direct = GroupKeyServerOutput {
			encrypted_group_key: rotation_out.encrypted_group_key_by_user.to_string(),
			group_key_alg: group_server_out.keys[0].group_key_alg.to_string(),
			group_key_id: group_server_out.keys[0].group_key_id.to_string(),
			encrypted_private_group_key: rotation_out.encrypted_private_group_key.to_string(),
			public_group_key: rotation_out.public_group_key.to_string(),
			keypair_encrypt_alg: rotation_out.keypair_encrypt_alg.to_string(),
			key_pair_id: "new_key_id_from_server".to_string(),
			user_public_key_id: user.user_keys[0].public_key.key_id.to_string(),
			time: 0,
			encrypted_sign_key: None,
			verify_key: None,
			keypair_sign_alg: None,
			keypair_sign_id: None,
			public_key_sig: None,
			public_key_sig_key_id: None,
		};

		let new_group_key_direct = decrypt_group_keys(&user.user_keys[0].private_key, server_key_output_direct).unwrap();

		//__________________________________________________________________________________________
		//do the server part
		let encrypted_ephemeral_key = Base64::decode_vec(rotation_out.encrypted_ephemeral_key.as_str()).unwrap();
		let encrypted_ephemeral_key_by_group_key_and_public_key =
			encrypt_asymmetric_core(&user.user_keys[0].public_key.key, &encrypted_ephemeral_key).unwrap();

		let server_output = KeyRotationInput {
			encrypted_ephemeral_key_by_group_key_and_public_key: Base64::encode_string(&encrypted_ephemeral_key_by_group_key_and_public_key),
			encrypted_group_key_by_ephemeral: rotation_out.encrypted_group_key_by_ephemeral.to_string(),
			ephemeral_alg: rotation_out.ephemeral_alg.to_string(),
			encrypted_eph_key_key_id: "".to_string(),
			previous_group_key_id: rotation_out.previous_group_key_id.to_string(),
			time: 0,
			new_group_key_id: "abc".to_string(),
			error: None,

			signed_by_user_id: rotation_out.signed_by_user_id.clone(),
			signed_by_user_sign_key_id: rotation_out.signed_by_user_sign_key_id.clone(),
			signed_by_user_sign_key_alg: rotation_out.signed_by_user_sign_key_alg.clone(),
		};

		//__________________________________________________________________________________________
		//test done key rotation without verify key (should work even if it is signed, sign is here ignored)

		let done_key_rotation_out = done_key_rotation(
			&user.user_keys[0].private_key,
			&user.user_keys[0].public_key,
			&key_data[0].group_key,
			server_output,
			None,
		)
		.unwrap();
		let done_key_rotation_out = DoneKeyRotationData::from_string(done_key_rotation_out.as_str()).unwrap();

		//get the new group keys
		let server_key_output = GroupKeyServerOutput {
			encrypted_group_key: done_key_rotation_out.encrypted_new_group_key.to_string(),
			group_key_alg: group_server_out.keys[0].group_key_alg.to_string(),
			group_key_id: group_server_out.keys[0].group_key_id.to_string(),
			encrypted_private_group_key: rotation_out.encrypted_private_group_key.to_string(),
			public_group_key: rotation_out.public_group_key.to_string(),
			keypair_encrypt_alg: rotation_out.keypair_encrypt_alg.clone(),
			key_pair_id: "new_key_id_from_server".to_string(),
			user_public_key_id: done_key_rotation_out.public_key_id,
			time: 0,
			encrypted_sign_key: None,
			verify_key: None,
			keypair_sign_alg: None,
			keypair_sign_id: None,
			public_key_sig: None,
			public_key_sig_key_id: None,
		};

		let out = decrypt_group_keys(&user.user_keys[0].private_key, server_key_output).unwrap();

		//the new group key must be different after key rotation
		match (&key_data[0].group_key.key, &out.group_key.key) {
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

		//__________________________________________________________________________________________
		//now test rotation with verify

		let server_output = KeyRotationInput {
			encrypted_ephemeral_key_by_group_key_and_public_key: Base64::encode_string(&encrypted_ephemeral_key_by_group_key_and_public_key),
			encrypted_group_key_by_ephemeral: rotation_out.encrypted_group_key_by_ephemeral.to_string(),
			ephemeral_alg: rotation_out.ephemeral_alg.to_string(),
			encrypted_eph_key_key_id: "".to_string(),
			previous_group_key_id: rotation_out.previous_group_key_id.to_string(),
			time: 0,
			new_group_key_id: "abc".to_string(),
			error: None,

			signed_by_user_id: rotation_out.signed_by_user_id,
			signed_by_user_sign_key_id: rotation_out.signed_by_user_sign_key_id,
			signed_by_user_sign_key_alg: rotation_out.signed_by_user_sign_key_alg,
		};

		let done_key_rotation_out = done_key_rotation(
			&user.user_keys[0].private_key,
			&user.user_keys[0].public_key,
			&key_data[0].group_key,
			server_output,
			Some(&user.user_keys[0].exported_verify_key),
		)
		.unwrap();
		let done_key_rotation_out = DoneKeyRotationData::from_string(done_key_rotation_out.as_str()).unwrap();

		//get the new group keys
		let server_key_output = GroupKeyServerOutput {
			encrypted_group_key: done_key_rotation_out.encrypted_new_group_key.to_string(),
			group_key_alg: group_server_out.keys[0].group_key_alg.to_string(),
			group_key_id: group_server_out.keys[0].group_key_id.to_string(),
			encrypted_private_group_key: rotation_out.encrypted_private_group_key.to_string(),
			public_group_key: rotation_out.public_group_key.to_string(),
			keypair_encrypt_alg: rotation_out.keypair_encrypt_alg,
			key_pair_id: "new_key_id_from_server".to_string(),
			user_public_key_id: done_key_rotation_out.public_key_id,
			time: 0,
			encrypted_sign_key: None,
			verify_key: None,
			keypair_sign_alg: None,
			keypair_sign_id: None,
			public_key_sig: None,
			public_key_sig_key_id: None,
		};

		let out = decrypt_group_keys(&user.user_keys[0].private_key, server_key_output).unwrap();

		//the new group key must be different after key rotation
		match (&key_data[0].group_key.key, &out.group_key.key) {
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
