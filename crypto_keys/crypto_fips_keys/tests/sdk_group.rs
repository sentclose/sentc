use base64ct::{Base64, Encoding};
use sentc_crypto::group::group::{get_group_data, get_group_key_from_server_output, get_group_keys_from_server_output};
use sentc_crypto_common::group::{
	CreateData,
	DoneKeyRotationData,
	GroupHmacData,
	GroupKeyServerOutput,
	GroupKeysForNewMember,
	GroupKeysForNewMemberServerInput,
	GroupServerData,
	GroupSortableData,
	GroupUserAccessBy,
	KeyRotationData,
	KeyRotationInput,
};
use sentc_crypto_common::ServerOutput;
use sentc_crypto_core::cryptomat::Pk;
use sentc_crypto_fips_keys::sdk::FipsGroup;
use sentc_crypto_fips_keys::util::SignKey;

use crate::sdk_test_fn::{create_group, create_user};

mod sdk_test_fn;

#[test]
fn test_create_group()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	//create a rust dummy user
	let user = create_user();
	let user_keys = &user.user_keys[0];

	let group = FipsGroup::prepare_create(&user_keys.public_key).unwrap();
	let group = CreateData::from_string(group.as_str()).unwrap();

	assert_eq!(group.creator_public_key_id, user_keys.public_key.key_id);
}

#[test]
fn test_create_and_get_group()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	//test here only basic functions, if function panics. the key test is done in crypto mod

	let user = create_user();

	let (data, _, _, _, _) = create_group(&user.user_keys[0]);

	assert_eq!(data.group_id, "123".to_string());
}

#[test]
fn test_get_group_data_and_keys()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let user = create_user();
	let user_keys = &user.user_keys[0];

	let (_, key_data, group_server_out, _, _) = create_group(user_keys);

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
		group_keys.push(FipsGroup::decrypt_group_keys(&user_keys.private_key, k).unwrap());
	}

	assert_eq!(
		key_data[0].group_key.key.as_ref(),
		group_keys[0].group_key.key.as_ref()
	);

	//fetch the key single
	let key = get_group_key_from_server_output(single_fetch.as_str()).unwrap();

	let group_keys_from_single_server_out = FipsGroup::decrypt_group_keys(&user_keys.private_key, key).unwrap();

	assert_eq!(
		&key_data[0].group_key.key.as_ref(),
		&group_keys_from_single_server_out.group_key.key.as_ref()
	);
}

#[test]
fn test_prepare_group_keys_for_new_member()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let user = create_user();
	let user_keys = &user.user_keys[0];

	let user1 = create_user();
	let user_keys1 = &user1.user_keys[0];

	let group_create = FipsGroup::prepare_create(&user_keys.public_key).unwrap();
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
		sortable_keys: vec![GroupSortableData {
			id: "123".to_string(),
			encrypted_sortable_key: group_create.encrypted_sortable_key.clone(),
			encrypted_sortable_alg: group_create.encrypted_sortable_alg.clone(),
			encrypted_sortable_encryption_key_id: "".to_string(),
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
		group_keys.push(FipsGroup::decrypt_group_keys(&user_keys.private_key, key).unwrap());
	}

	//prepare the keys for user 1
	let out = FipsGroup::prepare_group_keys_for_new_member(
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
		sortable_keys: vec![GroupSortableData {
			id: "123".to_string(),
			encrypted_sortable_key: group_create.encrypted_sortable_key.clone(),
			encrypted_sortable_alg: group_create.encrypted_sortable_alg.clone(),
			encrypted_sortable_encryption_key_id: "".to_string(),
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
		group_keys_u2.push(FipsGroup::decrypt_group_keys(&user_keys1.private_key, key).unwrap());
	}

	assert_eq!(group_keys_u2[0].group_key.key_id, group_keys_u2[0].group_key.key_id);

	assert_eq!(
		group_keys[0].group_key.key.as_ref(),
		group_keys_u2[0].group_key.key.as_ref()
	)
}

/**
The same test as before but this time with prepare_group_keys_for_new_member_via_session
 */
#[test]
fn test_prepare_group_keys_for_new_member_via_session()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let user = create_user();

	let user1 = create_user();

	let group_create = FipsGroup::prepare_create(&user.user_keys[0].public_key).unwrap();
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
		sortable_keys: vec![GroupSortableData {
			id: "123".to_string(),
			encrypted_sortable_key: group_create.encrypted_sortable_key.clone(),
			encrypted_sortable_alg: group_create.encrypted_sortable_alg.clone(),
			encrypted_sortable_encryption_key_id: "".to_string(),
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
		group_keys_u0.push(FipsGroup::decrypt_group_keys(&user.user_keys[0].private_key, key).unwrap());
	}

	//prepare the keys for user 1
	let out = FipsGroup::prepare_group_keys_for_new_member_via_session(
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
		sortable_keys: vec![GroupSortableData {
			id: "123".to_string(),
			encrypted_sortable_key: group_create.encrypted_sortable_key.clone(),
			encrypted_sortable_alg: group_create.encrypted_sortable_alg.clone(),
			encrypted_sortable_encryption_key_id: "".to_string(),
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
		group_keys_u1.push(FipsGroup::decrypt_group_keys(&user1.user_keys[0].private_key, key).unwrap());
	}

	assert_eq!(group_keys_u0[0].group_key.key_id, group_keys_u1[0].group_key.key_id);

	assert_eq!(
		group_keys_u0[0].group_key.key.as_ref(),
		group_keys_u1[0].group_key.key.as_ref()
	);
}

#[test]
fn test_key_rotation()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let user = create_user();

	let (_data, key_data, group_server_out, _, _) = create_group(&user.user_keys[0]);

	let rotation_out = FipsGroup::key_rotation(
		&key_data[0].group_key,
		&user.user_keys[0].public_key,
		false,
		None::<&SignKey>,
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

	let new_group_key_direct = FipsGroup::decrypt_group_keys(&user.user_keys[0].private_key, server_key_output_direct).unwrap();

	//simulate server key rotation encrypt. encrypt the ephemeral_key (encrypted by the previous room key) with the public keys of all users
	let encrypted_ephemeral_key = Base64::decode_vec(rotation_out.encrypted_ephemeral_key.as_str()).unwrap();
	let encrypted_ephemeral_key_by_group_key_and_public_key = user.user_keys[0]
		.public_key
		.key
		.encrypt(&encrypted_ephemeral_key)
		.unwrap();

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

	let done_key_rotation = FipsGroup::done_key_rotation(
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

	let out = FipsGroup::decrypt_group_keys(&user.user_keys[0].private_key, server_key_output).unwrap();

	//the new group key must be different after key rotation
	assert_ne!(key_data[0].group_key.key.as_ref(), out.group_key.key.as_ref());

	assert_eq!(
		new_group_key_direct.group_key.key.as_ref(),
		out.group_key.key.as_ref()
	);
}

#[test]
fn test_signed_key_rotation()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let user = create_user();

	let (_data, key_data, group_server_out, _, _) = create_group(&user.user_keys[0]);

	let rotation_out = FipsGroup::key_rotation(
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

	let new_group_key_direct = FipsGroup::decrypt_group_keys(&user.user_keys[0].private_key, server_key_output_direct).unwrap();

	//__________________________________________________________________________________________
	//do the server part
	let encrypted_ephemeral_key = Base64::decode_vec(rotation_out.encrypted_ephemeral_key.as_str()).unwrap();
	let encrypted_ephemeral_key_by_group_key_and_public_key = user.user_keys[0]
		.public_key
		.key
		.encrypt(&encrypted_ephemeral_key)
		.unwrap();

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

	let done_key_rotation_out = FipsGroup::done_key_rotation(
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

	let out = FipsGroup::decrypt_group_keys(&user.user_keys[0].private_key, server_key_output).unwrap();

	//the new group key must be different after key rotation
	assert_ne!(key_data[0].group_key.key.as_ref(), out.group_key.key.as_ref());

	assert_eq!(
		new_group_key_direct.group_key.key.as_ref(),
		out.group_key.key.as_ref()
	);

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

	let done_key_rotation_out = FipsGroup::done_key_rotation(
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

	let out = FipsGroup::decrypt_group_keys(&user.user_keys[0].private_key, server_key_output).unwrap();

	//the new group key must be different after key rotation
	assert_ne!(key_data[0].group_key.key.as_ref(), out.group_key.key.as_ref());

	assert_eq!(
		new_group_key_direct.group_key.key.as_ref(),
		out.group_key.key.as_ref()
	);
}
