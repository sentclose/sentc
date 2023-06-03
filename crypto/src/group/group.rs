use alloc::string::{String, ToString};
use alloc::vec::Vec;

use sentc_crypto_common::group::{
	CreateData,
	GroupHmacData,
	GroupKeyServerOutput,
	GroupKeysForNewMemberServerInput,
	GroupLightServerData,
	GroupServerData,
	KeyRotationInput,
};
use sentc_crypto_common::user::UserPublicKeyData;
use sentc_crypto_common::{EncryptionKeyPairId, GroupId, SymKeyId, UserId};
use serde::{Deserialize, Serialize};
use serde_json::{from_str, to_string};

use crate::crypto::{prepare_sign_key, prepare_verify_key};
use crate::group::{
	decrypt_group_hmac_key_internally,
	decrypt_group_keys_internally,
	done_key_rotation_internally,
	get_access_by,
	get_done_key_rotation_server_input_internally,
	get_group_key_from_server_output_internally,
	get_group_keys_from_server_output_internally,
	key_rotation_internally,
	prepare_change_rank_internally,
	prepare_create_internally,
	prepare_create_typed_internally,
	prepare_group_keys_for_new_member_internally,
	prepare_group_keys_for_new_member_internally_with_group_public_key,
	prepare_group_keys_for_new_member_typed_internally,
	prepare_group_keys_for_new_member_via_session_internally,
};
use crate::util::public::handle_server_response;
use crate::util::{
	export_hmac_key_to_string,
	export_private_key_to_string,
	export_public_key_to_string,
	export_sym_key_to_string,
	import_private_key,
	import_public_key,
	import_sym_key,
	import_sym_key_from_format,
	SymKeyFormat,
	SymKeyFormatInt,
};
use crate::SdkError;

#[derive(Serialize, Deserialize)]
pub struct GroupOutDataLight
{
	pub group_id: String,
	pub parent_group_id: Option<GroupId>,
	pub rank: i32,
	pub created_time: u128,
	pub joined_time: u128,
	pub access_by_group_as_member: Option<GroupId>,
	pub access_by_parent_group: Option<GroupId>,
	pub is_connected_group: bool,
}

/**
The decrypted and exported values
*/
#[derive(Serialize, Deserialize)]
pub struct GroupKeyData
{
	pub private_group_key: String,
	pub public_group_key: String,
	pub exported_public_key: String,
	pub group_key: String,
	pub time: u128,
	pub group_key_id: SymKeyId,
}

/**
First fetch of the group data
*/
#[derive(Serialize, Deserialize)]
pub struct GroupOutData
{
	pub group_id: GroupId,
	pub parent_group_id: Option<GroupId>,
	pub rank: i32,
	pub key_update: bool,
	pub created_time: u128,
	pub joined_time: u128,
	pub keys: Vec<GroupOutDataKeys>,
	pub hmac_keys: Vec<GroupOutDataHmacKeys>,
	pub access_by_group_as_member: Option<GroupId>,
	pub access_by_parent_group: Option<GroupId>,
	pub is_connected_group: bool,
}

impl GroupOutData
{
	pub fn from_string(v: &str) -> serde_json::Result<Self>
	{
		from_str::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}

#[derive(Serialize, Deserialize)]
pub struct GroupOutDataKeys
{
	pub private_key_id: EncryptionKeyPairId,
	pub key_data: String, //serde string
}

#[derive(Serialize, Deserialize)]
pub struct GroupOutDataHmacKeys
{
	pub group_key_id: SymKeyId,
	pub key_data: String, //serde string
}

pub fn prepare_create_typed(creators_public_key: &str) -> Result<CreateData, String>
{
	let creators_public_key = import_public_key(creators_public_key)?;

	let out = prepare_create_typed_internally(&creators_public_key)?;

	Ok(out.0)
}

pub fn prepare_create(creators_public_key: &str) -> Result<String, String>
{
	let creators_public_key = import_public_key(creators_public_key)?;

	let out = prepare_create_internally(&creators_public_key)?;

	Ok(out.0)
}

pub fn prepare_create_batch_typed(creators_public_key: &str) -> Result<(CreateData, String, String), String>
{
	let creators_public_key = import_public_key(creators_public_key)?;

	let out = prepare_create_typed_internally(&creators_public_key)?;

	let public_key = export_public_key_to_string(out.1)?;
	let group_key = export_sym_key_to_string(out.2)?;

	Ok((out.0, public_key, group_key))
}

pub fn prepare_create_batch(creators_public_key: &str) -> Result<(String, String, String), String>
{
	let creators_public_key = import_public_key(creators_public_key)?;

	let out = prepare_create_internally(&creators_public_key)?;

	let public_key = export_public_key_to_string(out.1)?;
	let group_key = export_sym_key_to_string(out.2)?;

	Ok((out.0, public_key, group_key))
}

pub fn key_rotation(
	previous_group_key: &str,
	invoker_public_key: &str,
	user_group: bool,
	sign_key: Option<&str>,
	starter: UserId,
) -> Result<String, String>
{
	let sign_key = prepare_sign_key(sign_key)?;

	//the ids comes from the storage of the current impl from the sdk, the group key id comes from get group
	let previous_group_key = import_sym_key(previous_group_key)?;

	let invoker_public_key = import_public_key(invoker_public_key)?;

	Ok(key_rotation_internally(
		&previous_group_key,
		&invoker_public_key,
		user_group,
		sign_key.as_ref(),
		starter,
	)?)
}

pub fn get_done_key_rotation_server_input(server_output: &str) -> Result<KeyRotationInput, String>
{
	Ok(get_done_key_rotation_server_input_internally(server_output)?)
}

pub fn done_key_rotation(
	private_key: &str,
	public_key: &str,
	previous_group_key: &str,
	server_output: &str,
	verify_key: Option<&str>,
) -> Result<String, String>
{
	let verify_key = prepare_verify_key(verify_key)?;

	let previous_group_key = import_sym_key(previous_group_key)?;

	let private_key = import_private_key(private_key)?;

	let public_key = import_public_key(public_key)?;

	let server_output = get_done_key_rotation_server_input(server_output)?;

	Ok(done_key_rotation_internally(
		&private_key,
		&public_key,
		&previous_group_key,
		server_output,
		verify_key.as_ref(),
	)?)
}

pub fn decrypt_group_hmac_key(group_key: &str, server_key_output: &str) -> Result<String, String>
{
	let key = import_sym_key(group_key)?;

	let server_output: GroupHmacData = from_str(server_key_output).map_err(SdkError::JsonParseFailed)?;

	let hmac_key = decrypt_group_hmac_key_internally(&key, server_output)?;

	let hmac_key = export_hmac_key_to_string(hmac_key)?;

	Ok(hmac_key)
}

pub fn decrypt_group_keys(private_key: &str, server_key_output: &str) -> Result<GroupKeyData, String>
{
	let private_key = import_private_key(private_key)?;

	let server_key_output = GroupKeyServerOutput::from_string(server_key_output).map_err(SdkError::JsonParseFailed)?;

	let result = decrypt_group_keys_internally(&private_key, server_key_output)?;

	let group_key_id = result.group_key.key_id.to_string();

	let private_group_key = export_private_key_to_string(result.private_group_key)?;
	let public_group_key = export_public_key_to_string(result.public_group_key)?;
	let group_key = export_sym_key_to_string(result.group_key)?;

	Ok(GroupKeyData {
		private_group_key,
		public_group_key,
		exported_public_key: result
			.exported_public_key
			.to_string()
			.map_err(|_e| SdkError::JsonToStringFailed)?,
		group_key,
		time: result.time,
		group_key_id,
	})
}

/**
Call this fn for pagination key fetch
*/
pub fn get_group_keys_from_server_output(server_output: &str) -> Result<Vec<GroupOutDataKeys>, String>
{
	let out = get_group_keys_from_server_output_internally(server_output)?;

	let mut keys = Vec::with_capacity(out.len());

	//create string for each key and save the used public key id for the sdk impl
	for key in out {
		let private_key_id = key.user_public_key_id.clone();

		//call with this string the get group keys fn
		let key_data = key.to_string().map_err(SdkError::JsonParseFailed)?;

		keys.push(GroupOutDataKeys {
			private_key_id,
			key_data,
		});
	}

	Ok(keys)
}

pub fn get_group_key_from_server_output(server_output: &str) -> Result<GroupOutDataKeys, String>
{
	let out = get_group_key_from_server_output_internally(server_output)?;

	let key_data = out.to_string().map_err(SdkError::JsonParseFailed)?;

	Ok(GroupOutDataKeys {
		private_key_id: out.user_public_key_id,
		key_data,
	})
}

pub fn get_group_light_data(server_output: &str) -> Result<GroupOutDataLight, String>
{
	let server_output: GroupLightServerData = handle_server_response(server_output)?;

	let (access_by_group_as_member, access_by_parent_group) = get_access_by(server_output.access_by);

	Ok(GroupOutDataLight {
		group_id: server_output.group_id,
		parent_group_id: server_output.parent_group_id,
		rank: server_output.rank,
		created_time: server_output.created_time,
		joined_time: server_output.joined_time,
		is_connected_group: server_output.is_connected_group,
		access_by_group_as_member,
		access_by_parent_group,
	})
}

/**
Returns the Group data.

Returns the server keys to use get_group_keys to decrypt each group key with the right private key
*/
pub fn get_group_data(server_output: &str) -> Result<GroupOutData, String>
{
	let server_output: GroupServerData = handle_server_response(server_output)?;

	let mut keys = Vec::with_capacity(server_output.keys.len());

	//create string for each key and save the used public key id for the sdk impl
	for key in server_output.keys {
		let private_key_id = key.user_public_key_id.clone();

		//call with this string the get group keys fn
		let key_data = key.to_string().map_err(SdkError::JsonParseFailed)?;

		keys.push(GroupOutDataKeys {
			private_key_id,
			key_data,
		});
	}

	//create also a string for the hmac group keys
	let mut hmac_keys = Vec::with_capacity(server_output.hmac_keys.len());

	for hmac_key in server_output.hmac_keys {
		let group_key_id = hmac_key.encrypted_hmac_encryption_key_id.clone();

		let key_data = to_string(&hmac_key).map_err(SdkError::JsonParseFailed)?;

		hmac_keys.push(GroupOutDataHmacKeys {
			group_key_id,
			key_data,
		})
	}

	let (access_by_group_as_member, access_by_parent_group) = get_access_by(server_output.access_by);

	Ok(GroupOutData {
		group_id: server_output.group_id,
		parent_group_id: server_output.parent_group_id,
		rank: server_output.rank,
		key_update: server_output.key_update,
		created_time: server_output.created_time,
		joined_time: server_output.joined_time,
		keys, //save the keys from server output to decrypt them later with get group keys
		hmac_keys,
		access_by_group_as_member,
		access_by_parent_group,
		is_connected_group: server_output.is_connected_group,
	})
}

pub fn prepare_group_keys_for_new_member_with_group_public_key(
	requester_public_key: &str,
	group_keys: &str,
	key_session: bool,
	rank: Option<i32>,
) -> Result<GroupKeysForNewMemberServerInput, String>
{
	//the same like the other fn but with the public key format and not the exported public key from server fetch

	let requester_public_key = import_public_key(requester_public_key)?;

	let group_keys: Vec<SymKeyFormat> = from_str(group_keys).map_err(SdkError::JsonParseFailed)?;

	//split group key and id
	let saved_keys = group_keys
		.iter()
		.map(import_sym_key_from_format)
		.collect::<Result<Vec<SymKeyFormatInt>, SdkError>>()?;

	let split_group_keys = prepare_group_keys_for_new_member_with_ref(&saved_keys);

	Ok(prepare_group_keys_for_new_member_internally_with_group_public_key(
		&requester_public_key,
		&split_group_keys,
		key_session,
		rank,
	)?)
}

pub fn prepare_group_keys_for_new_member_typed(
	requester_public_key_data: &str,
	group_keys: &str,
	key_session: bool,
	rank: Option<i32>,
) -> Result<GroupKeysForNewMemberServerInput, String>
{
	let requester_public_key_data = UserPublicKeyData::from_string(requester_public_key_data).map_err(SdkError::JsonParseFailed)?;

	let group_keys: Vec<SymKeyFormat> = from_str(group_keys).map_err(SdkError::JsonParseFailed)?;

	//split group key and id
	let saved_keys = group_keys
		.iter()
		.map(import_sym_key_from_format)
		.collect::<Result<Vec<SymKeyFormatInt>, SdkError>>()?;

	let split_group_keys = prepare_group_keys_for_new_member_with_ref(&saved_keys);

	Ok(prepare_group_keys_for_new_member_typed_internally(
		&requester_public_key_data,
		&split_group_keys,
		key_session,
		rank,
	)?)
}

pub fn prepare_group_keys_for_new_member(
	requester_public_key_data: &str,
	group_keys: &str,
	key_session: bool,
	rank: Option<i32>,
) -> Result<String, String>
{
	let requester_public_key_data = UserPublicKeyData::from_string(requester_public_key_data).map_err(SdkError::JsonParseFailed)?;

	let group_keys: Vec<SymKeyFormat> = from_str(group_keys).map_err(SdkError::JsonParseFailed)?;

	//split group key and id
	let saved_keys = group_keys
		.iter()
		.map(import_sym_key_from_format)
		.collect::<Result<Vec<SymKeyFormatInt>, SdkError>>()?;

	let split_group_keys = prepare_group_keys_for_new_member_with_ref(&saved_keys);

	Ok(prepare_group_keys_for_new_member_internally(
		&requester_public_key_data,
		&split_group_keys,
		key_session,
		rank,
	)?)
}

pub fn prepare_group_keys_for_new_member_via_session(requester_public_key_data: &str, group_keys: &str) -> Result<String, String>
{
	let requester_public_key_data = UserPublicKeyData::from_string(requester_public_key_data).map_err(SdkError::JsonParseFailed)?;

	let group_keys: Vec<SymKeyFormat> = from_str(group_keys).map_err(SdkError::JsonParseFailed)?;

	//split group key and id
	let saved_keys = group_keys
		.iter()
		.map(import_sym_key_from_format)
		.collect::<Result<Vec<SymKeyFormatInt>, SdkError>>()?;

	let split_group_keys = prepare_group_keys_for_new_member_with_ref(&saved_keys);

	Ok(prepare_group_keys_for_new_member_via_session_internally(
		&requester_public_key_data,
		&split_group_keys,
	)?)
}

pub(crate) fn prepare_group_keys_for_new_member_with_ref(saved_keys: &Vec<SymKeyFormatInt>) -> Vec<&SymKeyFormatInt>
{
	//this is needed because we need only ref of the group key not the group key itself.
	//but for the non rust version the key is just a string which gets

	let mut split_group_keys = Vec::with_capacity(saved_keys.len());

	for saved_key in saved_keys {
		split_group_keys.push(saved_key);
	}

	split_group_keys
}

pub fn prepare_change_rank(user_id: &str, new_rank: i32, admin_rank: i32) -> Result<String, String>
{
	Ok(prepare_change_rank_internally(user_id, new_rank, admin_rank)?)
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
		GroupHmacData,
		GroupKeysForNewMember,
		GroupKeysForNewMemberServerInput,
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

		let group = prepare_create(&user.user_keys[0].public_key).unwrap();
		let group = CreateData::from_string(group.as_str()).unwrap();

		let pk = import_public_key(user.user_keys[0].public_key.as_str()).unwrap();

		assert_eq!(group.creator_public_key_id, pk.key_id);
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

		let (_, key_data, group_server_out, _) = create_group(&user.user_keys[0]);

		let keys = group_server_out.keys;

		let single_fetch = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(&keys[0]),
		};

		let single_fetch = to_string(&single_fetch).unwrap();

		let server_key_out = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(keys),
		};

		let server_key_out = server_key_out.to_string().unwrap();

		let group_keys_from_server_out = get_group_keys_from_server_output(server_key_out.as_str()).unwrap();

		let group_keys_from_server_out = decrypt_group_keys(
			user.user_keys[0].private_key.as_str(),
			&group_keys_from_server_out[0].key_data,
		)
		.unwrap();

		//only one key
		assert_eq!(
			key_data[0].group_key.to_string(),
			group_keys_from_server_out.group_key
		);

		//fetch the key single
		let key = get_group_key_from_server_output(single_fetch.as_str()).unwrap();

		let group_keys_from_single_server_out = decrypt_group_keys(user.user_keys[0].private_key.as_str(), &key.key_data).unwrap();

		assert_eq!(
			key_data[0].group_key.to_string(),
			group_keys_from_single_server_out.group_key
		);
	}

	#[test]
	fn test_prepare_group_keys_for_new_member()
	{
		let user = create_user();

		let user1 = create_user();

		let group_create = prepare_create(user.user_keys[0].public_key.as_str()).unwrap();
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
			hmac_keys: vec![GroupHmacData {
				id: "123".to_string(),
				encrypted_hmac_encryption_key_id: "".to_string(),
				encrypted_hmac_key: group_create.encrypted_hmac_key.clone(),
				encrypted_hmac_alg: group_create.encrypted_hmac_alg.clone(),
				time: 0,
			}],
			key_update: false,
			rank: 0,
			created_time: 0,
			joined_time: 0,
			access_by: GroupUserAccessBy::User,
			is_connected_group: false,
		};

		let server_output = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(group_server_output_user_0),
		};

		let group_data_user_0 = get_group_data(server_output.to_string().unwrap().as_str()).unwrap();

		let group_key_user_0 = decrypt_group_keys(
			user.user_keys[0].private_key.as_str(),
			group_data_user_0.keys[0].key_data.as_str(),
		)
		.unwrap();

		let group_keys = to_string(&vec![SymKeyFormat::from_string(&group_key_user_0.group_key).unwrap()]).unwrap();

		//prepare the keys for user 1
		let out = prepare_group_keys_for_new_member(
			user1.user_keys[0].exported_public_key.as_str(),
			group_keys.as_str(),
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
			hmac_keys: vec![GroupHmacData {
				id: "123".to_string(),
				encrypted_hmac_encryption_key_id: "".to_string(),
				encrypted_hmac_key: group_create.encrypted_hmac_key,
				encrypted_hmac_alg: group_create.encrypted_hmac_alg,
				time: 0,
			}],
			key_update: false,
			rank: 0,
			created_time: 0,
			joined_time: 0,
			access_by: GroupUserAccessBy::User,
			is_connected_group: false,
		};

		let server_output = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(group_server_output_user_1),
		};

		let group_data_user_1 = get_group_data(server_output.to_string().unwrap().as_str()).unwrap();
		let group_key_user_1 = decrypt_group_keys(
			user1.user_keys[0].private_key.as_str(),
			group_data_user_1.keys[0].key_data.as_str(),
		)
		.unwrap();

		let group_key_0 = import_sym_key(group_key_user_0.group_key.as_str()).unwrap();
		let group_key_1 = import_sym_key(group_key_user_1.group_key.as_str()).unwrap();

		assert_eq!(group_key_0.key_id, group_key_1.key_id);

		match (&group_key_0.key, &group_key_1.key) {
			(SymKey::Aes(k0), SymKey::Aes(k1)) => {
				assert_eq!(*k0, *k1);
			},
		}
	}

	#[test]
	fn test_prepare_group_keys_for_new_member_via_session()
	{
		let user = create_user();
		let user_keys = &user.user_keys[0];

		let user1 = create_user();
		let user_keys1 = &user1.user_keys[0];

		let group_create = prepare_create(user_keys.public_key.as_str()).unwrap();
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
			hmac_keys: vec![GroupHmacData {
				id: "123".to_string(),
				encrypted_hmac_encryption_key_id: "".to_string(),
				encrypted_hmac_key: group_create.encrypted_hmac_key.clone(),
				encrypted_hmac_alg: group_create.encrypted_hmac_alg.clone(),
				time: 0,
			}],
			key_update: false,
			rank: 0,
			created_time: 0,
			joined_time: 0,
			access_by: GroupUserAccessBy::User,
			is_connected_group: false,
		};

		let server_output = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(group_server_output_user_0),
		};

		let group_data_user_0 = get_group_data(server_output.to_string().unwrap().as_str()).unwrap();

		let group_key_user_0 = decrypt_group_keys(
			user.user_keys[0].private_key.as_str(),
			group_data_user_0.keys[0].key_data.as_str(),
		)
		.unwrap();

		let group_keys = to_string(&vec![SymKeyFormat::from_string(&group_key_user_0.group_key).unwrap()]).unwrap();

		//prepare the keys for user 1
		let out = prepare_group_keys_for_new_member_via_session(user_keys1.exported_public_key.as_str(), group_keys.as_str()).unwrap();

		let out: Vec<GroupKeysForNewMember> = from_str(out.as_str()).unwrap();
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
		let group_key_user_1 = decrypt_group_keys(
			user_keys1.private_key.as_str(),
			group_data_user_1.keys[0].key_data.as_str(),
		)
		.unwrap();

		let group_key_0 = import_sym_key(group_key_user_0.group_key.as_str()).unwrap();
		let group_key_1 = import_sym_key(group_key_user_1.group_key.as_str()).unwrap();

		assert_eq!(group_key_0.key_id, group_key_1.key_id);

		match (&group_key_0.key, &group_key_1.key) {
			(SymKey::Aes(k0), SymKey::Aes(k1)) => {
				assert_eq!(*k0, *k1);
			},
		}
	}

	#[test]
	fn test_key_rotation()
	{
		let user = create_user();
		let user_keys = &user.user_keys[0];

		let (_data, key_data, group_server_out, _) = create_group(user_keys);

		let rotation_out = key_rotation(
			key_data[0].group_key.as_str(),
			user_keys.public_key.as_str(),
			false,
			None,
			"".to_string(),
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
			user_public_key_id: "abc".to_string(),
			time: 0,
			encrypted_sign_key: None,
			verify_key: None,
			keypair_sign_alg: None,
			keypair_sign_id: None,
			public_key_sig: None,
			public_key_sig_key_id: None,
		};

		let new_group_key_direct = decrypt_group_keys(
			user_keys.private_key.as_str(),
			&server_key_output_direct.to_string().unwrap(),
		)
		.unwrap();

		//simulate server key rotation encrypt. encrypt the ephemeral_key (encrypted by the previous room key) with the public keys of all users
		let encrypted_ephemeral_key = Base64::decode_vec(rotation_out.encrypted_ephemeral_key.as_str()).unwrap();
		let encrypted_ephemeral_key_by_group_key_and_public_key = encrypt_asymmetric_core(
			&import_public_key(user_keys.public_key.as_str())
				.unwrap()
				.key,
			&encrypted_ephemeral_key,
		)
		.unwrap();

		let server_output = KeyRotationInput {
			error: None,
			encrypted_ephemeral_key_by_group_key_and_public_key: Base64::encode_string(&encrypted_ephemeral_key_by_group_key_and_public_key),
			encrypted_group_key_by_ephemeral: rotation_out.encrypted_group_key_by_ephemeral.to_string(),
			ephemeral_alg: rotation_out.ephemeral_alg.to_string(),
			encrypted_eph_key_key_id: "".to_string(),
			previous_group_key_id: rotation_out.previous_group_key_id.to_string(),
			time: 0,
			new_group_key_id: "abc".to_string(),

			signed_by_user_id: None,
			signed_by_user_sign_key_id: None,
			signed_by_user_sign_key_alg: None,
		};

		let done_key_rotation = done_key_rotation(
			user.user_keys[0].private_key.as_str(),
			user.user_keys[0].public_key.as_str(),
			key_data[0].group_key.as_str(),
			server_output.to_string().unwrap().as_str(),
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

		let out = decrypt_group_keys(
			user_keys.private_key.as_str(),
			&server_key_output.to_string().unwrap(),
		)
		.unwrap();

		let old_group_key = import_sym_key(key_data[0].group_key.to_string().as_str()).unwrap();

		let new_group_key_direct = import_sym_key(new_group_key_direct.group_key.as_str()).unwrap();

		let new_group_key = import_sym_key(out.group_key.as_str()).unwrap();

		//the new group key must be different after key rotation
		match (&old_group_key.key, &new_group_key.key) {
			(SymKey::Aes(k_old), SymKey::Aes(k_new)) => {
				assert_ne!(*k_old, *k_new);
			},
		}

		match (&new_group_key_direct.key, &new_group_key.key) {
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
		let user_keys = &user.user_keys[0];

		let (_data, key_data, group_server_out, _) = create_group(user_keys);

		let rotation_out = key_rotation(
			key_data[0].group_key.as_str(),
			user_keys.public_key.as_str(),
			false,
			Some(&user_keys.sign_key),
			user.user_id.clone(),
		)
		.unwrap();
		let rotation_out = KeyRotationData::from_string(rotation_out.as_str()).unwrap();

		assert_eq!(rotation_out.signed_by_user_id.as_ref(), Some(&user.user_id));
		assert_eq!(
			rotation_out.signed_by_user_sign_key_id.as_ref(),
			Some(&user_keys.group_key_id)
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
			user_public_key_id: "abc".to_string(),
			time: 0,
			encrypted_sign_key: None,
			verify_key: None,
			keypair_sign_alg: None,
			keypair_sign_id: None,
			public_key_sig: None,
			public_key_sig_key_id: None,
		};

		let new_group_key_direct = decrypt_group_keys(
			user_keys.private_key.as_str(),
			&server_key_output_direct.to_string().unwrap(),
		)
		.unwrap();

		//__________________________________________________________________________________________
		//do the server part
		let encrypted_ephemeral_key = Base64::decode_vec(rotation_out.encrypted_ephemeral_key.as_str()).unwrap();
		let encrypted_ephemeral_key_by_group_key_and_public_key = encrypt_asymmetric_core(
			&import_public_key(user_keys.public_key.as_str())
				.unwrap()
				.key,
			&encrypted_ephemeral_key,
		)
		.unwrap();
		let server_output = KeyRotationInput {
			error: None,
			encrypted_ephemeral_key_by_group_key_and_public_key: Base64::encode_string(&encrypted_ephemeral_key_by_group_key_and_public_key),
			encrypted_group_key_by_ephemeral: rotation_out.encrypted_group_key_by_ephemeral.to_string(),
			ephemeral_alg: rotation_out.ephemeral_alg.to_string(),
			encrypted_eph_key_key_id: "".to_string(),
			previous_group_key_id: rotation_out.previous_group_key_id.to_string(),
			time: 0,
			new_group_key_id: "abc".to_string(),

			signed_by_user_id: rotation_out.signed_by_user_id,
			signed_by_user_sign_key_id: rotation_out.signed_by_user_sign_key_id,
			signed_by_user_sign_key_alg: rotation_out.signed_by_user_sign_key_alg,
		};

		//__________________________________________________________________________________________
		//test done key rotation without verify key (should work even if it is signed, sign is here ignored)

		let done_key_rotation_out = done_key_rotation(
			user.user_keys[0].private_key.as_str(),
			user.user_keys[0].public_key.as_str(),
			key_data[0].group_key.as_str(),
			server_output.to_string().unwrap().as_str(),
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
			keypair_encrypt_alg: rotation_out.keypair_encrypt_alg.to_string(),
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

		let out = decrypt_group_keys(
			user_keys.private_key.as_str(),
			&server_key_output.to_string().unwrap(),
		)
		.unwrap();

		let old_group_key = import_sym_key(key_data[0].group_key.to_string().as_str()).unwrap();

		let new_group_key_direct = import_sym_key(new_group_key_direct.group_key.as_str()).unwrap();

		let new_group_key = import_sym_key(out.group_key.as_str()).unwrap();

		//the new group key must be different after key rotation
		match (&old_group_key.key, &new_group_key.key) {
			(SymKey::Aes(k_old), SymKey::Aes(k_new)) => {
				assert_ne!(*k_old, *k_new);
			},
		}

		match (&new_group_key_direct.key, &new_group_key.key) {
			(SymKey::Aes(k_0), SymKey::Aes(k_1)) => {
				//should be the same for all users
				assert_eq!(*k_0, *k_1);
			},
		}

		//__________________________________________________________________________________________
		//now test rotation with verify

		let done_key_rotation_out = done_key_rotation(
			user.user_keys[0].private_key.as_str(),
			user.user_keys[0].public_key.as_str(),
			key_data[0].group_key.as_str(),
			server_output.to_string().unwrap().as_str(),
			Some(&user_keys.exported_verify_key),
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

		let out = decrypt_group_keys(
			user_keys.private_key.as_str(),
			&server_key_output.to_string().unwrap(),
		)
		.unwrap();

		let old_group_key = import_sym_key(key_data[0].group_key.to_string().as_str()).unwrap();

		let new_group_key = import_sym_key(out.group_key.as_str()).unwrap();

		//the new group key must be different after key rotation
		match (&old_group_key.key, &new_group_key.key) {
			(SymKey::Aes(k_old), SymKey::Aes(k_new)) => {
				assert_ne!(*k_old, *k_new);
			},
		}

		match (&new_group_key_direct.key, &new_group_key.key) {
			(SymKey::Aes(k_0), SymKey::Aes(k_1)) => {
				//should be the same for all users
				assert_eq!(*k_0, *k_1);
			},
		}
	}
}
