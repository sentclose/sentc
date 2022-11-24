//use here key ids from the api, the core sdk don't care about the ids because we have to call every function with the right keys
//but in the higher level mod we must care
//handle the key id for get group, and the rotation + accept / invite user

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use sentc_crypto_common::group::{
	CreateData,
	DoneKeyRotationData,
	GroupChangeRankServerInput,
	GroupKeyServerOutput,
	GroupKeysForNewMember,
	GroupKeysForNewMemberServerInput,
	GroupUserAccessBy,
	KeyRotationData,
	KeyRotationInput,
};
use sentc_crypto_common::user::UserPublicKeyData;
use sentc_crypto_common::GroupId;
use sentc_crypto_core::{getting_alg_from_public_key, group as core_group, Pk};

use crate::util::public::handle_server_response;
use crate::util::{
	export_raw_public_key_to_pem,
	export_raw_verify_key_to_pem,
	import_public_key_from_pem_with_alg,
	PrivateKeyFormatInt,
	PublicKeyFormatInt,
	SymKeyFormatInt,
};
use crate::SdkError;

#[cfg(not(feature = "rust"))]
mod group;

mod group_rank_check;
#[cfg(feature = "rust")]
mod group_rust;

#[cfg(not(feature = "rust"))]
pub(crate) use self::group::prepare_group_keys_for_new_member_with_ref;
#[cfg(not(feature = "rust"))]
pub use self::group::{
	decrypt_group_keys,
	done_key_rotation,
	get_done_key_rotation_server_input,
	get_group_data,
	get_group_key_from_server_output,
	get_group_keys_from_server_output,
	key_rotation,
	prepare_change_rank,
	prepare_create,
	prepare_group_keys_for_new_member,
	prepare_group_keys_for_new_member_via_session,
	GroupKeyData,
	GroupOutData,
	GroupOutDataKeys,
};
pub use self::group_rank_check::{
	check_create_sub_group,
	check_delete_user_rank,
	check_get_join_reqs,
	check_group_delete,
	check_kick_user,
	check_make_invite_req,
};
#[cfg(feature = "rust")]
pub use self::group_rust::{
	decrypt_group_keys,
	done_key_rotation,
	get_done_key_rotation_server_input,
	get_group_data,
	get_group_key_from_server_output,
	get_group_keys_from_server_output,
	key_rotation,
	prepare_change_rank,
	prepare_create,
	prepare_group_keys_for_new_member,
	prepare_group_keys_for_new_member_via_session,
	GroupOutData,
};
#[cfg(feature = "rust")]
pub use self::DoneGettingGroupKeysOutput as GroupKeyData;

pub struct DoneGettingGroupKeysOutput
{
	pub group_key: SymKeyFormatInt,
	pub private_group_key: PrivateKeyFormatInt,
	pub public_group_key: PublicKeyFormatInt,
	pub time: u128,
}

fn get_access_by(access_by: GroupUserAccessBy) -> (Option<GroupId>, Option<GroupId>)
{
	match access_by {
		GroupUserAccessBy::User => (None, None),
		GroupUserAccessBy::Parent(id) => (None, Some(id)),
		GroupUserAccessBy::GroupAsUser(id) => (Some(id), None),
		GroupUserAccessBy::GroupAsUserAsParent {
			parent,
			group_as_user,
		} => (Some(group_as_user), Some(parent)),
	}
}

fn prepare_create_internally(creators_public_key: &PublicKeyFormatInt) -> Result<String, SdkError>
{
	let out = prepare_create_private_internally(creators_public_key, false)?;

	out.to_string().map_err(|_| SdkError::JsonToStringFailed)
}

/**
Prepare the server input for the group creation.

Use the public key of the group for creating a child group.
*/
pub(crate) fn prepare_create_private_internally(creators_public_key: &PublicKeyFormatInt, user_group: bool) -> Result<CreateData, SdkError>
{
	//it is ok to use the internal format of the public key here because this is the own public key and get return from the done login fn
	let out = core_group::prepare_create(&creators_public_key.key, user_group)?;

	//1. encode the values to base64 for the server
	let encrypted_group_key = Base64::encode_string(&out.encrypted_group_key);
	let encrypted_private_group_key = Base64::encode_string(&out.encrypted_private_group_key);

	//2. export the public key
	let public_group_key = export_raw_public_key_to_pem(&out.public_group_key)?;

	//3. user group values
	let (encrypted_sign_key, verify_key, keypair_sign_alg) = if !user_group {
		(None, None, None)
	} else {
		let encrypted_sign_key = match &out.encrypted_sign_key {
			None => None,
			Some(k) => Some(Base64::encode_string(k)),
		};

		let verify_key = match &out.verify_key {
			None => None,
			Some(k) => Some(export_raw_verify_key_to_pem(k)?),
		};

		let keypair_sign_alg = match out.keypair_sign_alg {
			None => None,
			Some(alg) => Some(alg.to_string()),
		};

		(encrypted_sign_key, verify_key, keypair_sign_alg)
	};

	let create_out = CreateData {
		public_group_key,
		encrypted_group_key,
		encrypted_private_group_key,
		encrypted_group_key_alg: out.encrypted_group_key_alg.to_string(),
		group_key_alg: out.group_key_alg.to_string(),
		keypair_encrypt_alg: out.keypair_encrypt_alg.to_string(),
		creator_public_key_id: creators_public_key.key_id.clone(),

		//user group values
		encrypted_sign_key,
		verify_key,
		keypair_sign_alg,
	};

	Ok(create_out)
}

fn key_rotation_internally(
	previous_group_key: &SymKeyFormatInt,
	invoker_public_key: &PublicKeyFormatInt,
	user_group: bool,
) -> Result<String, SdkError>
{
	let out = core_group::key_rotation(&previous_group_key.key, &invoker_public_key.key, user_group)?;

	//1. encode the values to base64 for the server
	let encrypted_group_key_by_user = Base64::encode_string(&out.encrypted_group_key_by_user);
	let encrypted_private_group_key = Base64::encode_string(&out.encrypted_private_group_key);
	let encrypted_group_key_by_ephemeral = Base64::encode_string(&out.encrypted_group_key_by_ephemeral);
	let encrypted_ephemeral_key = Base64::encode_string(&out.encrypted_ephemeral_key);

	//2. export the public key
	let public_group_key = export_raw_public_key_to_pem(&out.public_group_key)?;

	//3. user group values
	let (encrypted_sign_key, verify_key, keypair_sign_alg) = if !user_group {
		(None, None, None)
	} else {
		let encrypted_sign_key = match &out.encrypted_sign_key {
			None => None,
			Some(k) => Some(Base64::encode_string(k)),
		};

		let verify_key = match &out.verify_key {
			None => None,
			Some(k) => Some(export_raw_verify_key_to_pem(k)?),
		};

		let keypair_sign_alg = match out.keypair_sign_alg {
			None => None,
			Some(alg) => Some(alg.to_string()),
		};

		(encrypted_sign_key, verify_key, keypair_sign_alg)
	};

	let rotation_out = KeyRotationData {
		encrypted_group_key_by_user,
		group_key_alg: out.group_key_alg.to_string(),
		encrypted_group_key_alg: out.encrypted_group_key_alg.to_string(),
		encrypted_private_group_key,
		public_group_key,
		keypair_encrypt_alg: out.keypair_encrypt_alg.to_string(),
		encrypted_group_key_by_ephemeral,
		ephemeral_alg: out.ephemeral_alg.to_string(),
		encrypted_ephemeral_key,
		previous_group_key_id: previous_group_key.key_id.clone(),
		invoker_public_key_id: invoker_public_key.key_id.clone(),

		//user group
		encrypted_sign_key,
		verify_key,
		keypair_sign_alg,
	};

	rotation_out
		.to_string()
		.map_err(|_| SdkError::JsonToStringFailed)
}

/**
Deserialize the server output
*/
fn get_done_key_rotation_server_input_internally(server_output: &str) -> Result<KeyRotationInput, SdkError>
{
	KeyRotationInput::from_string(server_output).map_err(|_| SdkError::KeyRotationServerOutputWrong)
}

fn done_key_rotation_internally(
	private_key: &PrivateKeyFormatInt,
	public_key: &PublicKeyFormatInt,
	previous_group_key: &SymKeyFormatInt,
	server_output: &KeyRotationInput,
) -> Result<String, SdkError>
{
	//the id of the previous group key was returned by the server too so the sdk impl knows which key it used

	//this values were encoded by key_rotation_internally
	let encrypted_ephemeral_key_by_group_key_and_public_key = Base64::decode_vec(
		server_output
			.encrypted_ephemeral_key_by_group_key_and_public_key
			.as_str(),
	)
	.map_err(|_| SdkError::KeyRotationServerOutputWrong)?;
	let encrypted_group_key_by_ephemeral =
		Base64::decode_vec(server_output.encrypted_group_key_by_ephemeral.as_str()).map_err(|_| SdkError::KeyRotationServerOutputWrong)?;

	let out = core_group::done_key_rotation(
		&private_key.key,
		&public_key.key,
		&previous_group_key.key,
		&encrypted_ephemeral_key_by_group_key_and_public_key,
		&encrypted_group_key_by_ephemeral,
		server_output.ephemeral_alg.as_str(),
	)?;

	let encrypted_new_group_key = Base64::encode_string(&out);

	let encrypted_alg = getting_alg_from_public_key(&public_key.key).to_string();

	let done_rotation_out = DoneKeyRotationData {
		encrypted_new_group_key,
		public_key_id: public_key.key_id.clone(),
		encrypted_alg,
	};

	done_rotation_out
		.to_string()
		.map_err(|_| SdkError::JsonToStringFailed)
}

/**
Get the key data from str
*/
fn get_group_keys_from_server_output_internally(server_output: &str) -> Result<Vec<GroupKeyServerOutput>, SdkError>
{
	let server_output: Vec<GroupKeyServerOutput> = handle_server_response(server_output)?;

	Ok(server_output)
}

fn get_group_key_from_server_output_internally(server_output: &str) -> Result<GroupKeyServerOutput, SdkError>
{
	let server_output: GroupKeyServerOutput = handle_server_response(server_output)?;

	Ok(server_output)
}

/**
Call this fn for each key, with the right private key
*/
pub(crate) fn decrypt_group_keys_internally(
	private_key: &PrivateKeyFormatInt,
	server_output: &GroupKeyServerOutput,
) -> Result<DoneGettingGroupKeysOutput, SdkError>
{
	//the user_public_key_id is used to get the right private key
	let encrypted_master_key = Base64::decode_vec(server_output.encrypted_group_key.as_str()).map_err(|_| SdkError::DerivedKeyWrongFormat)?;
	let encrypted_private_key =
		Base64::decode_vec(server_output.encrypted_private_group_key.as_str()).map_err(|_| SdkError::DerivedKeyWrongFormat)?;

	let (group_key, private_group_key) = core_group::get_group(
		&private_key.key,
		&encrypted_master_key,
		&encrypted_private_key,
		server_output.group_key_alg.as_str(),
		server_output.keypair_encrypt_alg.as_str(),
	)?;

	let public_group_key = import_public_key_from_pem_with_alg(
		&server_output.public_group_key,
		server_output.keypair_encrypt_alg.as_str(),
	)?;

	Ok(DoneGettingGroupKeysOutput {
		group_key: SymKeyFormatInt {
			key: group_key,
			key_id: server_output.group_key_id.clone(),
		},
		private_group_key: PrivateKeyFormatInt {
			key_id: server_output.key_pair_id.clone(),
			key: private_group_key,
		},
		public_group_key: PublicKeyFormatInt {
			key_id: server_output.key_pair_id.clone(),
			key: public_group_key,
		},
		time: server_output.time,
	})
}

fn prepare_group_keys_for_new_member_internally(
	requester_public_key_data: &UserPublicKeyData,
	group_keys: &[&SymKeyFormatInt],
	key_session: bool, //this value must be set form each sdk impl from key storage when more than 100 keys are used
) -> Result<String, SdkError>
{
	let server_input = prepare_group_keys_for_new_member_private_internally(requester_public_key_data, group_keys, key_session)?;

	server_input
		.to_string()
		.map_err(|_| SdkError::JsonToStringFailed)
}

pub(crate) fn prepare_group_keys_for_new_member_private_internally(
	requester_public_key_data: &UserPublicKeyData,
	group_keys: &[&SymKeyFormatInt],
	key_session: bool,
) -> Result<GroupKeysForNewMemberServerInput, SdkError>
{
	let public_key = import_public_key_from_pem_with_alg(
		requester_public_key_data.public_key_pem.as_str(),
		requester_public_key_data.public_key_alg.as_str(),
	)?;

	let keys = prepare_group_keys_for_new_member_internally_with_public_key(
		&public_key,
		requester_public_key_data.public_key_id.as_str(),
		group_keys,
	)?;

	let server_input = GroupKeysForNewMemberServerInput {
		keys,
		key_session,
	};

	Ok(server_input)
}

/**
When there are mor than 100 keys used in this group, upload the rest of the keys via a session
*/
fn prepare_group_keys_for_new_member_via_session_internally(
	requester_public_key_data: &UserPublicKeyData,
	group_keys: &[&SymKeyFormatInt],
) -> Result<String, SdkError>
{
	let public_key = import_public_key_from_pem_with_alg(
		requester_public_key_data.public_key_pem.as_str(),
		requester_public_key_data.public_key_alg.as_str(),
	)?;

	let keys = prepare_group_keys_for_new_member_internally_with_public_key(
		&public_key,
		requester_public_key_data.public_key_id.as_str(),
		group_keys,
	)?;

	serde_json::to_string(&keys).map_err(|_| SdkError::JsonToStringFailed)
}

fn prepare_group_keys_for_new_member_internally_with_public_key(
	public_key: &Pk,
	public_key_id: &str,
	group_keys: &[&SymKeyFormatInt],
) -> Result<Vec<GroupKeysForNewMember>, SdkError>
{
	//split group keys and their ids
	let mut split_group_keys = Vec::with_capacity(group_keys.len());
	let mut split_group_ids = Vec::with_capacity(group_keys.len());

	for group_key in group_keys {
		split_group_keys.push(&group_key.key);
		split_group_ids.push(group_key.key_id.as_str());
	}

	//get all the group keys from the server and use get group for all (if not already on the device)
	let out = core_group::prepare_group_keys_for_new_member(public_key, &split_group_keys)?;

	//transform this vec to the server input by encode each encrypted key to base64
	let mut encrypted_group_keys: Vec<GroupKeysForNewMember> = Vec::with_capacity(out.len());

	let mut i = 0;

	for key_out in out {
		let encrypted_group_key = Base64::encode_string(&key_out.encrypted_group_key);
		let key_id = split_group_ids[i].to_string();

		encrypted_group_keys.push(GroupKeysForNewMember {
			encrypted_group_key,
			alg: key_out.alg.to_string(),
			user_public_key_id: public_key_id.to_string(),
			key_id, //support multiple groups at once (important for user key update)
			encrypted_alg: key_out.encrypted_group_key_alg.to_string(),
		});

		i += 1;
	}

	Ok(encrypted_group_keys)
}

fn prepare_change_rank_internally(user_id: &str, new_rank: i32, admin_rank: i32) -> Result<String, SdkError>
{
	if new_rank < 1 || new_rank > 4 {
		return Err(SdkError::GroupRank);
	}

	if admin_rank > 1 {
		return Err(SdkError::GroupPermission);
	}

	GroupChangeRankServerInput {
		changed_user_id: user_id.to_string(),
		new_rank,
	}
	.to_string()
	.map_err(|_| SdkError::JsonToStringFailed)
}

#[cfg(test)]
pub(crate) mod test_fn
{
	use alloc::vec;

	use sentc_crypto_common::group::{GroupServerData, GroupUserAccessBy};
	use sentc_crypto_common::ServerOutput;

	use super::*;
	use crate::UserKeyData;

	#[cfg(feature = "rust")]
	pub(crate) fn create_group(user: &UserKeyData) -> (GroupOutData, Vec<GroupKeyData>, GroupServerData)
	{
		#[cfg(feature = "rust")]
		let group = prepare_create(&user.public_key).unwrap();
		let group = CreateData::from_string(group.as_str()).unwrap();

		let group_server_output = GroupKeyServerOutput {
			encrypted_group_key: group.encrypted_group_key,
			group_key_alg: group.group_key_alg,
			group_key_id: "123".to_string(),
			encrypted_private_group_key: group.encrypted_private_group_key,
			public_group_key: group.public_group_key,
			keypair_encrypt_alg: group.keypair_encrypt_alg,
			key_pair_id: "123".to_string(),
			user_public_key_id: "123".to_string(),
			time: 0,
			encrypted_sign_key: None,
			verify_key: None,
			keypair_sign_alg: None,
			keypair_sign_id: None,
		};

		let group_server_output = GroupServerData {
			group_id: "123".to_string(),
			parent_group_id: None,
			keys: vec![group_server_output],
			key_update: false,
			rank: 0,
			created_time: 0,
			joined_time: 0,
			access_by: GroupUserAccessBy::User,
		};

		//to avoid the clone trait on the real type
		let group_ser_str = group_server_output.to_string().unwrap();

		let server_output = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(group_server_output),
		};

		#[cfg(feature = "rust")]
		let out = get_group_data(server_output.to_string().unwrap().as_str()).unwrap();

		let mut group_keys = Vec::with_capacity(out.keys.len());

		for key in &out.keys {
			group_keys.push(decrypt_group_keys(&user.private_key, &key).unwrap());
		}

		(
			out,
			group_keys,
			GroupServerData::from_string(group_ser_str.as_str()).unwrap(),
		)
	}

	#[cfg(not(feature = "rust"))]
	pub(crate) fn create_group(user: &UserKeyData) -> (GroupOutData, Vec<GroupKeyData>, GroupServerData)
	{
		#[cfg(not(feature = "rust"))]
		let group = prepare_create(user.public_key.as_str()).unwrap();
		let group = CreateData::from_string(group.as_str()).unwrap();

		let group_server_output = GroupKeyServerOutput {
			encrypted_group_key: group.encrypted_group_key,
			group_key_alg: group.group_key_alg,
			group_key_id: "123".to_string(),
			encrypted_private_group_key: group.encrypted_private_group_key,
			public_group_key: group.public_group_key,
			keypair_encrypt_alg: group.keypair_encrypt_alg,
			key_pair_id: "123".to_string(),
			user_public_key_id: "123".to_string(),
			time: 0,
			encrypted_sign_key: None,
			verify_key: None,
			keypair_sign_alg: None,
			keypair_sign_id: None,
		};

		let group_server_output = GroupServerData {
			group_id: "123".to_string(),
			parent_group_id: None,
			keys: vec![group_server_output],
			key_update: false,
			rank: 0,
			created_time: 0,
			joined_time: 0,
			access_by: GroupUserAccessBy::User,
		};

		//to avoid the clone trait on the real type
		let group_ser_str = group_server_output.to_string().unwrap();

		let server_output = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(group_server_output),
		};

		#[cfg(not(feature = "rust"))]
		let group_data = get_group_data(server_output.to_string().unwrap().as_str()).unwrap();

		//get the group keys
		let mut group_keys = Vec::with_capacity(group_data.keys.len());

		for key in &group_data.keys {
			group_keys.push(decrypt_group_keys(user.private_key.as_str(), &key.key_data).unwrap());
		}

		(
			group_data,
			group_keys,
			GroupServerData::from_string(group_ser_str.as_str()).unwrap(),
		)
	}
}
