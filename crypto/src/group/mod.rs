//use here key ids from the api, the core sdk don't care about the ids because we have to call every function with the right keys
//but in the higher level mod we must care
//handle the key id for get group, and the rotation + accept / invite user

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use sentc_crypto_common::crypto::SignHead;
use sentc_crypto_common::group::{
	CreateData,
	DoneKeyRotationData,
	GroupChangeRankServerInput,
	GroupHmacData,
	GroupKeyServerOutput,
	GroupKeysForNewMember,
	GroupKeysForNewMemberServerInput,
	GroupLightServerData,
	GroupServerData,
	GroupSortableData,
	GroupUserAccessBy,
	KeyRotationData,
	KeyRotationInput,
};
use sentc_crypto_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto_common::{GroupId, UserId};
use sentc_crypto_core::{getting_alg_from_public_key, group as core_group, Pk};

use crate::entities::group::{GroupKeyData, GroupOutData, GroupOutDataLight};
use crate::entities::keys::{HmacKeyFormatInt, PrivateKeyFormatInt, PublicKeyFormatInt, SignKeyFormatInt, SortableKeyFormatInt, SymKeyFormatInt};
use crate::util::public::handle_server_response;
use crate::util::{export_raw_public_key_to_pem, export_raw_verify_key_to_pem, import_public_key_from_pem_with_alg, sig_to_string};
use crate::{crypto, SdkError};

#[cfg(not(feature = "rust"))]
mod group;

mod group_rank_check;
#[cfg(feature = "rust")]
mod group_rust;

#[cfg(not(feature = "rust"))]
pub(crate) use self::group::prepare_group_keys_for_new_member_with_ref;
#[cfg(not(feature = "rust"))]
pub use self::group::{
	decrypt_group_hmac_key,
	decrypt_group_keys,
	decrypt_group_sortable_key,
	done_key_rotation,
	get_done_key_rotation_server_input,
	get_group_data,
	get_group_key_from_server_output,
	get_group_keys_from_server_output,
	get_group_light_data,
	key_rotation,
	prepare_change_rank,
	prepare_create,
	prepare_create_batch,
	prepare_create_batch_typed,
	prepare_create_typed,
	prepare_group_keys_for_new_member,
	prepare_group_keys_for_new_member_typed,
	prepare_group_keys_for_new_member_via_session,
	prepare_group_keys_for_new_member_with_group_public_key,
};
pub use self::group_rank_check::{
	check_create_sub_group,
	check_delete_user_rank,
	check_get_join_reqs,
	check_group_delete,
	check_kick_user,
	check_make_invite_req,
	check_sent_join_req_list,
};
#[cfg(feature = "rust")]
pub use self::group_rust::{
	decrypt_group_hmac_key,
	decrypt_group_keys,
	decrypt_group_sortable_key,
	done_key_rotation,
	get_done_key_rotation_server_input,
	get_group_data,
	get_group_key_from_server_output,
	get_group_keys_from_server_output,
	get_group_light_data,
	key_rotation,
	prepare_change_rank,
	prepare_create,
	prepare_create_batch,
	prepare_create_batch_typed,
	prepare_create_typed,
	prepare_group_keys_for_new_member,
	prepare_group_keys_for_new_member_typed,
	prepare_group_keys_for_new_member_via_session,
	prepare_group_keys_for_new_member_with_group_public_key,
};

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

fn prepare_create_typed_internally(creators_public_key: &PublicKeyFormatInt) -> Result<(CreateData, PublicKeyFormatInt, SymKeyFormatInt), SdkError>
{
	prepare_create_private_internally(creators_public_key, false)
}

fn prepare_create_internally(creators_public_key: &PublicKeyFormatInt) -> Result<(String, PublicKeyFormatInt, SymKeyFormatInt), SdkError>
{
	let out = prepare_create_private_internally(creators_public_key, false)?;
	let input = out
		.0
		.to_string()
		.map_err(|_| SdkError::JsonToStringFailed)?;

	Ok((input, out.1, out.2))
}

/**
Prepare the server input for the group creation.

Use the public key of the group for creating a child group.
*/
pub(crate) fn prepare_create_private_internally(
	creators_public_key: &PublicKeyFormatInt,
	user_group: bool,
) -> Result<(CreateData, PublicKeyFormatInt, SymKeyFormatInt), SdkError>
{
	//it is ok to use the internal format of the public key here because this is the own public key and get return from the done login fn
	let out = core_group::prepare_create(&creators_public_key.key, user_group)?;
	let created_group_key = out.1;
	let out = out.0;

	//1. encode the values to base64 for the server
	let encrypted_group_key = Base64::encode_string(&out.encrypted_group_key);
	let encrypted_private_group_key = Base64::encode_string(&out.encrypted_private_group_key);
	let encrypted_hmac_key = Base64::encode_string(&out.encrypted_hmac_key);
	let encrypted_sortable_key = Base64::encode_string(&out.encrypted_sortable_key);

	//2. export the public key
	let public_group_key = export_raw_public_key_to_pem(&out.public_group_key)?;

	//3. user group values
	let (encrypted_sign_key, verify_key, keypair_sign_alg, public_key_sig) = if !user_group {
		(None, None, None, None)
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

		let public_key_sig = match &out.public_key_sig {
			None => None,
			Some(s) => Some(sig_to_string(s)),
		};

		(encrypted_sign_key, verify_key, keypair_sign_alg, public_key_sig)
	};

	let create_out = CreateData {
		public_group_key,
		encrypted_group_key,
		encrypted_private_group_key,
		encrypted_group_key_alg: out.encrypted_group_key_alg.to_string(),
		group_key_alg: out.group_key_alg.to_string(),
		keypair_encrypt_alg: out.keypair_encrypt_alg.to_string(),
		creator_public_key_id: creators_public_key.key_id.clone(),
		encrypted_hmac_key,
		encrypted_hmac_alg: out.encrypted_hmac_alg.to_string(),
		encrypted_sortable_key,
		encrypted_sortable_alg: out.encrypted_sortable_key_alg.to_string(),

		//user group values
		encrypted_sign_key,
		verify_key,
		keypair_sign_alg,
		public_key_sig,
	};

	//return the non registered version of the group key and the public group key to use it
	// to create child groups or connect to a group without register the group
	let group_public_key_int = PublicKeyFormatInt {
		key: out.public_group_key,
		key_id: "non_registered".to_string(),
	};

	let created_group_key = SymKeyFormatInt {
		key: created_group_key,
		key_id: "non_registered".to_string(),
	};

	Ok((create_out, group_public_key_int, created_group_key))
}

fn key_rotation_internally(
	previous_group_key: &SymKeyFormatInt,
	invoker_public_key: &PublicKeyFormatInt,
	user_group: bool,
	sign_key: Option<&SignKeyFormatInt>,
	starter: UserId,
) -> Result<String, SdkError>
{
	let out = core_group::key_rotation(&previous_group_key.key, &invoker_public_key.key, user_group)?;

	//1. encode the values to base64 for the server
	let encrypted_group_key_by_user = Base64::encode_string(&out.encrypted_group_key_by_user);
	let encrypted_private_group_key = Base64::encode_string(&out.encrypted_private_group_key);
	let encrypted_ephemeral_key = Base64::encode_string(&out.encrypted_ephemeral_key);

	//2. export the public key
	let public_group_key = export_raw_public_key_to_pem(&out.public_group_key)?;

	//3. user group values
	let (encrypted_sign_key, verify_key, keypair_sign_alg, public_key_sig) = if !user_group {
		(None, None, None, None)
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

		let public_key_sig = match &out.public_key_sig {
			None => None,
			Some(s) => Some(sig_to_string(s)),
		};

		(encrypted_sign_key, verify_key, keypair_sign_alg, public_key_sig)
	};

	//4. if set sign the encrypted group key
	let (encrypted_group_key_by_ephemeral, signed_by_user_id, signed_by_user_sign_key_id, signed_by_user_sign_key_alg) = if let Some(sk) = sign_key {
		let (sign_head_group_key, signed_group_key) = crypto::sign_internally(sk, &out.encrypted_group_key_by_ephemeral)?;
		(
			Base64::encode_string(&signed_group_key),
			Some(starter),
			Some(sign_head_group_key.id),
			Some(sign_head_group_key.alg),
		)
	} else {
		(
			Base64::encode_string(&out.encrypted_group_key_by_ephemeral),
			None,
			None,
			None,
		)
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

		signed_by_user_id,
		signed_by_user_sign_key_id,
		signed_by_user_sign_key_alg,

		//user group
		encrypted_sign_key,
		verify_key,
		keypair_sign_alg,
		public_key_sig,
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
	server_output: KeyRotationInput,
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<String, SdkError>
{
	if let Some(e) = server_output.error {
		return Err(SdkError::KeyRotationEncryptError(e));
	}

	//the id of the previous group key was returned by the server too so the sdk impl knows which key it used

	//this values were encoded by key_rotation_internally
	let encrypted_ephemeral_key_by_group_key_and_public_key =
		Base64::decode_vec(&server_output.encrypted_ephemeral_key_by_group_key_and_public_key).map_err(|_| SdkError::KeyRotationServerOutputWrong)?;
	let encrypted_group_key_by_ephemeral =
		Base64::decode_vec(&server_output.encrypted_group_key_by_ephemeral).map_err(|_| SdkError::KeyRotationServerOutputWrong)?;

	//if verify key set then verify the new group key first

	//get from the KeyRotationInput also if the key was signed before and only then do the verify, even if a verify key was set.
	//the user id doesn't matter here.
	let encrypted_group_key_by_ephemeral = match (
		server_output.signed_by_user_id,
		server_output.signed_by_user_sign_key_id,
		server_output.signed_by_user_sign_key_alg,
	) {
		(Some(_user_id), Some(sign_key_id), Some(sign_key_alg)) => {
			match verify_key {
				Some(vk) => {
					crypto::verify_internally(
						vk,
						&encrypted_group_key_by_ephemeral,
						&SignHead {
							id: sign_key_id,
							alg: sign_key_alg,
						},
					)?
				},
				None => {
					//if no verify key set, still split the data to get only the group key without the sign
					let (_, encrypted_group_key_by_ephemeral) =
						sentc_crypto_core::crypto::split_sig_and_data(&sign_key_alg, &encrypted_group_key_by_ephemeral)?;

					encrypted_group_key_by_ephemeral
				},
			}
		},
		_ => {
			//no sign head set for key rotation
			&encrypted_group_key_by_ephemeral
		},
	};

	let out = core_group::done_key_rotation(
		&private_key.key,
		&public_key.key,
		&previous_group_key.key,
		&encrypted_ephemeral_key_by_group_key_and_public_key,
		encrypted_group_key_by_ephemeral,
		&server_output.ephemeral_alg,
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

fn get_group_data_internally(server_output: &str) -> Result<GroupOutData, SdkError>
{
	let server_output: GroupServerData = handle_server_response(server_output)?;

	let (access_by_group_as_member, access_by_parent_group) = get_access_by(server_output.access_by);

	Ok(GroupOutData {
		keys: server_output.keys,
		hmac_keys: server_output.hmac_keys,
		key_update: server_output.key_update,
		parent_group_id: server_output.parent_group_id,
		created_time: server_output.created_time,
		joined_time: server_output.joined_time,
		rank: server_output.rank,
		group_id: server_output.group_id,
		access_by_group_as_member,
		access_by_parent_group,
		is_connected_group: server_output.is_connected_group,
		sortable_keys: server_output.sortable_keys,
	})
}

fn get_group_light_data_internally(server_output: &str) -> Result<GroupOutDataLight, SdkError>
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
Decrypt the group hmac key which is used for searchable encryption.
*/
pub(crate) fn decrypt_group_hmac_key_internally(group_key: &SymKeyFormatInt, server_output: GroupHmacData) -> Result<HmacKeyFormatInt, SdkError>
{
	let encrypted_hmac_key = Base64::decode_vec(&server_output.encrypted_hmac_key).map_err(|_| SdkError::DerivedKeyWrongFormat)?;

	let key = core_group::get_group_hmac_key(&group_key.key, &encrypted_hmac_key, &server_output.encrypted_hmac_alg)?;

	Ok(HmacKeyFormatInt {
		key_id: server_output.id,
		key,
	})
}

pub(crate) fn decrypt_group_sortable_key_internally(
	group_key: &SymKeyFormatInt,
	server_output: GroupSortableData,
) -> Result<SortableKeyFormatInt, SdkError>
{
	let encrypted_key = Base64::decode_vec(&server_output.encrypted_sortable_key).map_err(|_| SdkError::DerivedKeyWrongFormat)?;

	let key = core_group::get_group_sortable_key(&group_key.key, &encrypted_key, &server_output.encrypted_sortable_alg)?;

	Ok(SortableKeyFormatInt {
		key_id: server_output.id,
		key,
	})
}

/**
Call this fn for each key, with the right private key
*/
pub(crate) fn decrypt_group_keys_internally(private_key: &PrivateKeyFormatInt, server_output: GroupKeyServerOutput)
	-> Result<GroupKeyData, SdkError>
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

	//export it to use it for connecting to a group without fetching the key again
	let exported_public_key = UserPublicKeyData {
		public_key_pem: server_output.public_group_key,
		public_key_alg: server_output.keypair_encrypt_alg,
		public_key_id: server_output.key_pair_id.clone(),
		public_key_sig: server_output.public_key_sig,
		public_key_sig_key_id: server_output.public_key_sig_key_id,
	};

	Ok(GroupKeyData {
		group_key: SymKeyFormatInt {
			key: group_key,
			key_id: server_output.group_key_id,
		},
		private_group_key: PrivateKeyFormatInt {
			key_id: server_output.key_pair_id.clone(),
			key: private_group_key,
		},
		public_group_key: PublicKeyFormatInt {
			key_id: server_output.key_pair_id,
			key: public_group_key,
		},
		exported_public_key,
		time: server_output.time,
	})
}

fn prepare_group_keys_for_new_member_typed_internally(
	requester_public_key_data: &UserPublicKeyData,
	group_keys: &[&SymKeyFormatInt],
	key_session: bool, //this value must be set form each sdk impl from key storage when more than 100 keys are used
	rank: Option<i32>,
) -> Result<GroupKeysForNewMemberServerInput, SdkError>
{
	prepare_group_keys_for_new_member_private_internally(requester_public_key_data, group_keys, key_session, rank)
}

fn prepare_group_keys_for_new_member_internally(
	requester_public_key_data: &UserPublicKeyData,
	group_keys: &[&SymKeyFormatInt],
	key_session: bool, //this value must be set form each sdk impl from key storage when more than 100 keys are used
	rank: Option<i32>,
) -> Result<String, SdkError>
{
	let server_input = prepare_group_keys_for_new_member_private_internally(requester_public_key_data, group_keys, key_session, rank)?;

	server_input
		.to_string()
		.map_err(|_| SdkError::JsonToStringFailed)
}

pub(crate) fn prepare_group_keys_for_new_member_private_internally(
	requester_public_key_data: &UserPublicKeyData,
	group_keys: &[&SymKeyFormatInt],
	key_session: bool,
	rank: Option<i32>,
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
		rank,
	};

	Ok(server_input)
}

fn prepare_group_keys_for_new_member_internally_with_group_public_key(
	requester_public_key_data: &PublicKeyFormatInt,
	group_keys: &[&SymKeyFormatInt],
	key_session: bool,
	rank: Option<i32>,
) -> Result<GroupKeysForNewMemberServerInput, SdkError>
{
	//this can be used to not fetch the group public key but use it if the user already fetch the group
	let keys = prepare_group_keys_for_new_member_internally_with_public_key(
		&requester_public_key_data.key,
		&requester_public_key_data.key_id,
		group_keys,
	)?;

	let server_input = GroupKeysForNewMemberServerInput {
		keys,
		key_session,
		rank,
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

	use sentc_crypto_common::group::{GroupHmacData, GroupServerData, GroupSortableData, GroupUserAccessBy};
	use sentc_crypto_common::ServerOutput;

	use super::*;
	#[cfg(not(feature = "rust"))]
	use crate::entities::group::{GroupKeyDataExport, GroupOutDataExport};

	#[cfg(feature = "rust")]
	pub(crate) fn create_group(
		user: &crate::entities::user::UserKeyDataInt,
	) -> (
		GroupOutData,
		Vec<GroupKeyData>,
		GroupServerData,
		Vec<HmacKeyFormatInt>,
		Vec<SortableKeyFormatInt>,
	)
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
			public_key_sig: None,
			public_key_sig_key_id: None,
		};

		let group_server_output = GroupServerData {
			group_id: "123".to_string(),
			parent_group_id: None,
			keys: vec![group_server_output],
			hmac_keys: vec![GroupHmacData {
				id: "123".to_string(),
				encrypted_hmac_encryption_key_id: "".to_string(),
				encrypted_hmac_key: group.encrypted_hmac_key,
				encrypted_hmac_alg: group.encrypted_hmac_alg,
				time: 0,
			}],
			sortable_keys: vec![GroupSortableData {
				id: "123".to_string(),
				encrypted_sortable_key: group.encrypted_sortable_key,
				encrypted_sortable_alg: group.encrypted_sortable_alg,
				encrypted_sortable_encryption_key_id: "".to_string(),
				time: 0,
			}],
			key_update: false,
			rank: 0,
			created_time: 0,
			joined_time: 0,
			access_by: GroupUserAccessBy::User,
			is_connected_group: false,
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

		#[cfg(feature = "rust")]
		let group_keys: Vec<_> = out
			.keys
			.into_iter()
			.map(|k| decrypt_group_keys(&user.private_key, k).unwrap())
			.collect();

		let hmac_keys = out
			.hmac_keys
			.into_iter()
			.map(|k| decrypt_group_hmac_key(&group_keys[0].group_key, k).unwrap())
			.collect();

		let sortable_keys = out
			.sortable_keys
			.into_iter()
			.map(|k| decrypt_group_sortable_key(&group_keys[0].group_key, k).unwrap())
			.collect();

		(
			GroupOutData {
				keys: vec![],
				hmac_keys: vec![],
				sortable_keys: vec![],
				parent_group_id: out.parent_group_id,
				key_update: out.key_update,
				created_time: out.created_time,
				joined_time: out.joined_time,
				rank: out.rank,
				group_id: out.group_id,
				access_by_group_as_member: out.access_by_group_as_member,
				access_by_parent_group: out.access_by_parent_group,
				is_connected_group: out.is_connected_group,
			},
			group_keys,
			GroupServerData::from_string(group_ser_str.as_str()).unwrap(),
			hmac_keys,
			sortable_keys,
		)
	}

	#[cfg(not(feature = "rust"))]
	pub(crate) fn create_group(
		user: &crate::entities::user::UserKeyDataExport,
	) -> (
		GroupOutDataExport,
		Vec<GroupKeyDataExport>,
		GroupServerData,
		Vec<String>,
		Vec<String>,
	)
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
			public_key_sig: None,
			public_key_sig_key_id: None,
		};

		let group_server_output = GroupServerData {
			group_id: "123".to_string(),
			parent_group_id: None,
			keys: vec![group_server_output],
			hmac_keys: vec![GroupHmacData {
				id: "123".to_string(),
				encrypted_hmac_encryption_key_id: "".to_string(),
				encrypted_hmac_key: group.encrypted_hmac_key,
				encrypted_hmac_alg: group.encrypted_hmac_alg,
				time: 0,
			}],
			sortable_keys: vec![GroupSortableData {
				id: "123".to_string(),
				encrypted_sortable_key: group.encrypted_sortable_key,
				encrypted_sortable_alg: group.encrypted_sortable_alg,
				encrypted_sortable_encryption_key_id: "".to_string(),
				time: 0,
			}],
			key_update: false,
			rank: 0,
			created_time: 0,
			joined_time: 0,
			access_by: GroupUserAccessBy::User,
			is_connected_group: false,
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

		let group_keys: Vec<_> = group_data
			.keys
			.iter()
			.map(|k| decrypt_group_keys(user.private_key.as_str(), &k.key_data).unwrap())
			.collect();

		let hmac_keys = group_data
			.hmac_keys
			.iter()
			.map(|k| decrypt_group_hmac_key(&group_keys[0].group_key, &k.key_data).unwrap())
			.collect();

		let sortable_keys = group_data
			.sortable_keys
			.iter()
			.map(|k| decrypt_group_sortable_key(&group_keys[0].group_key, &k.key_data).unwrap())
			.collect();

		(
			group_data,
			group_keys,
			GroupServerData::from_string(group_ser_str.as_str()).unwrap(),
			hmac_keys,
			sortable_keys,
		)
	}
}
