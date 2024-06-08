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
	KeyRotationData,
	KeyRotationInput,
};
use sentc_crypto_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto_common::UserId;
use sentc_crypto_core::cryptomat::{CryptoAlg, SignK};
use sentc_crypto_core::{
	group as core_group,
	HmacKey as CoreHmacKey,
	PublicKey as CorePublicKey,
	Signature as CoreSig,
	SortKeys as CoreSortableKey,
	SortKeys,
};
use sentc_crypto_utils::error::SdkUtilError;
use sentc_crypto_utils::keys::VerifyKey;
use sentc_crypto_utils::{export_raw_public_key_to_pem, export_raw_verify_key_to_pem, import_public_key_from_pem_with_alg, sig_to_string};

use crate::entities::group::{GroupKeyData, GroupOutData, GroupOutDataLight};
use crate::entities::keys::{HmacKey, PublicKey, SecretKey, SignKey, SortableKey, SymmetricKey};
use crate::util::public::handle_server_response;
use crate::SdkError;

pub fn prepare_create_typed(creators_public_key: &PublicKey) -> Result<CreateData, SdkError>
{
	let out = prepare_create_private_internally(creators_public_key, false)?;

	Ok(out.0)
}

pub fn prepare_create(creators_public_key: &PublicKey) -> Result<String, SdkError>
{
	let out = prepare_create_batch(creators_public_key)?;

	Ok(out.0)
}

pub fn prepare_create_batch_typed(creators_public_key: &PublicKey) -> Result<(CreateData, PublicKey, SymmetricKey), SdkError>
{
	prepare_create_private_internally(creators_public_key, false)
}

pub fn prepare_create_batch(creators_public_key: &PublicKey) -> Result<(String, PublicKey, SymmetricKey), SdkError>
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
	creators_public_key: &PublicKey,
	user_group: bool,
) -> Result<(CreateData, PublicKey, SymmetricKey), SdkError>
{
	//it is ok to use the internal format of the public key here because this is the own public key and get return from the done login fn
	let out = core_group::prepare_create::<
		sentc_crypto_core::SymmetricKey,
		sentc_crypto_core::SecretKey,
		sentc_crypto_core::SignKey,
		sentc_crypto_core::HmacKey,
		SortKeys,
	>(&creators_public_key.key, user_group)?;
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
		let encrypted_sign_key = out.encrypted_sign_key.map(|k| Base64::encode_string(&k));

		let verify_key = if let Some(vk) = out.verify_key {
			Some(export_raw_verify_key_to_pem(&vk)?)
		} else {
			None
		};

		let keypair_sign_alg = out.keypair_sign_alg.map(|s| s.to_string());
		let public_key_sig = out.public_key_sig.map(|s| sig_to_string(&s));

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

	//return the non-registered version of the group key and the public group key to use it
	// to create child groups or connect to a group without register the group
	let group_public_key_int = PublicKey {
		key: out.public_group_key,
		key_id: "non_registered".to_string(),
	};

	let created_group_key = SymmetricKey {
		key: created_group_key,
		key_id: "non_registered".to_string(),
	};

	Ok((create_out, group_public_key_int, created_group_key))
}

pub fn key_rotation(
	previous_group_key: &SymmetricKey,
	invoker_public_key: &PublicKey,
	user_group: bool,
	sign_key: Option<&SignKey>,
	starter: UserId,
) -> Result<String, SdkError>
{
	let out = core_group::key_rotation::<sentc_crypto_core::SymmetricKey, sentc_crypto_core::SecretKey, sentc_crypto_core::SignKey>(
		&previous_group_key.key,
		&invoker_public_key.key,
		user_group,
	)?;

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
		let encrypted_sign_key = out.encrypted_sign_key.map(|k| Base64::encode_string(&k));

		let verify_key = if let Some(vk) = out.verify_key {
			Some(export_raw_verify_key_to_pem(&vk)?)
		} else {
			None
		};

		let keypair_sign_alg = out.keypair_sign_alg.map(|alg| alg.to_string());

		let public_key_sig = out.public_key_sig.map(|s| sig_to_string(&s));

		(encrypted_sign_key, verify_key, keypair_sign_alg, public_key_sig)
	};

	//4. if set sign the encrypted group key
	let (encrypted_group_key_by_ephemeral, signed_by_user_id, signed_by_user_sign_key_id, signed_by_user_sign_key_alg) = if let Some(sk) = sign_key {
		let sig = sk.sign(&out.encrypted_group_key_by_ephemeral)?;
		(
			Base64::encode_string(&sig),
			Some(starter),
			Some(sk.key_id.clone()),
			Some(sk.get_alg_str().to_string()),
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
pub fn get_done_key_rotation_server_input(server_output: &str) -> Result<KeyRotationInput, SdkError>
{
	KeyRotationInput::from_string(server_output).map_err(|_| SdkError::KeyRotationServerOutputWrong)
}

pub fn done_key_rotation(
	private_key: &SecretKey,
	public_key: &PublicKey,
	previous_group_key: &SymmetricKey,
	server_output: KeyRotationInput,
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<String, SdkError>
{
	if let Some(e) = server_output.error {
		return Err(SdkError::KeyRotationEncryptError(e));
	}

	//the id of the previous group key was returned by the server too so the sdk impl knows which key it used

	//these values were encoded by key_rotation_internally
	let encrypted_ephemeral_key_by_group_key_and_public_key =
		Base64::decode_vec(&server_output.encrypted_ephemeral_key_by_group_key_and_public_key).map_err(|_| SdkError::KeyRotationServerOutputWrong)?;
	let encrypted_group_key_by_ephemeral =
		Base64::decode_vec(&server_output.encrypted_group_key_by_ephemeral).map_err(|_| SdkError::KeyRotationServerOutputWrong)?;

	//if verify key set then verify the new group key first

	//get from the KeyRotationInput also if the key was signed before and only then do to verify, even if a verify key was set.
	//the user id doesn't matter here.
	let encrypted_group_key_by_ephemeral = match (
		server_output.signed_by_user_id,
		server_output.signed_by_user_sign_key_id,
		server_output.signed_by_user_sign_key_alg,
	) {
		(Some(_user_id), Some(sign_key_id), Some(sign_key_alg)) => {
			match verify_key {
				Some(vk) => {
					VerifyKey::verify_with_user_key(
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
					let (_, encrypted_group_key_by_ephemeral) = CoreSig::split_sig_and_data(&sign_key_alg, &encrypted_group_key_by_ephemeral)?;

					encrypted_group_key_by_ephemeral
				},
			}
		},
		_ => {
			//no sign headset for key rotation
			&encrypted_group_key_by_ephemeral
		},
	};

	let out = core_group::done_key_rotation::<sentc_crypto_core::SymmetricKey>(
		&private_key.key,
		&public_key.key,
		&previous_group_key.key,
		&encrypted_ephemeral_key_by_group_key_and_public_key,
		encrypted_group_key_by_ephemeral,
		&server_output.ephemeral_alg,
	)?;

	let encrypted_new_group_key = Base64::encode_string(&out);

	let encrypted_alg = public_key.key.get_alg_str().to_string();

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
pub fn get_group_keys_from_server_output(server_output: &str) -> Result<Vec<GroupKeyServerOutput>, SdkError>
{
	let server_output: Vec<GroupKeyServerOutput> = handle_server_response(server_output)?;

	Ok(server_output)
}

pub fn get_group_key_from_server_output(server_output: &str) -> Result<GroupKeyServerOutput, SdkError>
{
	let server_output: GroupKeyServerOutput = handle_server_response(server_output)?;

	Ok(server_output)
}

pub fn get_group_data(server_output: &str) -> Result<GroupOutData, SdkError>
{
	let server_output: GroupServerData = handle_server_response(server_output)?;

	let (access_by_group_as_member, access_by_parent_group) = sentc_crypto_utils::group::get_access_by(server_output.access_by);

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

pub fn get_group_light_data(server_output: &str) -> Result<GroupOutDataLight, SdkError>
{
	let server_output: GroupLightServerData = handle_server_response(server_output)?;

	let (access_by_group_as_member, access_by_parent_group) = sentc_crypto_utils::group::get_access_by(server_output.access_by);

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
pub fn decrypt_group_hmac_key(group_key: &SymmetricKey, server_output: GroupHmacData) -> Result<HmacKey, SdkError>
{
	let encrypted_hmac_key = Base64::decode_vec(&server_output.encrypted_hmac_key).map_err(|_| SdkUtilError::DerivedKeyWrongFormat)?;

	let key = CoreHmacKey::decrypt_key_with_master_key(&group_key.key, &encrypted_hmac_key, &server_output.encrypted_hmac_alg)?;

	Ok(HmacKey {
		key_id: server_output.id,
		key,
	})
}

pub fn decrypt_group_sortable_key(group_key: &SymmetricKey, server_output: GroupSortableData) -> Result<SortableKey, SdkError>
{
	let encrypted_key = Base64::decode_vec(&server_output.encrypted_sortable_key).map_err(|_| SdkUtilError::DerivedKeyWrongFormat)?;

	let key = CoreSortableKey::decrypt_key_with_master_key(&group_key.key, &encrypted_key, &server_output.encrypted_sortable_alg)?;

	Ok(SortableKey {
		key_id: server_output.id,
		key,
	})
}

/**
Call this fn for each key, with the right private key
 */
pub fn decrypt_group_keys(private_key: &SecretKey, server_output: GroupKeyServerOutput) -> Result<GroupKeyData, SdkError>
{
	//the user_public_key_id is used to get the right private key
	let encrypted_master_key = Base64::decode_vec(server_output.encrypted_group_key.as_str()).map_err(|_| SdkUtilError::DerivedKeyWrongFormat)?;
	let encrypted_private_key =
		Base64::decode_vec(server_output.encrypted_private_group_key.as_str()).map_err(|_| SdkUtilError::DerivedKeyWrongFormat)?;

	let (group_key, private_group_key) = core_group::get_group::<sentc_crypto_core::SymmetricKey, sentc_crypto_core::SecretKey>(
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
		group_key: SymmetricKey {
			key: group_key,
			key_id: server_output.group_key_id,
		},
		private_group_key: SecretKey {
			key_id: server_output.key_pair_id.clone(),
			key: private_group_key,
		},
		public_group_key: PublicKey {
			key_id: server_output.key_pair_id,
			key: public_group_key,
		},
		exported_public_key,
		time: server_output.time,
	})
}

pub fn prepare_group_keys_for_new_member(
	requester_public_key_data: &UserPublicKeyData,
	group_keys: &[&SymmetricKey],
	key_session: bool, //this value must be set form each sdk impl from key storage when more than 100 keys are used
	rank: Option<i32>,
) -> Result<String, SdkError>
{
	let server_input = prepare_group_keys_for_new_member_typed(requester_public_key_data, group_keys, key_session, rank)?;

	server_input
		.to_string()
		.map_err(|_| SdkError::JsonToStringFailed)
}

pub fn prepare_group_keys_for_new_member_typed(
	requester_public_key_data: &UserPublicKeyData,
	group_keys: &[&SymmetricKey],
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

pub fn prepare_group_keys_for_new_member_with_group_public_key(
	requester_public_key_data: &PublicKey,
	group_keys: &[&SymmetricKey],
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
pub fn prepare_group_keys_for_new_member_via_session(
	requester_public_key_data: &UserPublicKeyData,
	group_keys: &[&SymmetricKey],
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
	public_key: &CorePublicKey,
	public_key_id: &str,
	group_keys: &[&SymmetricKey],
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

pub fn prepare_change_rank(user_id: &str, new_rank: i32, admin_rank: i32) -> Result<String, SdkError>
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
	use sentc_crypto_core::cryptomat::Pk;

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

		let (data, _, _, _, _) = create_group(&user.user_keys[0]);

		assert_eq!(data.group_id, "123".to_string());
	}

	#[test]
	fn test_get_group_data_and_keys()
	{
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
			group_keys.push(decrypt_group_keys(&user_keys.private_key, k).unwrap());
		}

		assert_eq!(
			key_data[0].group_key.key.as_ref(),
			group_keys[0].group_key.key.as_ref()
		);

		//fetch the key single
		let key = get_group_key_from_server_output(single_fetch.as_str()).unwrap();

		let group_keys_from_single_server_out = decrypt_group_keys(&user_keys.private_key, key).unwrap();

		assert_eq!(
			&key_data[0].group_key.key.as_ref(),
			&group_keys_from_single_server_out.group_key.key.as_ref()
		);
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
			group_keys_u2.push(decrypt_group_keys(&user_keys1.private_key, key).unwrap());
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
			group_keys_u1.push(decrypt_group_keys(&user1.user_keys[0].private_key, key).unwrap());
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
		let user = create_user();

		let (_data, key_data, group_server_out, _, _) = create_group(&user.user_keys[0]);

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
		assert_ne!(key_data[0].group_key.key.as_ref(), out.group_key.key.as_ref());

		assert_eq!(
			new_group_key_direct.group_key.key.as_ref(),
			out.group_key.key.as_ref()
		);
	}

	#[test]
	fn test_signed_key_rotation()
	{
		let user = create_user();

		let (_data, key_data, group_server_out, _, _) = create_group(&user.user_keys[0]);

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
		assert_ne!(key_data[0].group_key.key.as_ref(), out.group_key.key.as_ref());

		assert_eq!(
			new_group_key_direct.group_key.key.as_ref(),
			out.group_key.key.as_ref()
		);
	}
}
