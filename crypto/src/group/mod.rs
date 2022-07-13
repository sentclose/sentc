//use here key ids from the api, the core sdk don't care about the ids because we have to call every function with the right keys
//but in the higher level mod we must care
//handle the key id for get group, and the rotation + accept / invite user

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use sentc_crypto_common::group::{
	CreateData,
	DoneKeyRotationData,
	GroupKeyServerOutput,
	GroupKeysForNewMember,
	GroupKeysForNewMemberServerInput,
	KeyRotationData,
	KeyRotationInput,
};
use sentc_crypto_common::user::UserPublicKeyData;
use sentc_crypto_common::GroupId;
use sentc_crypto_core::group::{
	done_key_rotation as done_key_rotation_core,
	get_group as get_group_core,
	key_rotation as key_rotation_core,
	prepare_create as prepare_create_core,
	prepare_group_keys_for_new_member as prepare_group_keys_for_new_member_core,
};
use sentc_crypto_core::{Error, Pk};

use crate::util::{export_raw_public_key_to_pem, import_public_key_from_pem_with_alg, PrivateKeyFormatInt, PublicKeyFormatInt, SymKeyFormatInt};

#[cfg(not(feature = "rust"))]
mod group;

#[cfg(feature = "rust")]
mod group_rust;

#[cfg(not(feature = "rust"))]
pub use self::group::{
	done_key_rotation,
	get_group_data,
	key_rotation,
	prepare_create,
	prepare_group_keys_for_new_member,
	GroupKeyData,
	GroupKeys,
	GroupOutData,
};
#[cfg(feature = "rust")]
pub use self::group_rust::{done_key_rotation, get_group_data, key_rotation, prepare_create, prepare_group_keys_for_new_member, GroupOutData};
#[cfg(feature = "rust")]
pub use self::DoneGettingGroupKeysOutput as GroupKeyData;

pub struct DoneGettingGroupKeysOutput
{
	pub group_key: SymKeyFormatInt,
	pub private_group_key: PrivateKeyFormatInt,
	pub public_group_key: PublicKeyFormatInt,
}

fn prepare_create_internally(creators_public_key: &PublicKeyFormatInt, parent_group_id: Option<GroupId>) -> Result<String, Error>
{
	//it is ok to use the internal format of the public key here because this is the own public key and get return from the done login fn
	let out = prepare_create_core(&creators_public_key.key)?;

	//1. encode the values to base64 for the server
	let encrypted_group_key = Base64::encode_string(&out.encrypted_group_key);
	let encrypted_private_group_key = Base64::encode_string(&out.encrypted_private_group_key);

	//2. export the public key
	let public_group_key = export_raw_public_key_to_pem(&out.public_group_key)?;

	let create_out = CreateData {
		public_group_key,
		encrypted_group_key,
		encrypted_private_group_key,
		encrypted_group_key_alg: out.encrypted_group_key_alg.to_string(),
		group_key_alg: out.group_key_alg.to_string(),
		keypair_encrypt_alg: out.keypair_encrypt_alg.to_string(),
		creator_public_key_id: creators_public_key.key_id.clone(),
		parent_group_id,
	};

	Ok(create_out
		.to_string()
		.map_err(|_| Error::JsonToStringFailed)?)
}

fn key_rotation_internally(previous_group_key: &SymKeyFormatInt, invoker_public_key: &PublicKeyFormatInt) -> Result<String, Error>
{
	let out = key_rotation_core(&previous_group_key.key, &invoker_public_key.key)?;

	//1. encode the values to base64 for the server
	let encrypted_group_key_by_user = Base64::encode_string(&out.encrypted_group_key_by_user);
	let encrypted_private_group_key = Base64::encode_string(&out.encrypted_private_group_key);
	let encrypted_group_key_by_ephemeral = Base64::encode_string(&out.encrypted_group_key_by_ephemeral);
	let encrypted_ephemeral_key = Base64::encode_string(&out.encrypted_ephemeral_key);

	//2. export the public key
	let public_group_key = export_raw_public_key_to_pem(&out.public_group_key)?;

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
	};

	Ok(rotation_out
		.to_string()
		.map_err(|_| Error::JsonToStringFailed)?)
}

fn done_key_rotation_internally(
	private_key: &PrivateKeyFormatInt,
	public_key: &PublicKeyFormatInt,
	previous_group_key: &SymKeyFormatInt,
	server_output: &KeyRotationInput,
) -> Result<String, Error>
{
	//the id of the previous group key was returned by the server too so the sdk impl knows which key it used

	//this values were encoded by key_rotation_internally
	let encrypted_ephemeral_key_by_group_key_and_public_key = Base64::decode_vec(
		server_output
			.encrypted_ephemeral_key_by_group_key_and_public_key
			.as_str(),
	)
	.map_err(|_| Error::KeyRotationServerOutputWrong)?;
	let encrypted_group_key_by_ephemeral =
		Base64::decode_vec(server_output.encrypted_group_key_by_ephemeral.as_str()).map_err(|_| Error::KeyRotationServerOutputWrong)?;

	let out = done_key_rotation_core(
		&private_key.key,
		&public_key.key,
		&previous_group_key.key,
		&encrypted_ephemeral_key_by_group_key_and_public_key,
		&encrypted_group_key_by_ephemeral,
		server_output.ephemeral_alg.as_str(),
	)?;

	let encrypted_new_group_key = Base64::encode_string(&out);

	let done_rotation_out = DoneKeyRotationData {
		encrypted_new_group_key,
		public_key_id: public_key.key_id.clone(),
	};

	Ok(done_rotation_out
		.to_string()
		.map_err(|_| Error::JsonToStringFailed)?)
}

fn get_group_keys_internally(private_key: &PrivateKeyFormatInt, server_output: &GroupKeyServerOutput) -> Result<DoneGettingGroupKeysOutput, Error>
{
	//the user_public_key_id is used to get the right private key
	let encrypted_master_key = Base64::decode_vec(server_output.encrypted_group_key.as_str()).map_err(|_| Error::DerivedKeyWrongFormat)?;
	let encrypted_private_key = Base64::decode_vec(server_output.encrypted_private_group_key.as_str()).map_err(|_| Error::DerivedKeyWrongFormat)?;

	let (group_key, private_group_key) = get_group_core(
		&private_key.key,
		&encrypted_master_key,
		&encrypted_private_key,
		server_output.group_key_alg.as_str(),
		server_output.keypair_encrypt_alg.as_str(),
	)?;

	let public_group_key = import_public_key_from_pem_with_alg(&server_output.public_group_key, server_output.keypair_encrypt_alg.as_str())?;

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
	})
}

fn prepare_group_keys_for_new_member_internally(
	requester_public_key_data: &UserPublicKeyData,
	group_keys: &[&SymKeyFormatInt],
) -> Result<String, Error>
{
	let public_key = import_public_key_from_pem_with_alg(
		requester_public_key_data.public_key_pem.as_str(),
		requester_public_key_data.public_key_alg.as_str(),
	)?;

	prepare_group_keys_for_new_member_internally_with_public_key(&public_key, requester_public_key_data.public_key_id.as_str(), group_keys)
}

fn prepare_group_keys_for_new_member_internally_with_public_key(
	public_key: &Pk,
	public_key_id: &str,
	group_keys: &[&SymKeyFormatInt],
) -> Result<String, Error>
{
	//split group keys and their ids
	let mut split_group_keys = Vec::with_capacity(group_keys.len());
	let mut split_group_ids = Vec::with_capacity(group_keys.len());

	for group_key in group_keys {
		split_group_keys.push(&group_key.key);
		split_group_ids.push(group_key.key_id.as_str());
	}

	//get all the group keys from the server and use get group for all (if not already on the device)
	let out = prepare_group_keys_for_new_member_core(public_key, &split_group_keys)?;

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
		});

		i += 1;
	}

	let server_input = GroupKeysForNewMemberServerInput(encrypted_group_keys);

	Ok(server_input
		.to_string()
		.map_err(|_| Error::JsonToStringFailed)?)
}

#[cfg(test)]
pub(crate) mod test_fn
{
	use alloc::vec;

	use sentc_crypto_common::group::GroupServerData;

	use super::*;
	use crate::util::KeyData;

	#[cfg(feature = "rust")]
	pub(crate) fn create_group(user: &KeyData) -> (GroupOutData, GroupServerData)
	{
		#[cfg(feature = "rust")]
		let group = prepare_create(&user.public_key, None).unwrap();
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
		};

		let group_server_output = GroupServerData {
			group_id: "123".to_string(),
			keys: vec![group_server_output],
			keys_page: 0,
		};

		#[cfg(feature = "rust")]
		let out = get_group_data(&user.private_key, &group_server_output).unwrap();

		(out, group_server_output)
	}

	#[cfg(not(feature = "rust"))]
	pub(crate) fn create_group(user: &KeyData) -> (GroupOutData, GroupServerData)
	{
		#[cfg(not(feature = "rust"))]
		let group = prepare_create(user.public_key.to_string().unwrap().as_str(), None).unwrap();
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
		};

		let group_server_output = GroupServerData {
			group_id: "123".to_string(),
			keys: vec![group_server_output],
			keys_page: 0,
		};

		#[cfg(not(feature = "rust"))]
		let group_data_string = get_group_data(
			user.private_key.to_string().unwrap().as_str(),
			group_server_output.to_string().unwrap().as_str(),
		)
		.unwrap();

		let out = GroupOutData::from_string(group_data_string.as_str()).unwrap();

		(out, group_server_output)
	}
}
