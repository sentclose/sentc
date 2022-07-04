//use here key ids from the api, the core sdk don't care about the ids because we have to call every function with the right keys
//but in the higher level mod we must care
//handle the key id for get group, and the rotation + accept / invite user

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use sendclose_crypto_common::group::{
	CreateData,
	DoneKeyRotationData,
	GroupKeyServerOutput,
	GroupKeysForNewMember,
	GroupKeysForNewMemberServerInput,
	KeyRotationData,
	KeyRotationInput,
};
use sendclose_crypto_core::group::{
	done_key_rotation as done_key_rotation_core,
	get_group as get_group_core,
	key_rotation as key_rotation_core,
	prepare_create as prepare_create_core,
	prepare_group_keys_for_new_member as prepare_group_keys_for_new_member_core,
};
use sendclose_crypto_core::{Error, Pk, Sk, SymKey};

use crate::util::{export_public_key_to_pem, import_public_key_from_pem_with_alg};

#[cfg(not(feature = "rust"))]
mod group;

#[cfg(feature = "rust")]
mod group_rust;

#[cfg(not(feature = "rust"))]
pub use self::group::{done_key_rotation, get_group_keys, key_rotation, prepare_create, prepare_group_keys_for_new_member, GroupData};
#[cfg(feature = "rust")]
pub use self::group_rust::{done_key_rotation, get_group_keys, key_rotation, prepare_create, prepare_group_keys_for_new_member, GroupData};

pub(crate) struct DoneGettingGroupOutput
{
	pub group_key: SymKey,
	pub private_group_key: Sk,
	pub public_group_key: Pk,
	pub key_pair_id: String,
	pub group_key_id: String,
}

fn prepare_create_internally(creators_public_key: &Pk, creator_public_key_id: &str) -> Result<String, Error>
{
	let out = prepare_create_core(creators_public_key)?;

	//1. encode the values to base64 for the server
	let encrypted_group_key = Base64::encode_string(&out.encrypted_group_key);
	let encrypted_private_group_key = Base64::encode_string(&out.encrypted_private_group_key);

	//2. export the public key
	let public_group_key = export_public_key_to_pem(&out.public_group_key)?;

	let create_out = CreateData {
		public_group_key,
		encrypted_group_key,
		encrypted_private_group_key,
		encrypted_group_key_alg: out.encrypted_group_key_alg.to_string(),
		group_key_alg: out.group_key_alg.to_string(),
		keypair_encrypt_alg: out.keypair_encrypt_alg.to_string(),
		creator_public_key_id: creator_public_key_id.to_string(),
	};

	Ok(create_out
		.to_string()
		.map_err(|_| Error::JsonToStringFailed)?)
}

fn key_rotation_internally(
	previous_group_key: &SymKey,
	invoker_public_key: &Pk,
	previous_group_key_id: &str,
	invoker_public_key_id: &str,
) -> Result<String, Error>
{
	let out = key_rotation_core(previous_group_key, invoker_public_key)?;

	//1. encode the values to base64 for the server
	let encrypted_group_key_by_user = Base64::encode_string(&out.encrypted_group_key_by_user);
	let encrypted_private_group_key = Base64::encode_string(&out.encrypted_private_group_key);
	let encrypted_group_key_by_ephemeral = Base64::encode_string(&out.encrypted_group_key_by_ephemeral);
	let encrypted_ephemeral_key = Base64::encode_string(&out.encrypted_ephemeral_key);

	//2. export the public key
	let public_group_key = export_public_key_to_pem(&out.public_group_key)?;

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
		previous_group_key_id: previous_group_key_id.to_string(),
		invoker_public_key_id: invoker_public_key_id.to_string(),
	};

	Ok(rotation_out
		.to_string()
		.map_err(|_| Error::JsonToStringFailed)?)
}

fn done_key_rotation_internally(
	private_key: &Sk,
	public_key: &Pk,
	previous_group_key: &SymKey,
	server_output: &KeyRotationInput,
	public_key_id: &str,
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
		private_key,
		public_key,
		previous_group_key,
		&encrypted_ephemeral_key_by_group_key_and_public_key,
		&encrypted_group_key_by_ephemeral,
		server_output.ephemeral_alg.as_str(),
	)?;

	let encrypted_new_group_key = Base64::encode_string(&out);

	let done_rotation_out = DoneKeyRotationData {
		encrypted_new_group_key,
		public_key_id: public_key_id.to_string(),
	};

	Ok(done_rotation_out
		.to_string()
		.map_err(|_| Error::JsonToStringFailed)?)
}

fn get_group_keys_internally(private_key: &Sk, server_output: &GroupKeyServerOutput) -> Result<DoneGettingGroupOutput, Error>
{
	//the user_public_key_id is used to get the right private key
	let encrypted_master_key = Base64::decode_vec(server_output.encrypted_group_key.as_str()).map_err(|_| Error::DerivedKeyWrongFormat)?;
	let encrypted_private_key = Base64::decode_vec(server_output.encrypted_private_group_key.as_str()).map_err(|_| Error::DerivedKeyWrongFormat)?;

	let (group_key, private_group_key) = get_group_core(
		private_key,
		&encrypted_master_key,
		&encrypted_private_key,
		server_output.group_key_alg.as_str(),
		server_output.keypair_encrypt_alg.as_str(),
	)?;

	let public_group_key = import_public_key_from_pem_with_alg(&server_output.public_group_key, server_output.keypair_encrypt_alg.as_str())?;

	Ok(DoneGettingGroupOutput {
		group_key,
		private_group_key,
		public_group_key,
		key_pair_id: server_output.key_pair_id.clone(),
		group_key_id: server_output.group_key_id.clone(),
	})
}

fn prepare_group_keys_for_new_member_internally(
	requester_public_key: &Pk,
	group_keys: &[&SymKey],
	group_key_ids: &[&str],
	requester_public_key_id: &str,
) -> Result<String, Error>
{
	//get all the group keys from the server and use get group for all (if not already on the device)
	let out = prepare_group_keys_for_new_member_core(requester_public_key, group_keys)?;

	//transform this vec to the server input by encode each encrypted key to base64
	let mut encrypted_group_keys: Vec<GroupKeysForNewMember> = Vec::with_capacity(out.len());

	let mut i = 0;

	for key_out in out {
		let encrypted_group_key = Base64::encode_string(&key_out.encrypted_group_key);
		let key_id = group_key_ids[i].to_string();

		encrypted_group_keys.push(GroupKeysForNewMember {
			encrypted_group_key,
			alg: key_out.alg.to_string(),
			user_public_key_id: requester_public_key_id.to_string(),
			key_id,
		});

		i += 1;
	}

	let server_input = GroupKeysForNewMemberServerInput(encrypted_group_keys);

	Ok(server_input
		.to_string()
		.map_err(|_| Error::JsonToStringFailed)?)
}
