use alloc::string::String;
use alloc::vec::Vec;

use sendclose_crypto_common::group::{GroupKeyServerOutput, GroupNewMemberPublicKeyData, GroupServerData, KeyRotationInput};
use sendclose_crypto_core::Error;
use serde::{Deserialize, Serialize};
use serde_json::{from_slice, to_string};

use crate::err_to_msg;
use crate::group::{
	done_key_rotation_internally,
	get_group_keys_internally,
	key_rotation_internally,
	prepare_create_internally,
	prepare_group_keys_for_new_member_internally,
};
use crate::util::{
	export_private_key,
	export_public_key,
	export_sym_key,
	import_private_key,
	import_public_key,
	import_sym_key,
	PrivateKeyFormat,
	PrivateKeyFormatInt,
	PublicKeyFormat,
	SymKeyFormat,
	SymKeyFormatInt,
};

#[derive(Serialize, Deserialize)]
pub struct GroupKeyData
{
	pub private_group_key: PrivateKeyFormat,
	pub public_group_key: PublicKeyFormat,
	pub group_key: SymKeyFormat,
}

impl GroupKeyData
{
	pub fn from_string(v: &[u8]) -> serde_json::Result<Self>
	{
		from_slice::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}

#[derive(Serialize, Deserialize)]
pub struct GroupOutData
{
	pub group_id: String,
	pub keys: Vec<GroupKeyData>,
}

impl GroupOutData
{
	pub fn from_string(v: &[u8]) -> serde_json::Result<Self>
	{
		from_slice::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}

pub fn prepare_create(creators_public_key: &str) -> String
{
	let creators_public_key = match import_public_key(creators_public_key) {
		Ok(k) => k,
		Err(e) => return err_to_msg(e),
	};

	match prepare_create_internally(&creators_public_key) {
		Ok(v) => v,
		Err(e) => err_to_msg(e),
	}
}

pub fn key_rotation(previous_group_key: &str, invoker_public_key: &str) -> String
{
	//the ids comes from the storage of the current impl from the sdk, the group key id comes from get group
	let previous_group_key = match import_sym_key(previous_group_key) {
		Ok(k) => k,
		Err(e) => return err_to_msg(e),
	};

	let invoker_public_key = match import_public_key(invoker_public_key) {
		Ok(k) => k,
		Err(e) => return err_to_msg(e),
	};

	match key_rotation_internally(&previous_group_key, &invoker_public_key) {
		Ok(v) => v,
		Err(e) => err_to_msg(e),
	}
}

pub fn done_key_rotation(private_key: &str, public_key: &str, previous_group_key: &str, server_output: &str) -> String
{
	let previous_group_key = match import_sym_key(previous_group_key) {
		Ok(k) => k,
		Err(e) => return err_to_msg(e),
	};

	let private_key = match import_private_key(private_key) {
		Ok(k) => k,
		Err(e) => return err_to_msg(e),
	};

	let public_key = match import_public_key(public_key) {
		Ok(k) => k,
		Err(e) => return err_to_msg(e),
	};

	let server_output = match KeyRotationInput::from_string(server_output.as_bytes()).map_err(|_| Error::KeyRotationServerOutputWrong) {
		Ok(k) => k,
		Err(e) => return err_to_msg(e),
	};

	match done_key_rotation_internally(&private_key, &public_key, &previous_group_key, &server_output) {
		Ok(v) => v,
		Err(e) => err_to_msg(e),
	}
}

fn get_group_keys(private_key: &PrivateKeyFormatInt, server_output: &GroupKeyServerOutput) -> Result<GroupKeyData, Error>
{
	let result = get_group_keys_internally(&private_key, &server_output)?;

	let private_group_key = export_private_key(result.private_group_key);
	let public_group_key = export_public_key(result.public_group_key);
	let group_key = export_sym_key(result.group_key);

	Ok(GroupKeyData {
		private_group_key,
		public_group_key,
		group_key,
	})
}

pub fn get_group_data(private_key: &str, server_output: &str) -> String
{
	let server_output = match GroupServerData::from_string(server_output.as_bytes()) {
		Ok(o) => o,
		Err(_e) => return err_to_msg(Error::JsonParseFailed),
	};

	let private_key = match import_private_key(private_key) {
		Ok(k) => k,
		Err(e) => return err_to_msg(e),
	};

	//resolve a group key page
	let mut keys = Vec::with_capacity(server_output.keys.len());

	for key in server_output.keys {
		let value = match get_group_keys(&private_key, &key) {
			Ok(v) => v,
			Err(e) => return err_to_msg(e),
		};

		keys.push(value);
	}

	let data = GroupOutData {
		group_id: server_output.group_id,
		keys,
	};

	match data.to_string() {
		Ok(o) => o,
		Err(_e) => return err_to_msg(Error::JsonToStringFailed),
	}
}

pub fn prepare_group_keys_for_new_member(requester_public_key_data: &str, group_keys: &[String]) -> String
{
	let requester_public_key_data = match GroupNewMemberPublicKeyData::from_string(requester_public_key_data.as_bytes()) {
		Ok(v) => v,
		Err(_e) => return err_to_msg(Error::JsonParseFailed),
	};

	let mut saved_keys = Vec::with_capacity(group_keys.len());

	//split group key and id
	for group_key in group_keys {
		let key = match import_sym_key(group_key) {
			Ok(v) => v,
			Err(e) => return err_to_msg(e),
		};

		saved_keys.push(key);
	}

	let split_group_keys = prepare_group_keys_for_new_member_with_ref(&saved_keys);

	match prepare_group_keys_for_new_member_internally(&requester_public_key_data, &split_group_keys) {
		Ok(o) => o,
		Err(e) => return err_to_msg(e),
	}
}

fn prepare_group_keys_for_new_member_with_ref(saved_keys: &Vec<SymKeyFormatInt>) -> Vec<&SymKeyFormatInt>
{
	//this is needed because we need only ref of the group key not the group key itself.
	//but for the non rust version the key is just a string which gets

	let mut split_group_keys = Vec::with_capacity(saved_keys.len());

	for saved_key in saved_keys {
		split_group_keys.push(saved_key);
	}

	split_group_keys
}
