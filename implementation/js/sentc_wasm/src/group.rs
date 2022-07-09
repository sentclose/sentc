use alloc::string::String;

use sentc_crypto::group::{
	done_key_rotation as done_key_rotation_core,
	get_group_data as get_group_data_core,
	key_rotation as key_rotation_core,
	prepare_create as prepare_create_core,
	prepare_group_keys_for_new_member as prepare_group_keys_for_new_member_core,
};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn prepare_create(creators_public_key: String) -> String
{
	prepare_create_core(creators_public_key.as_str())
}

#[wasm_bindgen]
pub fn key_rotation(previous_group_key: String, invoker_public_key: String) -> String
{
	key_rotation_core(previous_group_key.as_str(), invoker_public_key.as_str())
}

#[wasm_bindgen]
pub fn done_key_rotation(private_key: String, public_key: String, previous_group_key: String, server_output: String) -> String
{
	done_key_rotation_core(
		private_key.as_str(),
		public_key.as_str(),
		previous_group_key.as_str(),
		server_output.as_str(),
	)
}

#[wasm_bindgen]
pub fn get_group_data(private_key: String, server_output: String) -> String
{
	get_group_data_core(private_key.as_str(), server_output.as_str())
}

#[wasm_bindgen]
pub fn prepare_group_keys_for_new_member(requester_public_key_data: String, group_keys: String) -> String
{
	prepare_group_keys_for_new_member_core(requester_public_key_data.as_str(), group_keys.as_str())
}
