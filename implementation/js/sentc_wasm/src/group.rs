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
pub fn prepare_create(creators_public_key: &str) -> String
{
	prepare_create_core(creators_public_key)
}

#[wasm_bindgen]
pub fn key_rotation(previous_group_key: &str, invoker_public_key: &str) -> String
{
	key_rotation_core(previous_group_key, invoker_public_key)
}

#[wasm_bindgen]
pub fn done_key_rotation(private_key: &str, public_key: &str, previous_group_key: &str, server_output: &str) -> String
{
	done_key_rotation_core(private_key, public_key, previous_group_key, server_output)
}

#[wasm_bindgen]
pub fn get_group_data(private_key: &str, server_output: &str) -> String
{
	get_group_data_core(private_key, server_output)
}

#[wasm_bindgen]
pub fn prepare_group_keys_for_new_member(requester_public_key_data: &str, group_keys: &str) -> String
{
	prepare_group_keys_for_new_member_core(requester_public_key_data, group_keys)
}
