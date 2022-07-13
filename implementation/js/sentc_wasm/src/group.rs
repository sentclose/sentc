use alloc::string::String;

use sentc_crypto::group;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn prepare_create(creators_public_key: &str) -> Result<String, String>
{
	group::prepare_create(creators_public_key, None)
}

#[wasm_bindgen]
pub fn key_rotation(previous_group_key: &str, invoker_public_key: &str) -> Result<String, String>
{
	group::key_rotation(previous_group_key, invoker_public_key)
}

#[wasm_bindgen]
pub fn done_key_rotation(private_key: &str, public_key: &str, previous_group_key: &str, server_output: &str) -> Result<String, String>
{
	group::done_key_rotation(private_key, public_key, previous_group_key, server_output)
}

#[wasm_bindgen]
pub fn get_group_data(private_key: &str, server_output: &str) -> Result<String, String>
{
	group::get_group_data(private_key, server_output)
}

#[wasm_bindgen]
pub fn prepare_group_keys_for_new_member(requester_public_key_data: &str, group_keys: &str) -> Result<String, String>
{
	group::prepare_group_keys_for_new_member(requester_public_key_data, group_keys)
}
