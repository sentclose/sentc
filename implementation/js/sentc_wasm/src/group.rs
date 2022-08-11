use alloc::string::{String, ToString};
use alloc::vec::Vec;

use sentc_crypto::group;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Serialize, Deserialize)]
pub struct GroupKeyData
{
	private_group_key: String,
	public_group_key: String,
	group_key: String,
	time: u128,
}

impl From<group::GroupKeyData> for GroupKeyData
{
	fn from(key: group::GroupKeyData) -> Self
	{
		Self {
			private_group_key: key.private_group_key,
			public_group_key: key.public_group_key,
			group_key: key.group_key,
			time: key.time,
		}
	}
}

#[wasm_bindgen]
pub struct GroupOutData
{
	group_id: String,
	parent_group_id: String,
	rank: i32,
	key_update: bool,
	created_time: u128,
	joined_time: u128,
	keys: Vec<GroupKeyData>,
}

impl From<group::GroupOutData> for GroupOutData
{
	fn from(data: group::GroupOutData) -> Self
	{
		let mut out_keys = Vec::with_capacity(data.keys.len());

		for key in data.keys {
			out_keys.push(key.into());
		}

		Self {
			group_id: data.group_id,
			parent_group_id: data.parent_group_id,
			rank: data.rank,
			key_update: data.key_update,
			created_time: data.created_time,
			joined_time: data.joined_time,
			keys: out_keys,
		}
	}
}

#[wasm_bindgen]
impl GroupOutData
{
	pub fn get_group_id(&self) -> String
	{
		self.group_id.clone()
	}

	pub fn get_keys(&self) -> JsValue
	{
		JsValue::from_serde(&self.keys).unwrap()
	}

	pub fn get_parent_group_id(&self) -> String
	{
		self.parent_group_id.clone()
	}

	pub fn get_rank(&self) -> i32
	{
		self.rank
	}

	pub fn get_key_update(&self) -> bool
	{
		self.key_update
	}

	pub fn get_created_time(&self) -> String
	{
		self.created_time.to_string()
	}

	pub fn get_joined_time(&self) -> String
	{
		self.joined_time.to_string()
	}
}

//__________________________________________________________________________________________________

/**
Create input for the server api.

Use this for group and child group. For child group use the public key of the parent group!
*/
#[wasm_bindgen]
pub fn prepare_create_group(creators_public_key: &str) -> Result<String, String>
{
	group::prepare_create(creators_public_key)
}

/**
Create a group with request.

Only the default values are send to the server, no extra data. If extra data is required, use prepare_create
*/
#[wasm_bindgen]
pub async fn create_group(base_url: String, auth_token: String, jwt: String, creators_public_key: String) -> Result<String, JsValue>
{
	let out = sentc_crypto_full::group::create(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		creators_public_key.as_str(),
	)
	.await?;

	Ok(out)
}

#[wasm_bindgen]
pub async fn create_child_group(
	base_url: String,
	auth_token: String,
	jwt: String,
	parent_public_key: String,
	parent_id: String,
	admin_rank: i32,
) -> Result<String, JsValue>
{
	let out = sentc_crypto_full::group::create_child_group(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		parent_id.as_str(),
		admin_rank,
		parent_public_key.as_str(),
	)
	.await?;

	Ok(out)
}

//__________________________________________________________________________________________________

/**
Get the group data without request.

Use the parent group private key when fetching child group data.
*/
#[wasm_bindgen]
pub fn extract_group_data(private_key: &str, server_output: &str) -> Result<GroupOutData, JsValue>
{
	let out = group::get_group_data(private_key, server_output)?;

	Ok(out.into())
}

/**
Get keys from pagination.

Call the group route with the last fetched key time and the last fetched key id. Get both from the key data.
*/
#[wasm_bindgen]
pub fn extract_group_keys(private_key: &str, server_output: &str) -> Result<JsValue, JsValue>
{
	let out = group::get_group_keys_from_pagination(private_key, server_output)?;

	let mut out_keys: Vec<GroupKeyData> = Vec::with_capacity(out.len());

	for key in out {
		out_keys.push(key.into());
	}

	Ok(JsValue::from_serde(&out_keys).unwrap())
}

#[wasm_bindgen]
pub async fn get_group_data(base_url: String, auth_token: String, jwt: String, private_key: String, id: String) -> Result<GroupOutData, JsValue>
{
	let out = sentc_crypto_full::group::get_group(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		private_key.as_str(),
	)
	.await?;

	Ok(out.into())
}

#[wasm_bindgen]
pub async fn get_group_keys(
	base_url: String,
	auth_token: String,
	jwt: String,
	private_key: String,
	id: String,
	last_fetched_time: String,
	last_fetched_key_id: String,
) -> Result<JsValue, JsValue>
{
	let out = sentc_crypto_full::group::get_group_keys(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		last_fetched_time.as_str(),
		last_fetched_key_id.as_str(),
		private_key.as_str(),
	)
	.await?;

	let mut out_keys: Vec<GroupKeyData> = Vec::with_capacity(out.len());

	for key in out {
		out_keys.push(key.into());
	}

	Ok(JsValue::from_serde(&out_keys).unwrap())
}

//__________________________________________________________________________________________________
