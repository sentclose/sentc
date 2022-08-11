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
//invite

/**
Prepare all group keys for a new member.

Use the group keys from get group data or get group keys fn as string array
*/
#[wasm_bindgen]
pub fn prepare_keys_for_new_member(user_public_key: &str, group_keys: &str, key_count: i32, admin_rank: i32) -> Result<String, JsValue>
{
	group::check_make_invite_req(admin_rank)?;

	let key_session = if key_count > 50 { true } else { false };

	let input = group::prepare_group_keys_for_new_member(user_public_key, group_keys, key_session)?;

	Ok(input)
}

#[wasm_bindgen]
pub async fn invite_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	user_id: String,
	key_count: i32,
	admin_rank: i32,
	user_public_key: String,
	group_keys: String,
) -> Result<String, JsValue>
{
	let out = sentc_crypto_full::group::invite_user(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		user_id.as_str(),
		key_count,
		admin_rank,
		user_public_key.as_str(),
		group_keys.as_str(),
	)
	.await?;

	match out {
		Some(id) => Ok(id),
		None => Ok(String::from("")),
	}
}

#[wasm_bindgen]
pub async fn invite_user_session(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	session_id: String,
	user_public_key: String,
	group_keys: String,
) -> Result<(), JsValue>
{
	sentc_crypto_full::group::invite_user_session(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		session_id.as_str(),
		user_public_key.as_str(),
		group_keys.as_str(),
	)
	.await?;

	Ok(())
}

#[wasm_bindgen]
pub async fn get_invites_for_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	last_fetched_time: String,
	last_fetched_group_id: String,
) -> Result<JsValue, JsValue>
{
	let out = sentc_crypto_full::group::get_invites_for_user(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		last_fetched_time.as_str(),
		last_fetched_group_id.as_str(),
	)
	.await?;

	Ok(JsValue::from_serde(&out).unwrap())
}

#[wasm_bindgen]
pub async fn accept_invite(base_url: String, auth_token: String, jwt: String, id: String) -> Result<(), JsValue>
{
	sentc_crypto_full::group::accept_invite(base_url, auth_token.as_str(), jwt.as_str(), id.as_str()).await?;

	Ok(())
}

#[wasm_bindgen]
pub async fn reject_invite(base_url: String, auth_token: String, jwt: String, id: String) -> Result<(), JsValue>
{
	sentc_crypto_full::group::reject_invite(base_url, auth_token.as_str(), jwt.as_str(), id.as_str()).await?;

	Ok(())
}

//__________________________________________________________________________________________________
//join req

#[wasm_bindgen]
pub async fn join_req(base_url: String, auth_token: String, jwt: String, id: String) -> Result<(), JsValue>
{
	sentc_crypto_full::group::join_req(base_url, auth_token.as_str(), jwt.as_str(), id.as_str()).await?;

	Ok(())
}

#[wasm_bindgen]
pub async fn get_join_reqs(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	admin_rank: i32,
	last_fetched_time: String,
	last_fetched_id: String,
) -> Result<JsValue, JsValue>
{
	let out = sentc_crypto_full::group::get_join_reqs(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		admin_rank,
		last_fetched_time.as_str(),
		last_fetched_id.as_str(),
	)
	.await?;

	Ok(JsValue::from_serde(&out).unwrap())
}

#[wasm_bindgen]
pub async fn reject_join_req(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	admin_rank: i32,
	rejected_user_id: String,
) -> Result<(), JsValue>
{
	sentc_crypto_full::group::reject_join_req(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		admin_rank,
		rejected_user_id.as_str(),
	)
	.await?;

	Ok(())
}

#[wasm_bindgen]
pub async fn accept_join_req(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	user_id: String,
	key_count: i32,
	admin_rank: i32,
	user_public_key: String,
	group_keys: String,
) -> Result<String, JsValue>
{
	let out = sentc_crypto_full::group::accept_join_req(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		user_id.as_str(),
		key_count,
		admin_rank,
		user_public_key.as_str(),
		group_keys.as_str(),
	)
	.await?;

	match out {
		Some(id) => Ok(id),
		None => Ok(String::from("")),
	}
}

#[wasm_bindgen]
pub async fn join_user_session(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	session_id: String,
	user_public_key: String,
	group_keys: String,
) -> Result<(), JsValue>
{
	sentc_crypto_full::group::join_user_session(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		session_id.as_str(),
		user_public_key.as_str(),
		group_keys.as_str(),
	)
	.await?;

	Ok(())
}

//__________________________________________________________________________________________________

#[wasm_bindgen]
pub async fn leave_group(base_url: String, auth_token: String, jwt: String, id: String) -> Result<(), JsValue>
{
	sentc_crypto_full::group::leave_group(base_url, auth_token.as_str(), jwt.as_str(), id.as_str()).await?;

	Ok(())
}

//__________________________________________________________________________________________________
//key rotation

#[wasm_bindgen]
pub fn prepare_key_rotation(pre_group_key: &str, public_key: &str) -> Result<String, JsValue>
{
	let out = group::key_rotation(pre_group_key, public_key)?;

	Ok(out)
}

#[wasm_bindgen]
pub fn done_key_rotation(private_key: &str, public_key: &str, pre_group_key: &str, server_output: &str) -> Result<String, JsValue>
{
	let out = group::done_key_rotation(private_key, public_key, pre_group_key, server_output)?;

	Ok(out)
}

#[wasm_bindgen]
pub async fn key_rotation(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	public_key: String,
	pre_group_key: String,
) -> Result<String, JsValue>
{
	let out = sentc_crypto_full::group::key_rotation(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		public_key.as_str(),
		pre_group_key.as_str(),
	)
	.await?;

	Ok(out)
}

/**
Get the keys for done key rotation.

Then call for each key rotation server output the finish_key_rotation fn
*/
#[wasm_bindgen]
pub async fn pre_done_key_rotation(base_url: String, auth_token: String, jwt: String, id: String) -> Result<JsValue, JsValue>
{
	let out = sentc_crypto_full::group::prepare_done_key_rotation(base_url, auth_token.as_str(), jwt.as_str(), id.as_str()).await?;

	Ok(JsValue::from_serde(&out).unwrap())
}

#[wasm_bindgen]
pub async fn finish_key_rotation(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	server_output: String,
	pre_group_key: String,
	public_key: String,
	private_key: String,
) -> Result<(), JsValue>
{
	sentc_crypto_full::group::done_key_rotation(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		server_output.as_str(),
		pre_group_key.as_str(),
		public_key.as_str(),
		private_key.as_str(),
	)
	.await?;

	Ok(())
}

//__________________________________________________________________________________________________
//group update fn

#[wasm_bindgen]
pub fn prepare_update_rank(user_id: &str, rank: i32, admin_rank: i32) -> Result<String, JsValue>
{
	let input = group::prepare_change_rank(user_id, rank, admin_rank)?;

	Ok(input)
}

#[wasm_bindgen]
pub async fn update_rank(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	user_id: String,
	rank: i32,
	admin_rank: i32,
) -> Result<(), JsValue>
{
	sentc_crypto_full::group::update_rank(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		user_id.as_str(),
		rank,
		admin_rank,
	)
	.await?;

	Ok(())
}

#[wasm_bindgen]
pub async fn kick_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	user_id: String,
	rank: i32,
	admin_rank: i32,
) -> Result<(), JsValue>
{
	sentc_crypto_full::group::kick_user(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		user_id.as_str(),
		rank,
		admin_rank,
	)
	.await?;

	Ok(())
}

//__________________________________________________________________________________________________
