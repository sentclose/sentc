use alloc::string::{String, ToString};

use sentc_crypto_light::util_req_full;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct GroupOutDataLightExport
{
	group_id: String,
	parent_group_id: Option<String>,
	rank: i32,
	created_time: u128,
	joined_time: u128,
	access_by_group_as_member: Option<String>,
	access_by_parent_group: Option<String>,
	is_connected_group: bool,
}

impl From<sentc_crypto_light::sdk_utils::group::GroupOutDataLightExport> for GroupOutDataLightExport
{
	fn from(value: sentc_crypto_light::sdk_utils::group::GroupOutDataLightExport) -> Self
	{
		Self {
			group_id: value.group_id,
			parent_group_id: value.parent_group_id,
			rank: value.rank,
			created_time: value.created_time,
			joined_time: value.joined_time,
			access_by_group_as_member: value.access_by_group_as_member,
			access_by_parent_group: value.access_by_parent_group,
			is_connected_group: value.is_connected_group,
		}
	}
}

#[wasm_bindgen]
impl GroupOutDataLightExport
{
	pub fn get_group_id(&self) -> String
	{
		self.group_id.clone()
	}

	pub fn get_parent_group_id(&self) -> Option<String>
	{
		self.parent_group_id.clone()
	}

	pub fn get_rank(&self) -> i32
	{
		self.rank
	}

	pub fn get_created_time(&self) -> String
	{
		self.created_time.to_string()
	}

	pub fn get_joined_time(&self) -> String
	{
		self.joined_time.to_string()
	}

	pub fn get_access_by_group_as_member(&self) -> Option<String>
	{
		self.access_by_group_as_member.clone()
	}

	pub fn get_access_by_parent_group(&self) -> Option<String>
	{
		self.access_by_parent_group.clone()
	}

	pub fn get_is_connected_group(&self) -> bool
	{
		self.is_connected_group
	}
}

//__________________________________________________________________________________________________

/**
Create a group with request.

Only the default values are send to the server, no extra data. If extra data is required, use prepare_create
 */
#[wasm_bindgen]
pub async fn group_create_group(base_url: String, auth_token: String, jwt: String, group_as_member: Option<String>) -> Result<String, JsValue>
{
	let out = util_req_full::group::create(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		group_as_member.as_deref(),
	)
	.await?;

	Ok(out)
}

#[wasm_bindgen]
pub async fn group_create_child_group(
	base_url: String,
	auth_token: String,
	jwt: String,
	parent_id: String,
	admin_rank: i32,
	group_as_member: Option<String>,
) -> Result<String, JsValue>
{
	let out = util_req_full::group::create_child_group(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		parent_id.as_str(),
		admin_rank,
		group_as_member.as_deref(),
	)
	.await?;

	Ok(out)
}

#[wasm_bindgen]
pub async fn group_create_connected_group(
	base_url: String,
	auth_token: String,
	jwt: String,
	connected_group_id: String,
	admin_rank: i32,
	group_as_member: Option<String>,
) -> Result<String, JsValue>
{
	let out = util_req_full::group::create_connected_group(
		base_url,
		&auth_token,
		&jwt,
		&connected_group_id,
		admin_rank,
		group_as_member.as_deref(),
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
pub fn group_extract_group_data(server_output: &str) -> Result<GroupOutDataLightExport, JsValue>
{
	let out = sentc_crypto_light::group::get_group_light_data(server_output)?;

	Ok(out.into())
}

//__________________________________________________________________________________________________
//invite

#[wasm_bindgen]
pub async fn group_invite_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	user_id: String,
	rank: Option<i32>,
	admin_rank: i32,
	auto_invite: bool,
	group_invite: bool,
	group_as_member: Option<String>,
) -> Result<(), JsValue>
{
	util_req_full::group::invite_user(
		base_url,
		&auth_token,
		&jwt,
		&id,
		&user_id,
		rank,
		admin_rank,
		auto_invite,
		group_invite,
		group_as_member.as_deref(),
	)
	.await?;

	Ok(())
}

//__________________________________________________________________________________________________
//join req

#[wasm_bindgen]
pub async fn group_accept_join_req(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	user_id: String,
	rank: Option<i32>,
	admin_rank: i32,
	group_as_member: Option<String>,
) -> Result<(), JsValue>
{
	util_req_full::group::accept_join_req(
		base_url,
		&auth_token,
		&jwt,
		&id,
		&user_id,
		rank,
		admin_rank,
		group_as_member.as_deref(),
	)
	.await?;

	Ok(())
}

//__________________________________________________________________________________________________
//group update fn

#[wasm_bindgen]
pub fn group_prepare_update_rank(user_id: &str, rank: i32, admin_rank: i32) -> Result<String, JsValue>
{
	let input = sentc_crypto_light::group::prepare_change_rank(user_id, rank, admin_rank)?;

	Ok(input)
}
