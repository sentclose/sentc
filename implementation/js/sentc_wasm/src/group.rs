use alloc::string::{String, ToString};

use sentc_crypto::group;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct GroupOutData
{
	group_id: String,
	parent_group_id: String,
	rank: i32,
	key_update: bool,
	created_time: u128,
	joined_time: u128,
	keys: JsValue,
	access_by_group_as_member: Option<String>,
	access_by_parent_group: Option<String>,
}

impl From<group::GroupOutData> for GroupOutData
{
	fn from(data: group::GroupOutData) -> Self
	{
		Self {
			group_id: data.group_id,
			parent_group_id: data.parent_group_id,
			rank: data.rank,
			key_update: data.key_update,
			created_time: data.created_time,
			joined_time: data.joined_time,
			keys: JsValue::from_serde(&data.keys).unwrap(),
			access_by_group_as_member: data.access_by_group_as_member,
			access_by_parent_group: data.access_by_parent_group,
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
		self.keys.clone()
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

	pub fn get_access_by_group_as_member(&self) -> Option<String>
	{
		self.access_by_group_as_member.clone()
	}

	pub fn get_access_by_parent_group(&self) -> Option<String>
	{
		self.access_by_parent_group.clone()
	}
}

#[wasm_bindgen]
pub struct GroupOutDataKeys
{
	private_key_id: String,
	key_data: String, //serde string
}

impl From<group::GroupOutDataKeys> for GroupOutDataKeys
{
	fn from(key: group::GroupOutDataKeys) -> Self
	{
		Self {
			private_key_id: key.private_key_id,
			key_data: key.key_data,
		}
	}
}

#[wasm_bindgen]
impl GroupOutDataKeys
{
	pub fn get_private_key_id(&self) -> String
	{
		self.private_key_id.clone()
	}

	pub fn get_key_data(&self) -> String
	{
		self.key_data.clone()
	}
}

/**
Keys after decrypt each key
*/
#[wasm_bindgen]
pub struct GroupKeyData
{
	private_group_key: String,
	public_group_key: String,
	group_key: String,
	time: u128,
	group_key_id: String,
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
			group_key_id: key.group_key_id,
		}
	}
}

#[wasm_bindgen]
impl GroupKeyData
{
	pub fn get_private_group_key(&self) -> String
	{
		self.private_group_key.clone()
	}

	pub fn get_public_group_key(&self) -> String
	{
		self.public_group_key.clone()
	}

	pub fn get_group_key(&self) -> String
	{
		self.group_key.clone()
	}

	pub fn get_time(&self) -> String
	{
		self.time.to_string()
	}

	pub fn get_group_key_id(&self) -> String
	{
		self.group_key_id.clone()
	}
}

#[wasm_bindgen]
pub struct KeyRotationInput
{
	encrypted_ephemeral_key_by_group_key_and_public_key: String,
	encrypted_group_key_by_ephemeral: String,
	ephemeral_alg: String,
	encrypted_eph_key_key_id: String, //the public key id which was used to encrypt the eph key on the server.
	previous_group_key_id: String,
	time: u128,
	new_group_key_id: String,
}

impl From<sentc_crypto_common::group::KeyRotationInput> for KeyRotationInput
{
	fn from(out: sentc_crypto_common::group::KeyRotationInput) -> Self
	{
		Self {
			encrypted_ephemeral_key_by_group_key_and_public_key: out.encrypted_ephemeral_key_by_group_key_and_public_key,
			encrypted_group_key_by_ephemeral: out.encrypted_group_key_by_ephemeral,
			ephemeral_alg: out.ephemeral_alg,
			encrypted_eph_key_key_id: out.encrypted_eph_key_key_id,
			previous_group_key_id: out.previous_group_key_id,
			time: out.time,
			new_group_key_id: out.new_group_key_id,
		}
	}
}

#[wasm_bindgen]
impl KeyRotationInput
{
	pub fn get_encrypted_ephemeral_key_by_group_key_and_public_key(&self) -> String
	{
		self.encrypted_ephemeral_key_by_group_key_and_public_key
			.clone()
	}

	pub fn get_encrypted_group_key_by_ephemeral(&self) -> String
	{
		self.encrypted_group_key_by_ephemeral.clone()
	}

	pub fn get_ephemeral_alg(&self) -> String
	{
		self.ephemeral_alg.clone()
	}

	pub fn get_encrypted_eph_key_key_id(&self) -> String
	{
		self.encrypted_eph_key_key_id.clone()
	}

	pub fn get_previous_group_key_id(&self) -> String
	{
		self.previous_group_key_id.clone()
	}

	pub fn get_new_group_key_id(&self) -> String
	{
		self.new_group_key_id.clone()
	}

	pub fn get_time(&self) -> String
	{
		self.time.to_string()
	}
}

#[wasm_bindgen]
pub struct GroupDataCheckUpdateServerOutput
{
	key_update: bool,
	rank: i32,
}

#[wasm_bindgen]
impl GroupDataCheckUpdateServerOutput
{
	pub fn get_key_update(&self) -> bool
	{
		self.key_update
	}

	pub fn get_rank(&self) -> i32
	{
		self.rank
	}
}

//__________________________________________________________________________________________________

/**
Create input for the server api.

Use this for group and child group. For child group use the public key of the parent group!
*/
#[wasm_bindgen]
pub fn group_prepare_create_group(creators_public_key: &str) -> Result<String, String>
{
	group::prepare_create(creators_public_key)
}

/**
Create a group with request.

Only the default values are send to the server, no extra data. If extra data is required, use prepare_create
*/
#[wasm_bindgen]
pub async fn group_create_group(
	base_url: String,
	auth_token: String,
	jwt: String,
	creators_public_key: String,
	group_as_member: String,
) -> Result<String, JsValue>
{
	let out = sentc_crypto_full::group::create(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		creators_public_key.as_str(),
		get_group_as_member(&group_as_member),
	)
	.await?;

	Ok(out)
}

#[wasm_bindgen]
pub async fn group_create_child_group(
	base_url: String,
	auth_token: String,
	jwt: String,
	parent_public_key: String,
	parent_id: String,
	admin_rank: i32,
	group_as_member: String,
) -> Result<String, JsValue>
{
	let out = sentc_crypto_full::group::create_child_group(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		parent_id.as_str(),
		admin_rank,
		parent_public_key.as_str(),
		get_group_as_member(&group_as_member),
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
	parent_public_key: String,
	group_as_member: String,
) -> Result<String, JsValue>
{
	let out = sentc_crypto_full::group::create_connected_group(
		base_url,
		&auth_token,
		&jwt,
		&connected_group_id,
		admin_rank,
		&parent_public_key,
		get_group_as_member(&group_as_member),
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
pub fn group_extract_group_data(server_output: &str) -> Result<GroupOutData, JsValue>
{
	let out = group::get_group_data(server_output)?;

	Ok(out.into())
}

/**
Get keys from pagination.

Call the group route with the last fetched key time and the last fetched key id. Get both from the key data.
*/
#[wasm_bindgen]
pub fn group_extract_group_keys(server_output: &str) -> Result<JsValue, JsValue>
{
	let out = group::get_group_keys_from_server_output(server_output)?;

	Ok(JsValue::from_serde(&out).unwrap())
}

#[wasm_bindgen]
pub async fn group_get_group_data(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	group_as_member: String,
) -> Result<GroupOutData, JsValue>
{
	let out = sentc_crypto_full::group::get_group(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		get_group_as_member(&group_as_member),
	)
	.await?;

	Ok(out.into())
}

#[wasm_bindgen]
pub async fn group_get_group_keys(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	last_fetched_time: String,
	last_fetched_key_id: String,
	group_as_member: String,
) -> Result<JsValue, JsValue>
{
	let out = sentc_crypto_full::group::get_group_keys(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		last_fetched_time.as_str(),
		last_fetched_key_id.as_str(),
		get_group_as_member(&group_as_member),
	)
	.await?;

	Ok(JsValue::from_serde(&out).unwrap())
}

#[wasm_bindgen]
pub async fn group_get_group_key(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	key_id: String,
	group_as_member: String,
) -> Result<GroupOutDataKeys, JsValue>
{
	let out = sentc_crypto_full::group::get_group_key(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		key_id.as_str(),
		get_group_as_member(&group_as_member),
	)
	.await?;

	Ok(out.into())
}

#[wasm_bindgen]
pub fn group_decrypt_key(private_key: &str, server_key_data: &str) -> Result<GroupKeyData, JsValue>
{
	let out = sentc_crypto_full::group::decrypt_key(server_key_data, private_key)?;

	Ok(out.into())
}

#[wasm_bindgen]
pub async fn group_get_member(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	last_fetched_time: String,
	last_fetched_id: String,
	group_as_member: String,
) -> Result<JsValue, JsValue>
{
	let out = sentc_crypto_full::group::get_member(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		last_fetched_time.as_str(),
		last_fetched_id.as_str(),
		get_group_as_member(&group_as_member),
	)
	.await?;

	Ok(JsValue::from_serde(&out).unwrap())
}

#[wasm_bindgen]
pub async fn group_get_group_updates(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	group_as_member: String,
) -> Result<GroupDataCheckUpdateServerOutput, JsValue>
{
	let out = sentc_crypto_full::group::get_group_updates(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		get_group_as_member(&group_as_member),
	)
	.await?;

	Ok(GroupDataCheckUpdateServerOutput {
		key_update: out.key_update,
		rank: out.rank,
	})
}

#[wasm_bindgen]
pub async fn group_get_groups_for_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	last_fetched_time: String,
	last_fetched_group_id: String,
) -> Result<JsValue, JsValue>
{
	let out = sentc_crypto_full::group::get_groups_for_user(
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
pub async fn group_get_sent_join_req_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	last_fetched_time: String,
	last_fetched_id: String,
) -> Result<JsValue, JsValue>
{
	let out = sentc_crypto_full::group::get_sent_join_req(
		base_url,
		&auth_token,
		&jwt,
		None,
		None,
		&last_fetched_time,
		&last_fetched_id,
		None,
	)
	.await?;

	Ok(JsValue::from_serde(&out).unwrap())
}

#[wasm_bindgen]
pub async fn group_delete_sent_join_req_user(base_url: String, auth_token: String, jwt: String, join_req_group_id: String) -> Result<(), JsValue>
{
	sentc_crypto_full::group::delete_sent_join_req(base_url, &auth_token, &jwt, None, None, &join_req_group_id, None).await?;

	Ok(())
}

//__________________________________________________________________________________________________
//invite

/**
Prepare all group keys for a new member.

Use the group keys from get group data or get group keys fn as string array
*/
#[wasm_bindgen]
pub fn group_prepare_keys_for_new_member(user_public_key: &str, group_keys: &str, key_count: i32, admin_rank: i32) -> Result<String, JsValue>
{
	group::check_make_invite_req(admin_rank)?;

	let key_session = key_count > 50;

	let input = group::prepare_group_keys_for_new_member(user_public_key, group_keys, key_session)?;

	Ok(input)
}

#[wasm_bindgen]
pub async fn group_invite_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	user_id: String,
	key_count: i32,
	admin_rank: i32,
	auto_invite: bool,
	group_invite: bool,
	user_public_key: String,
	group_keys: String,
	group_as_member: String,
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
		auto_invite,
		group_invite,
		user_public_key.as_str(),
		group_keys.as_str(),
		get_group_as_member(&group_as_member),
	)
	.await?;

	match out {
		Some(id) => Ok(id),
		None => Ok(String::from("")),
	}
}

#[wasm_bindgen]
pub async fn group_invite_user_session(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	auto_invite: bool,
	session_id: String,
	user_public_key: String,
	group_keys: String,
	group_as_member: String,
) -> Result<(), JsValue>
{
	sentc_crypto_full::group::invite_user_session(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		session_id.as_str(),
		auto_invite,
		user_public_key.as_str(),
		group_keys.as_str(),
		get_group_as_member(&group_as_member),
	)
	.await?;

	Ok(())
}

#[wasm_bindgen]
pub async fn group_get_invites_for_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	last_fetched_time: String,
	last_fetched_group_id: String,
	group_id: String,
	group_as_member: String,
) -> Result<JsValue, JsValue>
{
	let group_id = if group_id.is_empty() { None } else { Some(group_id.as_str()) };

	let out = sentc_crypto_full::group::get_invites_for_user(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		last_fetched_time.as_str(),
		last_fetched_group_id.as_str(),
		group_id,
		get_group_as_member(&group_as_member),
	)
	.await?;

	Ok(JsValue::from_serde(&out).unwrap())
}

#[wasm_bindgen]
pub async fn group_accept_invite(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	group_id: String,
	group_as_member: String,
) -> Result<(), JsValue>
{
	let group_id = if group_id.is_empty() { None } else { Some(group_id.as_str()) };

	sentc_crypto_full::group::accept_invite(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		group_id,
		get_group_as_member(&group_as_member),
	)
	.await?;

	Ok(())
}

#[wasm_bindgen]
pub async fn group_reject_invite(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	group_id: String,
	group_as_member: String,
) -> Result<(), JsValue>
{
	let group_id = if group_id.is_empty() { None } else { Some(group_id.as_str()) };

	sentc_crypto_full::group::reject_invite(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		group_id,
		get_group_as_member(&group_as_member),
	)
	.await?;

	Ok(())
}

//__________________________________________________________________________________________________
//join req

#[wasm_bindgen]
pub async fn group_join_req(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	group_id: String,
	group_as_member: String,
) -> Result<(), JsValue>
{
	let group_id = if group_id.is_empty() { None } else { Some(group_id.as_str()) };

	sentc_crypto_full::group::join_req(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		group_id,
		get_group_as_member(&group_as_member),
	)
	.await?;

	Ok(())
}

#[wasm_bindgen]
pub async fn group_get_join_reqs(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	admin_rank: i32,
	last_fetched_time: String,
	last_fetched_id: String,
	group_as_member: String,
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
		get_group_as_member(&group_as_member),
	)
	.await?;

	Ok(JsValue::from_serde(&out).unwrap())
}

#[wasm_bindgen]
pub async fn group_reject_join_req(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	admin_rank: i32,
	rejected_user_id: String,
	group_as_member: String,
) -> Result<(), JsValue>
{
	sentc_crypto_full::group::reject_join_req(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		admin_rank,
		rejected_user_id.as_str(),
		get_group_as_member(&group_as_member),
	)
	.await?;

	Ok(())
}

#[wasm_bindgen]
pub async fn group_accept_join_req(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	user_id: String,
	key_count: i32,
	admin_rank: i32,
	user_public_key: String,
	group_keys: String,
	group_as_member: String,
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
		get_group_as_member(&group_as_member),
	)
	.await?;

	match out {
		Some(id) => Ok(id),
		None => Ok(String::from("")),
	}
}

#[wasm_bindgen]
pub async fn group_join_user_session(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	session_id: String,
	user_public_key: String,
	group_keys: String,
	group_as_member: String,
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
		get_group_as_member(&group_as_member),
	)
	.await?;

	Ok(())
}

#[wasm_bindgen]
pub async fn group_stop_group_invites(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	admin_rank: i32,
	group_as_member: String,
) -> Result<(), JsValue>
{
	sentc_crypto_full::group::stop_group_invites(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		admin_rank,
		get_group_as_member(&group_as_member),
	)
	.await?;

	Ok(())
}

//__________________________________________________________________________________________________

#[wasm_bindgen]
pub async fn leave_group(base_url: String, auth_token: String, jwt: String, id: String, group_as_member: String) -> Result<(), JsValue>
{
	sentc_crypto_full::group::leave_group(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		get_group_as_member(&group_as_member),
	)
	.await?;

	Ok(())
}

//__________________________________________________________________________________________________
//key rotation

#[wasm_bindgen]
pub fn group_prepare_key_rotation(pre_group_key: &str, public_key: &str) -> Result<String, JsValue>
{
	let out = group::key_rotation(pre_group_key, public_key, false)?;

	Ok(out)
}

#[wasm_bindgen]
pub fn group_done_key_rotation(private_key: &str, public_key: &str, pre_group_key: &str, server_output: &str) -> Result<String, JsValue>
{
	let out = group::done_key_rotation(private_key, public_key, pre_group_key, server_output)?;

	Ok(out)
}

#[wasm_bindgen]
pub async fn group_key_rotation(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	public_key: String,
	pre_group_key: String,
	group_as_member: String,
) -> Result<String, JsValue>
{
	let out = sentc_crypto_full::group::key_rotation(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		public_key.as_str(),
		pre_group_key.as_str(),
		false,
		get_group_as_member(&group_as_member),
	)
	.await?;

	Ok(out)
}

/**
Get the keys for done key rotation.

Then call for each key rotation server output the finish_key_rotation fn
*/
#[wasm_bindgen]
pub async fn group_pre_done_key_rotation(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	group_as_member: String,
) -> Result<JsValue, JsValue>
{
	let out = sentc_crypto_full::group::prepare_done_key_rotation(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		false,
		get_group_as_member(&group_as_member),
	)
	.await?;

	Ok(JsValue::from_serde(&out).unwrap())
}

#[wasm_bindgen]
pub fn group_get_done_key_rotation_server_input(server_output: &str) -> Result<KeyRotationInput, JsValue>
{
	let out = group::get_done_key_rotation_server_input(server_output)?;

	Ok(out.into())
}

#[wasm_bindgen]
pub async fn group_finish_key_rotation(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	server_output: String,
	pre_group_key: String,
	public_key: String,
	private_key: String,
	group_as_member: String,
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
		false,
		get_group_as_member(&group_as_member),
	)
	.await?;

	Ok(())
}

//__________________________________________________________________________________________________
//group update fn

#[wasm_bindgen]
pub fn group_prepare_update_rank(user_id: &str, rank: i32, admin_rank: i32) -> Result<String, JsValue>
{
	let input = group::prepare_change_rank(user_id, rank, admin_rank)?;

	Ok(input)
}

#[wasm_bindgen]
pub async fn group_update_rank(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	user_id: String,
	rank: i32,
	admin_rank: i32,
	group_as_member: String,
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
		get_group_as_member(&group_as_member),
	)
	.await?;

	Ok(())
}

#[wasm_bindgen]
pub async fn group_kick_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	user_id: String,
	admin_rank: i32,
	group_as_member: String,
) -> Result<(), JsValue>
{
	sentc_crypto_full::group::kick_user(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		user_id.as_str(),
		admin_rank,
		get_group_as_member(&group_as_member),
	)
	.await?;

	Ok(())
}

#[wasm_bindgen]
pub async fn group_get_sent_join_req(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	admin_rank: i32,
	last_fetched_time: String,
	last_fetched_id: String,
	group_as_member: String,
) -> Result<JsValue, JsValue>
{
	let out = sentc_crypto_full::group::get_sent_join_req(
		base_url,
		&auth_token,
		&jwt,
		Some(&id),
		Some(admin_rank),
		&last_fetched_time,
		&last_fetched_id,
		get_group_as_member(&group_as_member),
	)
	.await?;

	Ok(JsValue::from_serde(&out).unwrap())
}

#[wasm_bindgen]
pub async fn group_delete_sent_join_req(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	admin_rank: i32,
	join_req_group_id: String,
	group_as_member: String,
) -> Result<(), JsValue>
{
	sentc_crypto_full::group::delete_sent_join_req(
		base_url,
		&auth_token,
		&jwt,
		Some(&id),
		Some(admin_rank),
		&join_req_group_id,
		get_group_as_member(&group_as_member),
	)
	.await?;

	Ok(())
}

//__________________________________________________________________________________________________

#[wasm_bindgen]
pub async fn group_delete_group(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	admin_rank: i32,
	group_as_member: String,
) -> Result<(), JsValue>
{
	sentc_crypto_full::group::delete_group(
		base_url,
		auth_token.as_str(),
		jwt.as_str(),
		id.as_str(),
		admin_rank,
		get_group_as_member(&group_as_member),
	)
	.await?;

	Ok(())
}

//__________________________________________________________________________________________________

#[wasm_bindgen]
pub struct GroupPublicKeyData
{
	public_key: String,
	public_key_id: String,
}

#[wasm_bindgen]
impl GroupPublicKeyData
{
	pub fn get_public_key(&self) -> String
	{
		self.public_key.clone()
	}

	pub fn get_public_key_id(&self) -> String
	{
		self.public_key_id.clone()
	}
}

#[wasm_bindgen]
pub async fn group_get_public_key_data(base_url: String, auth_token: String, id: String) -> Result<GroupPublicKeyData, JsValue>
{
	let (public_key, public_key_id) = sentc_crypto_full::group::get_public_key_data(base_url, &auth_token, &id).await?;

	Ok(GroupPublicKeyData {
		public_key,
		public_key_id,
	})
}

#[inline(never)]
fn get_group_as_member(group_as_member: &String) -> Option<&str>
{
	if group_as_member.is_empty() {
		None
	} else {
		Some(group_as_member.as_str())
	}
}
