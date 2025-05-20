use napi::bindgen_prelude::*;
use sentc_crypto::util_req_full;

use crate::user::KeyRotationGetOut;

#[napi(object)]
pub struct GroupKeyData
{
	pub private_group_key: String,
	pub public_group_key: String,
	pub exported_public_key: String,
	pub group_key: String,
	pub time: String,
	pub group_key_id: String,
}

impl From<sentc_crypto::entities::group::GroupKeyDataExport> for GroupKeyData
{
	fn from(data: sentc_crypto::entities::group::GroupKeyDataExport) -> Self
	{
		Self {
			private_group_key: data.private_group_key,
			public_group_key: data.public_group_key,
			exported_public_key: data.exported_public_key,
			group_key: data.group_key,
			time: data.time.to_string(),
			group_key_id: data.group_key_id,
		}
	}
}

#[napi(object)]
pub struct GroupOutDataKeys
{
	pub private_key_id: String,
	pub key_data: String, //serde string
	pub signed_by_user_id: Option<String>,
	pub signed_by_user_sign_key_id: Option<String>,
}

impl From<sentc_crypto::entities::group::GroupOutDataKeyExport> for GroupOutDataKeys
{
	fn from(key: sentc_crypto::entities::group::GroupOutDataKeyExport) -> Self
	{
		Self {
			private_key_id: key.private_key_id,
			key_data: key.key_data,
			signed_by_user_sign_key_id: key.signed_by_user_sign_key_id,
			signed_by_user_id: key.signed_by_user_id,
		}
	}
}

#[napi(object)]
pub struct GroupOutDataHmacKeys
{
	pub group_key_id: String,
	pub key_data: String, //serde string
}

impl From<sentc_crypto::entities::group::GroupOutDataHmacKeyExport> for GroupOutDataHmacKeys
{
	fn from(key: sentc_crypto::entities::group::GroupOutDataHmacKeyExport) -> Self
	{
		Self {
			group_key_id: key.group_key_id,
			key_data: key.key_data,
		}
	}
}

#[napi(object)]
pub struct GroupOutDataSortableKeys
{
	pub group_key_id: String,
	pub key_data: String, //serde string
}

impl From<sentc_crypto::entities::group::GroupOutDataSortableEyExport> for GroupOutDataSortableKeys
{
	fn from(key: sentc_crypto::entities::group::GroupOutDataSortableEyExport) -> Self
	{
		Self {
			group_key_id: key.group_key_id,
			key_data: key.key_data,
		}
	}
}

#[napi(object)]
pub struct GroupOutData
{
	pub group_id: String,
	pub parent_group_id: Option<String>,
	pub rank: i32,
	pub key_update: bool,
	pub created_time: String,
	pub joined_time: String,
	pub keys: Vec<GroupOutDataKeys>,
	pub hmac_keys: Vec<GroupOutDataHmacKeys>,
	pub sortable_keys: Vec<GroupOutDataSortableKeys>,
	pub access_by_group_as_member: Option<String>,
	pub access_by_parent_group: Option<String>,
	pub is_connected_group: bool,
}

impl From<sentc_crypto::entities::group::GroupOutDataExport> for GroupOutData
{
	fn from(data: sentc_crypto::entities::group::GroupOutDataExport) -> Self
	{
		Self {
			group_id: data.group_id,
			parent_group_id: data.parent_group_id,
			rank: data.rank,
			key_update: data.key_update,
			created_time: data.created_time.to_string(),
			joined_time: data.joined_time.to_string(),
			keys: data.keys.into_iter().map(|key| key.into()).collect(),
			hmac_keys: data
				.hmac_keys
				.into_iter()
				.map(|hmac_key| hmac_key.into())
				.collect(),
			sortable_keys: data
				.sortable_keys
				.into_iter()
				.map(|hmac_key| hmac_key.into())
				.collect(),
			access_by_group_as_member: data.access_by_group_as_member,
			access_by_parent_group: data.access_by_parent_group,
			is_connected_group: data.is_connected_group,
		}
	}
}

#[napi(object)]
pub struct GroupInviteReqList
{
	pub group_id: String,
	pub time: String,
}

impl From<sentc_crypto_common::group::GroupInviteReqList> for GroupInviteReqList
{
	fn from(list: sentc_crypto_common::group::GroupInviteReqList) -> Self
	{
		Self {
			group_id: list.group_id,
			time: list.time.to_string(),
		}
	}
}

#[napi(object)]
pub struct KeyRotationInput
{
	pub error: Option<String>,
	pub encrypted_ephemeral_key_by_group_key_and_public_key: String,
	pub encrypted_group_key_by_ephemeral: String,
	pub ephemeral_alg: String,
	pub encrypted_eph_key_key_id: String, //the public key id which was used to encrypt the eph key on the server.
	pub previous_group_key_id: String,
	pub time: String,
	pub new_group_key_id: String,
}

impl From<sentc_crypto_common::group::KeyRotationInput> for KeyRotationInput
{
	fn from(out: sentc_crypto_common::group::KeyRotationInput) -> Self
	{
		Self {
			error: out.error,
			encrypted_ephemeral_key_by_group_key_and_public_key: out.encrypted_ephemeral_key_by_group_key_and_public_key,
			encrypted_group_key_by_ephemeral: out.encrypted_group_key_by_ephemeral,
			ephemeral_alg: out.ephemeral_alg,
			encrypted_eph_key_key_id: out.encrypted_eph_key_key_id,
			previous_group_key_id: out.previous_group_key_id,
			time: out.time.to_string(),
			new_group_key_id: out.new_group_key_id,
		}
	}
}

//__________________________________________________________________________________________________

/**
Create input for the server api.

Use this for a group and child group. For child group use the public key of the parent group!
 */
#[napi]
pub fn group_prepare_create_group(creators_public_key: String, sign_key: Option<String>, starter: String) -> Result<String>
{
	sentc_crypto::group::prepare_create(&creators_public_key, sign_key.as_deref(), starter).map_err(Error::from_reason)
}

/**
Create a group with a request.

Only the default values are sent to the server, no extra data. If extra data is required, use prepare_create
 */
#[napi]
pub async fn group_create_group(
	base_url: String,
	auth_token: String,
	jwt: String,
	creators_public_key: String,
	group_as_member: Option<String>,
	sign_key: Option<String>,
	starter: String,
) -> Result<String>
{
	util_req_full::group::create(
		base_url,
		&auth_token,
		&jwt,
		&creators_public_key,
		group_as_member.as_deref(),
		sign_key.as_deref(),
		starter,
	)
	.await
	.map_err(Error::from_reason)
}

#[napi]
pub async fn group_create_child_group(
	base_url: String,
	auth_token: String,
	jwt: String,
	parent_public_key: String,
	parent_id: String,
	admin_rank: i32,
	group_as_member: Option<String>,
	sign_key: Option<String>,
	starter: String,
) -> Result<String>
{
	util_req_full::group::create_child_group(
		base_url,
		&auth_token,
		&jwt,
		&parent_id,
		admin_rank,
		&parent_public_key,
		group_as_member.as_deref(),
		sign_key.as_deref(),
		starter,
	)
	.await
	.map_err(Error::from_reason)
}

#[napi]
pub async fn group_create_connected_group(
	base_url: String,
	auth_token: String,
	jwt: String,
	connected_group_id: String,
	admin_rank: i32,
	parent_public_key: String,
	group_as_member: Option<String>,
	sign_key: Option<String>,
	starter: String,
) -> Result<String>
{
	util_req_full::group::create_connected_group(
		base_url,
		&auth_token,
		&jwt,
		&connected_group_id,
		admin_rank,
		&parent_public_key,
		group_as_member.as_deref(),
		sign_key.as_deref(),
		starter,
	)
	.await
	.map_err(Error::from_reason)
}

//__________________________________________________________________________________________________

/**
Get the group data without a request.

Use the parent group private key when fetching child group data.
 */
#[napi]
pub fn group_extract_group_data(server_output: String) -> Result<GroupOutData>
{
	let out = sentc_crypto::group::get_group_data(&server_output).map_err(Error::from_reason)?;

	Ok(out.into())
}

/**
Get keys from pagination.

Call the group route with the last fetched key time and the last fetched key id. Get both from the key data.
 */
#[napi]
pub fn group_extract_group_keys(server_output: String) -> Result<Vec<GroupOutDataKeys>>
{
	let out = sentc_crypto::group::get_group_keys_from_server_output(&server_output).map_err(Error::from_reason)?;

	Ok(out.into_iter().map(|key| key.into()).collect())
}

#[napi]
pub async fn group_get_group_data(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	group_as_member: Option<String>,
) -> Result<GroupOutData>
{
	let out = util_req_full::group::get_group(base_url, &auth_token, &jwt, &id, group_as_member.as_deref())
		.await
		.map_err(Error::from_reason)?;

	Ok(out.into())
}

#[napi]
pub async fn group_get_group_keys(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	last_fetched_time: String,
	last_fetched_key_id: String,
	group_as_member: Option<String>,
) -> Result<Vec<GroupOutDataKeys>>
{
	let out = util_req_full::group::get_group_keys(
		base_url,
		&auth_token,
		&jwt,
		&id,
		&last_fetched_time,
		&last_fetched_key_id,
		group_as_member.as_deref(),
	)
	.await
	.map_err(Error::from_reason)?;

	Ok(out.into_iter().map(|key| key.into()).collect())
}

#[napi]
pub async fn group_get_group_key(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	key_id: String,
	group_as_member: Option<String>,
) -> Result<GroupOutDataKeys>
{
	let out = util_req_full::group::get_group_key(base_url, &auth_token, &jwt, &id, &key_id, group_as_member.as_deref())
		.await
		.map_err(Error::from_reason)?;

	Ok(out.into())
}

#[napi]
pub fn group_decrypt_key(private_key: String, server_key_data: String, verify_key: Option<String>) -> Result<GroupKeyData>
{
	let out = sentc_crypto::group::decrypt_group_keys(&private_key, &server_key_data, verify_key.as_deref()).map_err(Error::from_reason)?;

	Ok(out.into())
}

#[napi]
pub fn group_decrypt_hmac_key(group_key: String, server_key_data: String) -> Result<String>
{
	sentc_crypto::group::decrypt_group_hmac_key(&group_key, &server_key_data).map_err(Error::from_reason)
}

#[napi]
pub fn group_decrypt_sortable_key(group_key: String, server_key_data: String) -> Result<String>
{
	sentc_crypto::group::decrypt_group_sortable_key(&group_key, &server_key_data).map_err(Error::from_reason)
}

//__________________________________________________________________________________________________

#[napi(object)]
pub struct GroupUserListItem
{
	pub user_id: String,
	pub rank: i32,
	pub joined_time: String,
	pub user_type: i32,
}

impl From<sentc_crypto_common::group::GroupUserListItem> for GroupUserListItem
{
	fn from(item: sentc_crypto_common::group::GroupUserListItem) -> Self
	{
		Self {
			user_id: item.user_id,
			rank: item.rank,
			joined_time: item.joined_time.to_string(),
			user_type: item.user_type,
		}
	}
}

#[napi(object)]
pub struct GroupDataCheckUpdateServerOutput
{
	pub key_update: bool,
	pub rank: i32,
}

#[napi(object)]
pub struct GroupChildrenList
{
	pub group_id: String,
	pub time: String,
	pub parent: Option<String>,
}

impl From<sentc_crypto_common::group::GroupChildrenList> for GroupChildrenList
{
	fn from(i: sentc_crypto_common::group::GroupChildrenList) -> Self
	{
		Self {
			group_id: i.group_id,
			time: i.time.to_string(),
			parent: i.parent,
		}
	}
}

#[napi(object)]
pub struct ListGroups
{
	pub group_id: String,
	pub time: String,
	pub joined_time: String,
	pub rank: i32,
	pub parent: Option<String>,
}

impl From<sentc_crypto_common::group::ListGroups> for ListGroups
{
	fn from(item: sentc_crypto_common::group::ListGroups) -> Self
	{
		Self {
			group_id: item.group_id,
			time: item.time.to_string(),
			joined_time: item.joined_time.to_string(),
			rank: item.rank,
			parent: item.parent,
		}
	}
}

#[napi]
pub async fn group_get_member(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	last_fetched_time: String,
	last_fetched_id: String,
	group_as_member: Option<String>,
) -> Result<Vec<GroupUserListItem>>
{
	let out = util_req_full::group::get_member(
		base_url,
		&auth_token,
		&jwt,
		&id,
		&last_fetched_time,
		&last_fetched_id,
		group_as_member.as_deref(),
	)
	.await
	.map_err(Error::from_reason)?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

#[napi]
pub async fn group_get_group_updates(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	group_as_member: Option<String>,
) -> Result<GroupDataCheckUpdateServerOutput>
{
	let out = util_req_full::group::get_group_updates(base_url, &auth_token, &jwt, &id, group_as_member.as_deref())
		.await
		.map_err(Error::from_reason)?;

	Ok(GroupDataCheckUpdateServerOutput {
		key_update: out.key_update,
		rank: out.rank,
	})
}

#[napi]
pub async fn group_get_all_first_level_children(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	last_fetched_time: String,
	last_fetched_group_id: String,
	group_as_member: Option<String>,
) -> Result<Vec<GroupChildrenList>>
{
	let out = util_req_full::group::get_all_first_level_children(
		base_url,
		&auth_token,
		&jwt,
		&id,
		&last_fetched_time,
		&last_fetched_group_id,
		group_as_member.as_deref(),
	)
	.await
	.map_err(Error::from_reason)?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

#[napi]
pub async fn group_get_groups_for_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	last_fetched_time: String,
	last_fetched_group_id: String,
	group_id: Option<String>,
) -> Result<Vec<ListGroups>>
{
	let out = util_req_full::group::get_groups_for_user(
		base_url,
		&auth_token,
		&jwt,
		&last_fetched_time,
		&last_fetched_group_id,
		group_id.as_deref(),
	)
	.await
	.map_err(Error::from_reason)?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

//__________________________________________________________________________________________________
//invite

/**
Prepare all group keys for a new member.

Use the group keys from get group data or get group keys fn as a string array
 */
#[napi]
pub fn group_prepare_keys_for_new_member(
	user_public_key: String,
	group_keys: String,
	key_count: i32,
	rank: Option<i32>,
	admin_rank: i32,
) -> Result<String>
{
	sentc_crypto::group::check_make_invite_req(admin_rank).map_err(Error::from_reason)?;

	let key_session = key_count > 50;

	sentc_crypto::group::prepare_group_keys_for_new_member(&user_public_key, &group_keys, key_session, rank).map_err(Error::from_reason)
}

#[napi]
pub async fn group_invite_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	user_id: String,
	key_count: i32,
	rank: Option<i32>,
	admin_rank: i32,
	auto_invite: bool,
	group_invite: bool,
	re_invite: bool,
	user_public_key: String,
	group_keys: String,
	group_as_member: Option<String>,
) -> Result<String>
{
	let out = util_req_full::group::invite_user(
		base_url,
		&auth_token,
		&jwt,
		&id,
		&user_id,
		key_count,
		rank,
		admin_rank,
		auto_invite,
		group_invite,
		re_invite,
		&user_public_key,
		&group_keys,
		group_as_member.as_deref(),
	)
	.await
	.map_err(Error::from_reason)?;

	Ok(out.unwrap_or_default())
}

#[napi]
pub async fn group_invite_user_session(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	auto_invite: bool,
	session_id: String,
	user_public_key: String,
	group_keys: String,
	group_as_member: Option<String>,
) -> Result<()>
{
	util_req_full::group::invite_user_session(
		base_url,
		&auth_token,
		&jwt,
		&id,
		&session_id,
		auto_invite,
		&user_public_key,
		&group_keys,
		group_as_member.as_deref(),
	)
	.await
	.map_err(Error::from_reason)
}

#[napi]
pub async fn group_get_invites_for_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	last_fetched_time: String,
	last_fetched_group_id: String,
	group_id: Option<String>,
	group_as_member: Option<String>,
) -> Result<Vec<GroupInviteReqList>>
{
	let out = util_req_full::group::get_invites_for_user(
		base_url,
		&auth_token,
		&jwt,
		&last_fetched_time,
		&last_fetched_group_id,
		group_id.as_deref(),
		group_as_member.as_deref(),
	)
	.await
	.map_err(Error::from_reason)?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

#[napi]
pub async fn group_accept_invite(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	group_id: Option<String>,
	group_as_member: Option<String>,
) -> Result<()>
{
	util_req_full::group::accept_invite(
		base_url,
		&auth_token,
		&jwt,
		&id,
		group_id.as_deref(),
		group_as_member.as_deref(),
	)
	.await
	.map_err(Error::from_reason)
}

#[napi]
pub async fn group_reject_invite(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	group_id: Option<String>,
	group_as_member: Option<String>,
) -> Result<()>
{
	util_req_full::group::reject_invite(
		base_url,
		&auth_token,
		&jwt,
		&id,
		group_id.as_deref(),
		group_as_member.as_deref(),
	)
	.await
	.map_err(Error::from_reason)
}

//__________________________________________________________________________________________________
//join req

#[napi(object)]
pub struct GroupJoinReqList
{
	pub user_id: String,
	pub time: String,
	pub user_type: i32,
}

impl From<sentc_crypto_common::group::GroupJoinReqList> for GroupJoinReqList
{
	fn from(list: sentc_crypto_common::group::GroupJoinReqList) -> Self
	{
		Self {
			user_id: list.user_id,
			time: list.time.to_string(),
			user_type: list.user_type,
		}
	}
}

#[napi]
pub async fn group_get_sent_join_req_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	last_fetched_time: String,
	last_fetched_group_id: String,
	group_as_member: Option<String>,
) -> Result<Vec<GroupInviteReqList>>
{
	let out = util_req_full::group::get_sent_join_req(
		base_url,
		&auth_token,
		&jwt,
		None,
		None,
		&last_fetched_time,
		&last_fetched_group_id,
		group_as_member.as_deref(),
	)
	.await
	.map_err(Error::from_reason)?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

#[napi]
pub async fn group_get_sent_join_req(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	admin_rank: i32,
	last_fetched_time: String,
	last_fetched_group_id: String,
	group_as_member: Option<String>,
) -> Result<Vec<GroupInviteReqList>>
{
	let out = util_req_full::group::get_sent_join_req(
		base_url,
		&auth_token,
		&jwt,
		Some(&id),
		Some(admin_rank),
		&last_fetched_time,
		&last_fetched_group_id,
		group_as_member.as_deref(),
	)
	.await
	.map_err(Error::from_reason)?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

#[napi]
pub async fn group_delete_sent_join_req_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	join_req_group_id: String,
	group_as_member: Option<String>,
) -> Result<()>
{
	util_req_full::group::delete_sent_join_req(
		base_url,
		&auth_token,
		&jwt,
		None,
		None,
		&join_req_group_id,
		group_as_member.as_deref(),
	)
	.await
	.map_err(Error::from_reason)
}

#[napi]
pub async fn group_delete_sent_join_req(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	admin_rank: i32,
	join_req_group_id: String,
	group_as_member: Option<String>,
) -> Result<()>
{
	util_req_full::group::delete_sent_join_req(
		base_url,
		&auth_token,
		&jwt,
		Some(&id),
		Some(admin_rank),
		&join_req_group_id,
		group_as_member.as_deref(),
	)
	.await
	.map_err(Error::from_reason)
}

#[napi]
pub async fn group_join_req(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	group_id: String,
	group_as_member: Option<String>,
) -> Result<()>
{
	let group_id = if group_id.is_empty() { None } else { Some(group_id.as_str()) };

	util_req_full::group::join_req(base_url, &auth_token, &jwt, &id, group_id, group_as_member.as_deref())
		.await
		.map_err(Error::from_reason)
}

#[napi]
pub async fn group_get_join_reqs(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	admin_rank: i32,
	last_fetched_time: String,
	last_fetched_id: String,
	group_as_member: Option<String>,
) -> Result<Vec<GroupJoinReqList>>
{
	let out = util_req_full::group::get_join_reqs(
		base_url,
		&auth_token,
		&jwt,
		&id,
		admin_rank,
		&last_fetched_time,
		&last_fetched_id,
		group_as_member.as_deref(),
	)
	.await
	.map_err(Error::from_reason)?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

#[napi]
pub async fn group_reject_join_req(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	admin_rank: i32,
	rejected_user_id: String,
	group_as_member: Option<String>,
) -> Result<()>
{
	util_req_full::group::reject_join_req(
		base_url,
		&auth_token,
		&jwt,
		&id,
		admin_rank,
		&rejected_user_id,
		group_as_member.as_deref(),
	)
	.await
	.map_err(Error::from_reason)
}

#[napi]
pub async fn group_accept_join_req(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	user_id: String,
	key_count: i32,
	rank: Option<i32>,
	admin_rank: i32,
	user_public_key: String,
	group_keys: String,
	group_as_member: Option<String>,
) -> Result<String>
{
	let out = util_req_full::group::accept_join_req(
		base_url,
		&auth_token,
		&jwt,
		&id,
		&user_id,
		key_count,
		rank,
		admin_rank,
		&user_public_key,
		&group_keys,
		group_as_member.as_deref(),
	)
	.await
	.map_err(Error::from_reason)?;

	Ok(out.unwrap_or_default())
}

#[napi]
pub async fn group_join_user_session(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	session_id: String,
	user_public_key: String,
	group_keys: String,
	group_as_member: Option<String>,
) -> Result<()>
{
	util_req_full::group::join_user_session(
		base_url,
		&auth_token,
		&jwt,
		&id,
		&session_id,
		&user_public_key,
		&group_keys,
		group_as_member.as_deref(),
	)
	.await
	.map_err(Error::from_reason)
}

#[napi]
pub async fn group_stop_group_invites(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	admin_rank: i32,
	group_as_member: Option<String>,
) -> Result<()>
{
	util_req_full::group::stop_group_invites(
		base_url,
		&auth_token,
		&jwt,
		&id,
		admin_rank,
		group_as_member.as_deref(),
	)
	.await
	.map_err(Error::from_reason)
}

//__________________________________________________________________________________________________

#[napi]
pub async fn leave_group(base_url: String, auth_token: String, jwt: String, id: String, group_as_member: Option<String>) -> Result<()>
{
	util_req_full::group::leave_group(base_url, &auth_token, &jwt, &id, group_as_member.as_deref())
		.await
		.map_err(Error::from_reason)
}

//__________________________________________________________________________________________________
//key rotation

#[napi]
pub fn group_prepare_key_rotation(pre_group_key: String, public_key: String, sign_key: Option<String>, starter: String) -> Result<String>
{
	sentc_crypto::group::key_rotation(&pre_group_key, &public_key, false, sign_key.as_deref(), starter).map_err(Error::from_reason)
}

#[napi]
pub fn group_done_key_rotation(private_key: String, public_key: String, pre_group_key: String, server_output: String) -> Result<String>
{
	sentc_crypto::group::done_key_rotation(&private_key, &public_key, &pre_group_key, &server_output).map_err(Error::from_reason)
}

#[napi]
pub async fn group_key_rotation(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	public_key: String,
	pre_group_key: String,
	sign_key: Option<String>,
	starter: String,
	group_as_member: Option<String>,
) -> Result<String>
{
	util_req_full::group::key_rotation(
		base_url,
		&auth_token,
		&jwt,
		&id,
		&public_key,
		&pre_group_key,
		false,
		sign_key.as_deref(),
		starter,
		group_as_member.as_deref(),
	)
	.await
	.map_err(Error::from_reason)
}

#[napi]
pub async fn group_pre_done_key_rotation(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	group_as_member: Option<String>,
) -> Result<Vec<KeyRotationGetOut>>
{
	let out = util_req_full::group::prepare_done_key_rotation(base_url, &auth_token, &jwt, &id, false, group_as_member.as_deref())
		.await
		.map_err(Error::from_reason)?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

#[napi]
pub fn group_get_done_key_rotation_server_input(server_output: String) -> Result<KeyRotationInput>
{
	let out = sentc_crypto::group::get_done_key_rotation_server_input(&server_output).map_err(Error::from_reason)?;

	Ok(out.into())
}

#[napi]
pub async fn group_finish_key_rotation(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	server_output: String,
	pre_group_key: String,
	public_key: String,
	private_key: String,
	group_as_member: Option<String>,
) -> Result<()>
{
	util_req_full::group::done_key_rotation(
		base_url,
		&auth_token,
		&jwt,
		&id,
		&server_output,
		&pre_group_key,
		&public_key,
		&private_key,
		false,
		group_as_member.as_deref(),
	)
	.await
	.map_err(Error::from_reason)
}

//__________________________________________________________________________________________________
//group update fn

#[napi]
pub fn group_prepare_update_rank(user_id: String, rank: i32, admin_rank: i32) -> Result<String>
{
	sentc_crypto::group::prepare_change_rank(&user_id, rank, admin_rank).map_err(Error::from_reason)
}

#[napi]
pub async fn group_update_rank(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	user_id: String,
	rank: i32,
	admin_rank: i32,
	group_as_member: Option<String>,
) -> Result<()>
{
	util_req_full::group::update_rank(
		base_url,
		&auth_token,
		&jwt,
		&id,
		&user_id,
		rank,
		admin_rank,
		group_as_member.as_deref(),
	)
	.await
	.map_err(Error::from_reason)
}

#[napi]
pub async fn group_kick_user(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	user_id: String,
	admin_rank: i32,
	group_as_member: Option<String>,
) -> Result<()>
{
	util_req_full::group::kick_user(
		base_url,
		&auth_token,
		&jwt,
		&id,
		&user_id,
		admin_rank,
		group_as_member.as_deref(),
	)
	.await
	.map_err(Error::from_reason)
}

//__________________________________________________________________________________________________

#[napi]
pub async fn group_delete_group(
	base_url: String,
	auth_token: String,
	jwt: String,
	id: String,
	admin_rank: i32,
	group_as_member: Option<String>,
) -> Result<()>
{
	util_req_full::group::delete_group(
		base_url,
		&auth_token,
		&jwt,
		&id,
		admin_rank,
		group_as_member.as_deref(),
	)
	.await
	.map_err(Error::from_reason)
}

#[napi(object)]
pub struct GroupPublicKeyData
{
	pub public_key: String,
	pub public_key_id: String,
}

#[napi]
pub async fn group_get_public_key_data(base_url: String, auth_token: String, id: String) -> Result<GroupPublicKeyData>
{
	let (public_key, public_key_id) = util_req_full::group::get_public_key_data(base_url, &auth_token, &id)
		.await
		.map_err(Error::from_reason)?;

	Ok(GroupPublicKeyData {
		public_key,
		public_key_id,
	})
}
