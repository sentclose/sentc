use sentc_crypto::util_req_full;

use crate::user::KeyRotationGetOut;
use crate::SentcError;

#[derive(uniffi::Record)]
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

#[derive(uniffi::Record)]
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

#[derive(uniffi::Record)]
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

#[derive(uniffi::Record)]
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

#[derive(uniffi::Record)]
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

#[derive(uniffi::Record)]
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

#[derive(uniffi::Record)]
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

#[uniffi::export]
pub fn group_prepare_create_group(creators_public_key: &str, sign_key: Option<String>, starter: String) -> Result<String, SentcError>
{
	Ok(sentc_crypto::group::prepare_create(
		creators_public_key,
		sign_key.as_deref(),
		starter,
	)?)
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_create_group(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	creators_public_key: &str,
	group_as_member: Option<String>,
	sign_key: Option<String>,
	starter: String,
) -> Result<String, SentcError>
{
	Ok(util_req_full::group::create(
		base_url,
		auth_token,
		jwt,
		creators_public_key,
		group_as_member.as_deref(),
		sign_key.as_deref(),
		starter,
	)
	.await?)
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_create_child_group(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	parent_public_key: &str,
	parent_id: &str,
	admin_rank: i32,
	group_as_member: Option<String>,
	sign_key: Option<String>,
	starter: String,
) -> Result<String, SentcError>
{
	Ok(util_req_full::group::create_child_group(
		base_url,
		auth_token,
		jwt,
		parent_id,
		admin_rank,
		parent_public_key,
		group_as_member.as_deref(),
		sign_key.as_deref(),
		starter,
	)
	.await?)
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_create_connected_group(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	connected_group_id: &str,
	admin_rank: i32,
	parent_public_key: &str,
	group_as_member: Option<String>,
	sign_key: Option<String>,
	starter: String,
) -> Result<String, SentcError>
{
	Ok(util_req_full::group::create_connected_group(
		base_url,
		auth_token,
		jwt,
		connected_group_id,
		admin_rank,
		parent_public_key,
		group_as_member.as_deref(),
		sign_key.as_deref(),
		starter,
	)
	.await?)
}

//__________________________________________________________________________________________________

#[uniffi::export]
pub fn group_extract_group_data(server_output: &str) -> Result<GroupOutData, SentcError>
{
	let out = sentc_crypto::group::get_group_data(server_output)?;

	Ok(out.into())
}

#[uniffi::export]
pub fn group_extract_group_keys(server_output: &str) -> Result<Vec<GroupOutDataKeys>, SentcError>
{
	let out = sentc_crypto::group::get_group_keys_from_server_output(server_output)?;

	Ok(out.into_iter().map(|key| key.into()).collect())
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_get_group_data(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	group_as_member: Option<String>,
) -> Result<GroupOutData, SentcError>
{
	let out = util_req_full::group::get_group(base_url, auth_token, jwt, id, group_as_member.as_deref()).await?;

	Ok(out.into())
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_get_group_keys(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	last_fetched_time: &str,
	last_fetched_key_id: &str,
	group_as_member: Option<String>,
) -> Result<Vec<GroupOutDataKeys>, SentcError>
{
	let out = util_req_full::group::get_group_keys(
		base_url,
		auth_token,
		jwt,
		id,
		last_fetched_time,
		last_fetched_key_id,
		group_as_member.as_deref(),
	)
	.await?;

	Ok(out.into_iter().map(|key| key.into()).collect())
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_get_group_key(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	key_id: &str,
	group_as_member: Option<String>,
) -> Result<GroupOutDataKeys, SentcError>
{
	let out = util_req_full::group::get_group_key(base_url, auth_token, jwt, id, key_id, group_as_member.as_deref()).await?;

	Ok(out.into())
}

#[uniffi::export]
pub fn group_decrypt_key(private_key: &str, server_key_data: &str, verify_key: Option<String>) -> Result<GroupKeyData, SentcError>
{
	let out = sentc_crypto::group::decrypt_group_keys(private_key, server_key_data, verify_key.as_deref())?;

	Ok(out.into())
}

#[uniffi::export]
pub fn group_decrypt_hmac_key(group_key: &str, server_key_data: &str) -> Result<String, SentcError>
{
	Ok(sentc_crypto::group::decrypt_group_hmac_key(
		group_key,
		server_key_data,
	)?)
}

#[uniffi::export]
pub fn group_decrypt_sortable_key(group_key: &str, server_key_data: &str) -> Result<String, SentcError>
{
	Ok(sentc_crypto::group::decrypt_group_sortable_key(
		group_key,
		server_key_data,
	)?)
}

//__________________________________________________________________________________________________

#[derive(uniffi::Record)]
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

#[derive(uniffi::Record)]
pub struct GroupDataCheckUpdateServerOutput
{
	pub key_update: bool,
	pub rank: i32,
}

#[derive(uniffi::Record)]
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

#[derive(uniffi::Record)]
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

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_get_member(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	last_fetched_time: &str,
	last_fetched_id: &str,
	group_as_member: Option<String>,
) -> Result<Vec<GroupUserListItem>, SentcError>
{
	let out = util_req_full::group::get_member(
		base_url,
		auth_token,
		jwt,
		id,
		last_fetched_time,
		last_fetched_id,
		group_as_member.as_deref(),
	)
	.await?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_get_group_updates(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	group_as_member: Option<String>,
) -> Result<GroupDataCheckUpdateServerOutput, SentcError>
{
	let out = util_req_full::group::get_group_updates(base_url, auth_token, jwt, id, group_as_member.as_deref()).await?;

	Ok(GroupDataCheckUpdateServerOutput {
		key_update: out.key_update,
		rank: out.rank,
	})
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_get_all_first_level_children(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	last_fetched_time: &str,
	last_fetched_group_id: &str,
	group_as_member: Option<String>,
) -> Result<Vec<GroupChildrenList>, SentcError>
{
	let out = util_req_full::group::get_all_first_level_children(
		base_url,
		auth_token,
		jwt,
		id,
		last_fetched_time,
		last_fetched_group_id,
		group_as_member.as_deref(),
	)
	.await?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_get_groups_for_user(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	last_fetched_time: &str,
	last_fetched_group_id: &str,
	group_id: Option<String>,
) -> Result<Vec<ListGroups>, SentcError>
{
	let out = util_req_full::group::get_groups_for_user(
		base_url,
		auth_token,
		jwt,
		last_fetched_time,
		last_fetched_group_id,
		group_id.as_deref(),
	)
	.await?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

//__________________________________________________________________________________________________
//invite

#[uniffi::export]
pub fn group_prepare_keys_for_new_member(
	user_public_key: &str,
	group_keys: &str,
	key_count: i32,
	rank: Option<i32>,
	admin_rank: i32,
) -> Result<String, SentcError>
{
	sentc_crypto::group::check_make_invite_req(admin_rank)?;

	let key_session = key_count > 50;

	Ok(sentc_crypto::group::prepare_group_keys_for_new_member(
		user_public_key,
		group_keys,
		key_session,
		rank,
	)?)
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_invite_user(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	user_id: &str,
	key_count: i32,
	rank: Option<i32>,
	admin_rank: i32,
	auto_invite: bool,
	group_invite: bool,
	re_invite: bool,
	user_public_key: &str,
	group_keys: &str,
	group_as_member: Option<String>,
) -> Result<String, SentcError>
{
	let out = util_req_full::group::invite_user(
		base_url,
		auth_token,
		jwt,
		id,
		user_id,
		key_count,
		rank,
		admin_rank,
		auto_invite,
		group_invite,
		re_invite,
		user_public_key,
		group_keys,
		group_as_member.as_deref(),
	)
	.await?;

	Ok(out.unwrap_or_default())
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_invite_user_session(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	auto_invite: bool,
	session_id: &str,
	user_public_key: &str,
	group_keys: &str,
	group_as_member: Option<String>,
) -> Result<(), SentcError>
{
	Ok(util_req_full::group::invite_user_session(
		base_url,
		auth_token,
		jwt,
		id,
		session_id,
		auto_invite,
		user_public_key,
		group_keys,
		group_as_member.as_deref(),
	)
	.await?)
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_get_invites_for_user(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	last_fetched_time: &str,
	last_fetched_group_id: &str,
	group_id: Option<String>,
	group_as_member: Option<String>,
) -> Result<Vec<GroupInviteReqList>, SentcError>
{
	let out = util_req_full::group::get_invites_for_user(
		base_url,
		auth_token,
		jwt,
		last_fetched_time,
		last_fetched_group_id,
		group_id.as_deref(),
		group_as_member.as_deref(),
	)
	.await?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_accept_invite(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	group_id: Option<String>,
	group_as_member: Option<String>,
) -> Result<(), SentcError>
{
	Ok(util_req_full::group::accept_invite(
		base_url,
		auth_token,
		jwt,
		id,
		group_id.as_deref(),
		group_as_member.as_deref(),
	)
	.await?)
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_reject_invite(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	group_id: Option<String>,
	group_as_member: Option<String>,
) -> Result<(), SentcError>
{
	Ok(util_req_full::group::reject_invite(
		base_url,
		auth_token,
		jwt,
		id,
		group_id.as_deref(),
		group_as_member.as_deref(),
	)
	.await?)
}

//__________________________________________________________________________________________________
//join req

#[derive(uniffi::Record)]
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

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_get_sent_join_req_user(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	last_fetched_time: &str,
	last_fetched_group_id: &str,
	group_as_member: Option<String>,
) -> Result<Vec<GroupInviteReqList>, SentcError>
{
	let out = util_req_full::group::get_sent_join_req(
		base_url,
		auth_token,
		jwt,
		None,
		None,
		last_fetched_time,
		last_fetched_group_id,
		group_as_member.as_deref(),
	)
	.await?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_get_sent_join_req(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	admin_rank: i32,
	last_fetched_time: &str,
	last_fetched_group_id: &str,
	group_as_member: Option<String>,
) -> Result<Vec<GroupInviteReqList>, SentcError>
{
	let out = util_req_full::group::get_sent_join_req(
		base_url,
		auth_token,
		jwt,
		Some(id),
		Some(admin_rank),
		last_fetched_time,
		last_fetched_group_id,
		group_as_member.as_deref(),
	)
	.await?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_delete_sent_join_req_user(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	join_req_group_id: &str,
	group_as_member: Option<String>,
) -> Result<(), SentcError>
{
	Ok(util_req_full::group::delete_sent_join_req(
		base_url,
		auth_token,
		jwt,
		None,
		None,
		join_req_group_id,
		group_as_member.as_deref(),
	)
	.await?)
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_delete_sent_join_req(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	admin_rank: i32,
	join_req_group_id: &str,
	group_as_member: Option<String>,
) -> Result<(), SentcError>
{
	Ok(util_req_full::group::delete_sent_join_req(
		base_url,
		auth_token,
		jwt,
		Some(id),
		Some(admin_rank),
		join_req_group_id,
		group_as_member.as_deref(),
	)
	.await?)
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_join_req(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	group_id: &str,
	group_as_member: Option<String>,
) -> Result<(), SentcError>
{
	let group_id = if group_id.is_empty() { None } else { Some(group_id) };

	Ok(util_req_full::group::join_req(base_url, auth_token, jwt, id, group_id, group_as_member.as_deref()).await?)
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_get_join_reqs(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	admin_rank: i32,
	last_fetched_time: &str,
	last_fetched_id: &str,
	group_as_member: Option<String>,
) -> Result<Vec<GroupJoinReqList>, SentcError>
{
	let out = util_req_full::group::get_join_reqs(
		base_url,
		auth_token,
		jwt,
		id,
		admin_rank,
		last_fetched_time,
		last_fetched_id,
		group_as_member.as_deref(),
	)
	.await?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_reject_join_req(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	admin_rank: i32,
	rejected_user_id: &str,
	group_as_member: Option<String>,
) -> Result<(), SentcError>
{
	Ok(util_req_full::group::reject_join_req(
		base_url,
		auth_token,
		jwt,
		id,
		admin_rank,
		rejected_user_id,
		group_as_member.as_deref(),
	)
	.await?)
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_accept_join_req(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	user_id: &str,
	key_count: i32,
	rank: Option<i32>,
	admin_rank: i32,
	user_public_key: &str,
	group_keys: &str,
	group_as_member: Option<String>,
) -> Result<String, SentcError>
{
	let out = util_req_full::group::accept_join_req(
		base_url,
		auth_token,
		jwt,
		id,
		user_id,
		key_count,
		rank,
		admin_rank,
		user_public_key,
		group_keys,
		group_as_member.as_deref(),
	)
	.await?;

	Ok(out.unwrap_or_default())
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_join_user_session(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	session_id: &str,
	user_public_key: &str,
	group_keys: &str,
	group_as_member: Option<String>,
) -> Result<(), SentcError>
{
	Ok(util_req_full::group::join_user_session(
		base_url,
		auth_token,
		jwt,
		id,
		session_id,
		user_public_key,
		group_keys,
		group_as_member.as_deref(),
	)
	.await?)
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_stop_group_invites(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	admin_rank: i32,
	group_as_member: Option<String>,
) -> Result<(), SentcError>
{
	Ok(util_req_full::group::stop_group_invites(base_url, auth_token, jwt, id, admin_rank, group_as_member.as_deref()).await?)
}

//__________________________________________________________________________________________________

#[uniffi::export(async_runtime = "tokio")]
pub async fn leave_group(base_url: String, auth_token: &str, jwt: &str, id: &str, group_as_member: Option<String>) -> Result<(), SentcError>
{
	Ok(util_req_full::group::leave_group(base_url, auth_token, jwt, id, group_as_member.as_deref()).await?)
}

//__________________________________________________________________________________________________
//key rotation

#[uniffi::export]
pub fn group_prepare_key_rotation(pre_group_key: &str, public_key: &str, sign_key: Option<String>, starter: String) -> Result<String, SentcError>
{
	Ok(sentc_crypto::group::key_rotation(
		pre_group_key,
		public_key,
		false,
		sign_key.as_deref(),
		starter,
	)?)
}

#[uniffi::export]
pub fn group_done_key_rotation(private_key: &str, public_key: &str, pre_group_key: &str, server_output: &str) -> Result<String, SentcError>
{
	Ok(sentc_crypto::group::done_key_rotation(
		private_key,
		public_key,
		pre_group_key,
		server_output,
	)?)
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_key_rotation(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	public_key: &str,
	pre_group_key: &str,
	sign_key: Option<String>,
	starter: String,
	group_as_member: Option<String>,
) -> Result<String, SentcError>
{
	Ok(util_req_full::group::key_rotation(
		base_url,
		auth_token,
		jwt,
		id,
		public_key,
		pre_group_key,
		false,
		sign_key.as_deref(),
		starter,
		group_as_member.as_deref(),
	)
	.await?)
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_pre_done_key_rotation(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	group_as_member: Option<String>,
) -> Result<Vec<KeyRotationGetOut>, SentcError>
{
	let out = util_req_full::group::prepare_done_key_rotation(base_url, auth_token, jwt, id, false, group_as_member.as_deref()).await?;

	Ok(out.into_iter().map(|item| item.into()).collect())
}

#[uniffi::export]
pub fn group_get_done_key_rotation_server_input(server_output: &str) -> Result<KeyRotationInput, SentcError>
{
	let out = sentc_crypto::group::get_done_key_rotation_server_input(server_output)?;

	Ok(out.into())
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_finish_key_rotation(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	server_output: &str,
	pre_group_key: &str,
	public_key: &str,
	private_key: &str,
	group_as_member: Option<String>,
) -> Result<(), SentcError>
{
	Ok(util_req_full::group::done_key_rotation(
		base_url,
		auth_token,
		jwt,
		id,
		server_output,
		pre_group_key,
		public_key,
		private_key,
		false,
		group_as_member.as_deref(),
	)
	.await?)
}

//__________________________________________________________________________________________________
//group update fn

#[uniffi::export]
pub fn group_prepare_update_rank(user_id: &str, rank: i32, admin_rank: i32) -> Result<String, SentcError>
{
	Ok(sentc_crypto::group::prepare_change_rank(user_id, rank, admin_rank)?)
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_update_rank(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	user_id: &str,
	rank: i32,
	admin_rank: i32,
	group_as_member: Option<String>,
) -> Result<(), SentcError>
{
	Ok(util_req_full::group::update_rank(
		base_url,
		auth_token,
		jwt,
		id,
		user_id,
		rank,
		admin_rank,
		group_as_member.as_deref(),
	)
	.await?)
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_kick_user(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	user_id: &str,
	admin_rank: i32,
	group_as_member: Option<String>,
) -> Result<(), SentcError>
{
	Ok(util_req_full::group::kick_user(
		base_url,
		auth_token,
		jwt,
		id,
		user_id,
		admin_rank,
		group_as_member.as_deref(),
	)
	.await?)
}

//__________________________________________________________________________________________________

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_delete_group(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	admin_rank: i32,
	group_as_member: Option<String>,
) -> Result<(), SentcError>
{
	Ok(util_req_full::group::delete_group(base_url, auth_token, jwt, id, admin_rank, group_as_member.as_deref()).await?)
}

#[derive(uniffi::Record)]
pub struct GroupPublicKeyData
{
	pub public_key: String,
	pub public_key_id: String,
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn group_get_public_key_data(base_url: String, auth_token: &str, id: &str) -> Result<GroupPublicKeyData, SentcError>
{
	let (public_key, public_key_id) = util_req_full::group::get_public_key_data(base_url, auth_token, id).await?;

	Ok(GroupPublicKeyData {
		public_key,
		public_key_id,
	})
}
