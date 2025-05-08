use sentc_crypto_light::util_req_full;

pub struct GroupOutDataLightExport
{
	pub group_id: String,
	pub parent_group_id: Option<String>,
	pub rank: i32,
	pub created_time: String,
	pub joined_time: String,
	pub access_by_group_as_member: Option<String>,
	pub access_by_parent_group: Option<String>,
	pub is_connected_group: bool,
}

impl From<sentc_crypto_light::sdk_utils::group::GroupOutDataLightExport> for GroupOutDataLightExport
{
	fn from(value: sentc_crypto_light::sdk_utils::group::GroupOutDataLightExport) -> Self
	{
		Self {
			group_id: value.group_id,
			parent_group_id: value.parent_group_id,
			rank: value.rank,
			created_time: value.created_time.to_string(),
			joined_time: value.joined_time.to_string(),
			access_by_group_as_member: value.access_by_group_as_member,
			access_by_parent_group: value.access_by_parent_group,
			is_connected_group: value.is_connected_group,
		}
	}
}

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

/**
Create a group with a request.

Only the default values are sent to the server, no extra data. If extra data is required, use prepare_create
 */
pub async fn group_create_group(base_url: String, auth_token: &str, jwt: &str, group_as_member: Option<String>) -> Result<String, String>
{
	util_req_full::group::create(base_url, auth_token, jwt, group_as_member.as_deref()).await
}

pub async fn group_create_child_group(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	parent_id: &str,
	admin_rank: i32,
	group_as_member: Option<String>,
) -> Result<String, String>
{
	util_req_full::group::create_child_group(
		base_url,
		auth_token,
		jwt,
		parent_id,
		admin_rank,
		group_as_member.as_deref(),
	)
	.await
}

pub async fn group_create_connected_group(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	connected_group_id: &str,
	admin_rank: i32,
	group_as_member: Option<String>,
) -> Result<String, String>
{
	util_req_full::group::create_connected_group(
		base_url,
		auth_token,
		jwt,
		connected_group_id,
		admin_rank,
		group_as_member.as_deref(),
	)
	.await
}

//__________________________________________________________________________________________________

/**
Get the group data without a request.

Use the parent group private key when fetching child group data.
 */
pub fn group_extract_group_data(server_output: &str) -> Result<GroupOutDataLightExport, String>
{
	let out = sentc_crypto_light::group::get_group_light_data(server_output)?;

	Ok(out.into())
}

pub async fn group_get_group_data(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	group_as_member: Option<String>,
) -> Result<GroupOutDataLightExport, String>
{
	let out = util_req_full::group::get_group_light(base_url, auth_token, jwt, id, group_as_member.as_deref()).await?;

	Ok(out.into())
}

//__________________________________________________________________________________________________

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

pub async fn group_get_member(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	last_fetched_time: &str,
	last_fetched_id: &str,
	group_as_member: Option<String>,
) -> Result<Vec<GroupUserListItem>, String>
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

pub async fn group_get_group_updates(base_url: String, auth_token: &str, jwt: &str, id: &str, group_as_member: Option<String>)
	-> Result<i32, String>
{
	util_req_full::group::get_group_updates(base_url, auth_token, jwt, id, group_as_member.as_deref()).await
}

pub async fn group_get_all_first_level_children(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	last_fetched_time: &str,
	last_fetched_group_id: &str,
	group_as_member: Option<String>,
) -> Result<Vec<GroupChildrenList>, String>
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

pub async fn group_get_groups_for_user(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	last_fetched_time: &str,
	last_fetched_group_id: &str,
	group_id: Option<String>,
) -> Result<Vec<ListGroups>, String>
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

#[allow(clippy::too_many_arguments)]
pub async fn group_invite_user(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	user_id: &str,
	rank: Option<i32>,
	admin_rank: i32,
	auto_invite: bool,
	group_invite: bool,
	group_as_member: Option<String>,
) -> Result<(), String>
{
	util_req_full::group::invite_user(
		base_url,
		auth_token,
		jwt,
		id,
		user_id,
		rank,
		admin_rank,
		auto_invite,
		group_invite,
		group_as_member.as_deref(),
	)
	.await
}

pub async fn group_get_invites_for_user(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	last_fetched_time: &str,
	last_fetched_group_id: &str,
	group_id: Option<String>,
	group_as_member: Option<String>,
) -> Result<Vec<GroupInviteReqList>, String>
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

pub async fn group_accept_invite(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	group_id: Option<String>,
	group_as_member: Option<String>,
) -> Result<(), String>
{
	util_req_full::group::accept_invite(
		base_url,
		auth_token,
		jwt,
		id,
		group_id.as_deref(),
		group_as_member.as_deref(),
	)
	.await
}

pub async fn group_reject_invite(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	group_id: Option<String>,
	group_as_member: Option<String>,
) -> Result<(), String>
{
	util_req_full::group::reject_invite(
		base_url,
		auth_token,
		jwt,
		id,
		group_id.as_deref(),
		group_as_member.as_deref(),
	)
	.await
}

//__________________________________________________________________________________________________
//join req

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

pub async fn group_get_sent_join_req_user(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	last_fetched_time: &str,
	last_fetched_group_id: &str,
	group_as_member: Option<String>,
) -> Result<Vec<GroupInviteReqList>, String>
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

#[allow(clippy::too_many_arguments)]
pub async fn group_get_sent_join_req(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	admin_rank: i32,
	last_fetched_time: &str,
	last_fetched_group_id: &str,
	group_as_member: Option<String>,
) -> Result<Vec<GroupInviteReqList>, String>
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

pub async fn group_delete_sent_join_req_user(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	join_req_group_id: &str,
	group_as_member: Option<String>,
) -> Result<(), String>
{
	util_req_full::group::delete_sent_join_req(
		base_url,
		auth_token,
		jwt,
		None,
		None,
		join_req_group_id,
		group_as_member.as_deref(),
	)
	.await
}

pub async fn group_delete_sent_join_req(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	admin_rank: i32,
	join_req_group_id: &str,
	group_as_member: Option<String>,
) -> Result<(), String>
{
	util_req_full::group::delete_sent_join_req(
		base_url,
		auth_token,
		jwt,
		Some(id),
		Some(admin_rank),
		join_req_group_id,
		group_as_member.as_deref(),
	)
	.await
}

pub async fn group_join_req(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	group_id: &str,
	group_as_member: Option<String>,
) -> Result<(), String>
{
	let group_id = if group_id.is_empty() { None } else { Some(group_id) };

	util_req_full::group::join_req(base_url, auth_token, jwt, id, group_id, group_as_member.as_deref()).await
}

#[allow(clippy::too_many_arguments)]
pub async fn group_get_join_reqs(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	admin_rank: i32,
	last_fetched_time: &str,
	last_fetched_id: &str,
	group_as_member: Option<String>,
) -> Result<Vec<GroupJoinReqList>, String>
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

pub async fn group_reject_join_req(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	admin_rank: i32,
	rejected_user_id: &str,
	group_as_member: Option<String>,
) -> Result<(), String>
{
	util_req_full::group::reject_join_req(
		base_url,
		auth_token,
		jwt,
		id,
		admin_rank,
		rejected_user_id,
		group_as_member.as_deref(),
	)
	.await
}

#[allow(clippy::too_many_arguments)]
pub async fn group_accept_join_req(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	user_id: &str,
	rank: Option<i32>,
	admin_rank: i32,
	group_as_member: Option<String>,
) -> Result<(), String>
{
	util_req_full::group::accept_join_req(
		base_url,
		auth_token,
		jwt,
		id,
		user_id,
		rank,
		admin_rank,
		group_as_member.as_deref(),
	)
	.await
}

pub async fn group_stop_group_invites(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	admin_rank: i32,
	group_as_member: Option<String>,
) -> Result<(), String>
{
	util_req_full::group::stop_group_invites(base_url, auth_token, jwt, id, admin_rank, group_as_member.as_deref()).await
}

//__________________________________________________________________________________________________

pub async fn leave_group(base_url: String, auth_token: &str, jwt: &str, id: &str, group_as_member: Option<String>) -> Result<(), String>
{
	util_req_full::group::leave_group(base_url, auth_token, jwt, id, group_as_member.as_deref()).await
}

//__________________________________________________________________________________________________
//group update fn

pub fn group_prepare_update_rank(user_id: &str, rank: i32, admin_rank: i32) -> Result<String, String>
{
	sentc_crypto_light::group::prepare_change_rank(user_id, rank, admin_rank)
}

#[allow(clippy::too_many_arguments)]
pub async fn group_update_rank(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	user_id: &str,
	rank: i32,
	admin_rank: i32,
	group_as_member: Option<String>,
) -> Result<(), String>
{
	util_req_full::group::update_rank(
		base_url,
		auth_token,
		jwt,
		id,
		user_id,
		rank,
		admin_rank,
		group_as_member.as_deref(),
	)
	.await
}

pub async fn group_kick_user(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	user_id: &str,
	admin_rank: i32,
	group_as_member: Option<String>,
) -> Result<(), String>
{
	util_req_full::group::kick_user(
		base_url,
		auth_token,
		jwt,
		id,
		user_id,
		admin_rank,
		group_as_member.as_deref(),
	)
	.await
}

//__________________________________________________________________________________________________

pub async fn group_delete_group(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	admin_rank: i32,
	group_as_member: Option<String>,
) -> Result<(), String>
{
	util_req_full::group::delete_group(base_url, auth_token, jwt, id, admin_rank, group_as_member.as_deref()).await
}
