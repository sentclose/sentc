#[cfg(not(feature = "rust"))]
mod non_rust;
#[cfg(feature = "rust")]
mod rust;

use alloc::string::String;
use alloc::vec::Vec;
use core::future::Future;

use sentc_crypto_common::group::{
	GroupCreateOutput,
	GroupDataCheckUpdateServerOutputLight,
	GroupInviteReqList,
	GroupJoinReqList,
	GroupNewMemberLightInput,
	GroupUserListItem,
};
use sentc_crypto_light::error::SdkLightError;
use sentc_crypto_utils::http::{make_req, HttpMethod};
use sentc_crypto_utils::{handle_general_server_response, handle_server_response};

#[cfg(not(feature = "rust"))]
pub(crate) use self::non_rust::{DataRes, InviteListRes, JoinReqListRes, MemberRes, Res, UserUpdateCheckRes, VoidRes};
#[cfg(feature = "rust")]
pub(crate) use self::rust::{DataRes, InviteListRes, JoinReqListRes, MemberRes, Res, UserUpdateCheckRes, VoidRes};

#[inline(never)]
async fn create_group(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	parent_group_id: Option<&str>,
	connected_group_id: Option<&str>,
	group_as_member: Option<&str>,
) -> Res
{
	let url = match (parent_group_id, connected_group_id) {
		(None, Some(id)) => base_url + "/api/v1/group/" + id + "/connected/light",
		(Some(id), None) => base_url + "/api/v1/group/" + id + "/child/light",
		_ => base_url + "/api/v1/group/light", //(None, None) or both set
	};

	let res = make_req(HttpMethod::POST, &url, auth_token, None, Some(jwt), group_as_member).await?;

	let group_id: GroupCreateOutput = handle_server_response(&res)?;

	Ok(group_id.group_id)
}

pub fn create<'a>(base_url: String, auth_token: &'a str, jwt: &'a str, group_as_member: Option<&'a str>) -> impl Future<Output = Res> + 'a
{
	create_group(base_url, auth_token, jwt, None, None, group_as_member)
}

pub async fn create_child_group(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	parent_group_id: &str,
	admin_rank: i32,
	group_as_member: Option<&str>,
) -> Res
{
	if admin_rank > 1 {
		return Err(SdkLightError::GroupPermission)?;
	}

	create_group(
		base_url,
		auth_token,
		jwt,
		Some(parent_group_id),
		None,
		group_as_member,
	)
	.await
}

pub async fn create_connected_group(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	connected_group_id: &str,
	admin_rank: i32,
	group_as_member: Option<&str>,
) -> Res
{
	if admin_rank > 1 {
		return Err(SdkLightError::GroupPermission)?;
	}

	create_group(
		base_url,
		auth_token,
		jwt,
		None,
		Some(connected_group_id),
		group_as_member,
	)
	.await
}

pub async fn get_group_light(base_url: String, auth_token: &str, jwt: &str, id: &str, group_as_member: Option<&str>) -> DataRes
{
	let url = base_url + "/api/v1/group/" + id + "/light";

	let res = make_req(
		HttpMethod::GET,
		url.as_str(),
		auth_token,
		None,
		Some(jwt),
		group_as_member,
	)
	.await?;

	let out = sentc_crypto_light::group::get_group_light_data(&res)?;

	Ok(out)
}

pub async fn get_member(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	last_fetched_time: &str,
	last_fetched_id: &str,
	group_as_member: Option<&str>,
) -> MemberRes
{
	let url = base_url + "/api/v1/group/" + id + "/member/" + last_fetched_time + "/" + last_fetched_id;

	let res = make_req(HttpMethod::GET, &url, auth_token, None, Some(jwt), group_as_member).await?;

	let out: Vec<GroupUserListItem> = handle_server_response(&res)?;

	Ok(out)
}

pub async fn get_group_updates(base_url: String, auth_token: &str, jwt: &str, id: &str, group_as_member: Option<&str>) -> UserUpdateCheckRes
{
	let url = base_url + "/api/v1/group/" + id + "/update_check_light";

	let res = make_req(HttpMethod::GET, &url, auth_token, None, Some(jwt), group_as_member).await?;

	let out: GroupDataCheckUpdateServerOutputLight = handle_server_response(&res)?;

	Ok(out.rank)
}

//__________________________________________________________________________________________________
//invite

#[allow(clippy::too_many_arguments)]
pub async fn invite_user(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	user_to_invite_id: &str,
	rank: Option<i32>,
	admin_rank: i32,
	auto_invite: bool,
	group_invite: bool,
	re_invite: bool,
	group_as_member: Option<&str>,
) -> VoidRes
{
	if admin_rank > 2 {
		return Err(SdkLightError::GroupPermission)?;
	}

	let endpoint = if re_invite {
		if group_invite {
			"re_invite_group"
		} else {
			"re_invite"
		}
	} else {
		match (group_invite, auto_invite) {
			(true, true) => "invite_group_auto",
			(false, true) => "invite_auto",
			(true, false) => "invite_group",
			(false, false) => "invite",
		}
	};

	let url = base_url + "/api/v1/group/" + id + "/" + endpoint + "/" + user_to_invite_id + "/light";

	let body = GroupNewMemberLightInput {
		rank,
	};

	let res = make_req(
		HttpMethod::PUT,
		url.as_str(),
		auth_token,
		Some(serde_json::to_string(&body).map_err(SdkLightError::JsonParseFailed)?),
		Some(jwt),
		group_as_member,
	)
	.await?;

	Ok(handle_general_server_response(&res)?)
}

pub async fn get_invites_for_user(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	last_fetched_time: &str,
	last_fetched_group_id: &str,
	group_id: Option<&str>,
	group_as_member: Option<&str>,
) -> InviteListRes
{
	//get invites for user and group as member

	let url = match group_id {
		Some(id) => base_url + "/api/v1/group/" + id + "/invite/" + last_fetched_time + "/" + last_fetched_group_id,
		None => base_url + "/api/v1/group/invite/" + last_fetched_time + "/" + last_fetched_group_id,
	};

	let res = make_req(HttpMethod::GET, &url, auth_token, None, Some(jwt), group_as_member).await?;

	let invites: Vec<GroupInviteReqList> = handle_server_response(&res)?;

	Ok(invites)
}

pub async fn accept_invite(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id_to_accept: &str,
	group_id: Option<&str>,
	group_as_member: Option<&str>,
) -> VoidRes
{
	let url = match group_id {
		Some(id) => base_url + "/api/v1/group/" + id + "/" + group_id_to_accept + "/invite",
		None => base_url + "/api/v1/group/" + group_id_to_accept + "/invite",
	};

	let res = make_req(HttpMethod::PATCH, &url, auth_token, None, Some(jwt), group_as_member).await?;

	Ok(handle_general_server_response(&res)?)
}

pub async fn reject_invite(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id_to_reject: &str,
	group_id: Option<&str>,
	group_as_member: Option<&str>,
) -> VoidRes
{
	let url = match group_id {
		Some(id) => base_url + "/api/v1/group/" + id + "/" + group_id_to_reject + "/invite",
		None => base_url + "/api/v1/group/" + group_id_to_reject + "/invite",
	};

	let res = make_req(HttpMethod::DELETE, &url, auth_token, None, Some(jwt), group_as_member).await?;

	Ok(handle_general_server_response(&res)?)
}

pub async fn join_req(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id_to_join: &str,
	group_id: Option<&str>,
	group_as_member: Option<&str>,
) -> VoidRes
{
	let url = match group_id {
		Some(id) => base_url + "/api/v1/group/" + id + "/join_req/" + group_id_to_join,
		None => base_url + "/api/v1/group/" + group_id_to_join + "/join_req",
	};

	let res = make_req(HttpMethod::PATCH, &url, auth_token, None, Some(jwt), group_as_member).await?;

	Ok(handle_general_server_response(&res)?)
}

#[allow(clippy::too_many_arguments)]
pub async fn get_join_reqs(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: &str,
	admin_rank: i32,
	last_fetched_time: &str,
	last_fetched_id: &str,
	group_as_member: Option<&str>,
) -> JoinReqListRes
{
	if admin_rank > 2 {
		return Err(SdkLightError::GroupPermission)?;
	}

	let url = base_url + "/api/v1/group/" + group_id + "/join_req/" + last_fetched_time + "/" + last_fetched_id;

	let res = make_req(HttpMethod::GET, &url, auth_token, None, Some(jwt), group_as_member).await?;

	let join_reqs: Vec<GroupJoinReqList> = handle_server_response(&res)?;

	Ok(join_reqs)
}

pub async fn reject_join_req(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: &str,
	admin_rank: i32,
	rejected_user_id: &str,
	group_as_member: Option<&str>,
) -> VoidRes
{
	if admin_rank > 2 {
		return Err(SdkLightError::GroupPermission)?;
	}

	let url = base_url + "/api/v1/group/" + group_id + "/join_req/" + rejected_user_id;

	let res = make_req(HttpMethod::DELETE, &url, auth_token, None, Some(jwt), group_as_member).await?;

	Ok(handle_general_server_response(&res)?)
}

#[allow(clippy::too_many_arguments)]
pub async fn accept_join_req(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: &str,
	user_id: &str,
	rank: Option<i32>,
	admin_rank: i32,
	group_as_member: Option<&str>,
) -> VoidRes
{
	if admin_rank > 2 {
		return Err(SdkLightError::GroupPermission)?;
	}

	let url = base_url + "/api/v1/group/" + group_id + "/join_req/" + user_id + "/light";

	let input = GroupNewMemberLightInput {
		rank,
	};

	//insert the invite and check for more keys in the sdk impl and call the other fn!
	let res = make_req(
		HttpMethod::PUT,
		&url,
		auth_token,
		Some(serde_json::to_string(&input).map_err(SdkLightError::JsonParseFailed)?),
		Some(jwt),
		group_as_member,
	)
	.await?;

	Ok(handle_general_server_response(&res)?)
}

pub async fn stop_group_invites(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: &str,
	admin_rank: i32,
	group_as_member: Option<&str>,
) -> VoidRes
{
	if admin_rank > 1 {
		return Err(SdkLightError::GroupPermission)?;
	}

	let url = base_url + "/api/v1/group/" + group_id + "/change_invite";

	let res = make_req(HttpMethod::PATCH, &url, auth_token, None, Some(jwt), group_as_member).await?;

	Ok(handle_general_server_response(&res)?)
}

//__________________________________________________________________________________________________

pub async fn leave_group(base_url: String, auth_token: &str, jwt: &str, group_id: &str, group_as_member: Option<&str>) -> VoidRes
{
	let url = base_url + "/api/v1/group/" + group_id + "/leave";

	let res = make_req(HttpMethod::DELETE, &url, auth_token, None, Some(jwt), group_as_member).await?;

	Ok(handle_general_server_response(&res)?)
}

//__________________________________________________________________________________________________
//group admin fn

#[allow(clippy::too_many_arguments)]
pub async fn update_rank(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: &str,
	user_id: &str,
	rank: i32,
	admin_rank: i32,
	group_as_member: Option<&str>,
) -> VoidRes
{
	let url = base_url + "/api/v1/group/" + group_id + "/change_rank";

	let input = sentc_crypto_light::group::prepare_change_rank(user_id, rank, admin_rank)?;

	let res = make_req(
		HttpMethod::PUT,
		&url,
		auth_token,
		Some(input),
		Some(jwt),
		group_as_member,
	)
	.await?;

	Ok(handle_general_server_response(&res)?)
}

pub async fn kick_user(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: &str,
	user_id: &str,
	admin_rank: i32,
	group_as_member: Option<&str>,
) -> VoidRes
{
	if admin_rank > 2 {
		return Err(SdkLightError::GroupPermission)?;
	}

	let url = base_url + "/api/v1/group/" + group_id + "/kick/" + user_id;

	let res = make_req(HttpMethod::DELETE, &url, auth_token, None, Some(jwt), group_as_member).await?;

	Ok(handle_general_server_response(&res)?)
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub async fn get_sent_join_req(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: Option<&str>,
	admin_rank: Option<i32>,
	last_fetched_time: &str,
	last_fetched_id: &str,
	group_as_member: Option<&str>,
) -> InviteListRes
{
	//the join req the group or user sent

	let url = match (group_id, admin_rank) {
		(Some(id), Some(rank)) => {
			if rank > 1 {
				return Err(SdkLightError::GroupPermission)?;
			}

			base_url + "/api/v1/group/" + id + "/joins/" + last_fetched_time + "/" + last_fetched_id
		},
		_ => base_url + "/api/v1/group/joins/" + last_fetched_time + "/" + last_fetched_id,
	};

	let res = make_req(HttpMethod::GET, &url, auth_token, None, Some(jwt), group_as_member).await?;

	let out: Vec<GroupInviteReqList> = handle_server_response(&res)?;

	Ok(out)
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub async fn delete_sent_join_req(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: Option<&str>,
	admin_rank: Option<i32>,
	join_req_group_id: &str,
	group_as_member: Option<&str>,
) -> VoidRes
{
	let url = match (group_id, admin_rank) {
		(Some(id), Some(rank)) => {
			if rank > 1 {
				return Err(SdkLightError::GroupPermission)?;
			}

			base_url + "/api/v1/group/" + id + "/joins/" + join_req_group_id
		},
		_ => base_url + "/api/v1/group/joins/" + join_req_group_id,
	};

	let res = make_req(HttpMethod::DELETE, &url, auth_token, None, Some(jwt), group_as_member).await?;

	Ok(handle_general_server_response(&res)?)
}

//__________________________________________________________________________________________________

pub async fn delete_group(base_url: String, auth_token: &str, jwt: &str, group_id: &str, admin_rank: i32, group_as_member: Option<&str>) -> VoidRes
{
	if admin_rank > 1 {
		return Err(SdkLightError::GroupPermission)?;
	}

	let url = base_url + "/api/v1/group/" + group_id;

	let res = make_req(HttpMethod::DELETE, &url, auth_token, None, Some(jwt), group_as_member).await?;

	Ok(handle_general_server_response(&res)?)
}
