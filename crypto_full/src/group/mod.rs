#[cfg(not(feature = "rust"))]
mod non_rust;
#[cfg(feature = "rust")]
mod rust;

use alloc::string::String;
use alloc::vec::Vec;
use core::future::Future;

use sentc_crypto::util::public::{handle_general_server_response, handle_server_response};
use sentc_crypto_common::group::{
	GroupAcceptJoinReqServerOutput,
	GroupCreateOutput,
	GroupDataCheckUpdateServerOutput,
	GroupInviteReqList,
	GroupInviteServerOutput,
	GroupJoinReqList,
	GroupUserListItem,
	KeyRotationInput,
	KeyRotationStartServerOutput,
	ListGroups,
};

#[cfg(not(feature = "rust"))]
pub(crate) use self::non_rust::{
	DataRes,
	GroupListRes,
	InviteListRes,
	JoinReqListRes,
	KeyFetchRes,
	KeyRes,
	KeyRotationGetOut,
	KeyRotationRes,
	MemberRes,
	Res,
	SessionRes,
	SingleKeyRes,
	UserUpdateCheckRes,
	VoidRes,
};
#[cfg(feature = "rust")]
pub(crate) use self::rust::{
	DataRes,
	GroupListRes,
	InviteListRes,
	JoinReqListRes,
	KeyFetchRes,
	KeyRes,
	KeyRotationRes,
	MemberRes,
	Res,
	SessionRes,
	SingleKeyRes,
	UserUpdateCheckRes,
	VoidRes,
};
use crate::util::{make_req, HttpMethod};

async fn create_group(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	parent_group_id: Option<&str>,
	#[cfg(not(feature = "rust"))] public_key: &str,
	#[cfg(feature = "rust")] public_key: &sentc_crypto::util::PublicKeyFormat,
) -> Res
{
	let url = match parent_group_id {
		Some(id) => base_url + "/api/v1/group/" + id + "/child",
		None => base_url + "/api/v1/group",
	};

	let input = sentc_crypto::group::prepare_create(public_key)?;

	let res = make_req(HttpMethod::POST, url.as_str(), auth_token, Some(input), Some(jwt)).await?;

	let group_id: GroupCreateOutput = handle_server_response(res.as_str())?;

	Ok(group_id.group_id)
}

pub fn create<'a>(
	base_url: String,
	auth_token: &'a str,
	jwt: &'a str,
	#[cfg(not(feature = "rust"))] creators_public_key: &'a str,
	#[cfg(feature = "rust")] creators_public_key: &'a sentc_crypto::util::PublicKeyFormat,
) -> impl Future<Output = Res> + 'a
{
	create_group(base_url, auth_token, jwt, None, creators_public_key)
}

pub async fn create_child_group(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	parent_group_id: &str,
	admin_rank: i32,
	#[cfg(not(feature = "rust"))] parent_public_key: &str,
	#[cfg(feature = "rust")] parent_public_key: &sentc_crypto::util::PublicKeyFormat,
) -> Res
{
	sentc_crypto::group::check_create_sub_group(admin_rank)?;

	create_group(base_url, auth_token, jwt, Some(parent_group_id), parent_public_key).await
}

//__________________________________________________________________________________________________

pub async fn get_group(base_url: String, auth_token: &str, jwt: &str, id: &str) -> DataRes
{
	let url = base_url + "/api/v1/group/" + id;

	let res = make_req(HttpMethod::GET, url.as_str(), auth_token, None, Some(jwt)).await?;

	let out = sentc_crypto::group::get_group_data(res.as_str())?;

	Ok(out)
}

pub async fn get_group_keys(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	last_fetched_time: &str,
	last_fetched_key_id: &str,
) -> KeyFetchRes
{
	let url = base_url + "/api/v1/group/" + id + "/keys/" + last_fetched_time + "/" + last_fetched_key_id;

	let res = make_req(HttpMethod::GET, url.as_str(), auth_token, None, Some(jwt)).await?;

	let group_keys = sentc_crypto::group::get_group_keys_from_server_output(res.as_str())?;

	Ok(group_keys)
}

pub async fn get_group_key(base_url: String, auth_token: &str, jwt: &str, id: &str, key_id: &str) -> SingleKeyRes
{
	let url = base_url + "/api/v1/group/" + id + "/key/" + key_id;

	let res = make_req(HttpMethod::GET, url.as_str(), auth_token, None, Some(jwt)).await?;

	let group_key = sentc_crypto::group::get_group_key_from_server_output(res.as_str())?;

	Ok(group_key)
}

//allowed because of the rust feature needs the ? for converting the err into sdk full err
#[allow(clippy::needless_question_mark)]
pub fn decrypt_key(
	#[cfg(not(feature = "rust"))] server_key_output: &str,
	#[cfg(feature = "rust")] server_key_output: &sentc_crypto_common::group::GroupKeyServerOutput,
	#[cfg(not(feature = "rust"))] private_key: &str,
	#[cfg(feature = "rust")] private_key: &sentc_crypto::util::PrivateKeyFormat,
) -> KeyRes
{
	Ok(sentc_crypto::group::decrypt_group_keys(
		private_key,
		server_key_output,
	)?)
}

pub async fn get_member(base_url: String, auth_token: &str, jwt: &str, id: &str, last_fetched_time: &str, last_fetched_id: &str) -> MemberRes
{
	let url = base_url + "/api/v1/group/" + id + "/member/" + last_fetched_time + "/" + last_fetched_id;

	let res = make_req(HttpMethod::GET, url.as_str(), auth_token, None, Some(jwt)).await?;

	let out: Vec<GroupUserListItem> = handle_server_response(res.as_str())?;

	Ok(out)
}

pub async fn get_group_updates(base_url: String, auth_token: &str, jwt: &str, id: &str) -> UserUpdateCheckRes
{
	let url = base_url + "/api/v1/group/" + id + "/update_check";

	let res = make_req(HttpMethod::GET, url.as_str(), auth_token, None, Some(jwt)).await?;

	let out: GroupDataCheckUpdateServerOutput = handle_server_response(res.as_str())?;

	Ok(out)
}

pub async fn get_groups_for_user(base_url: String, auth_token: &str, jwt: &str, last_fetched_time: &str, last_fetched_group_id: &str)
	-> GroupListRes
{
	let url = base_url + "/api/v1/group/all/" + last_fetched_time + "/" + last_fetched_group_id;

	let res = make_req(HttpMethod::GET, url.as_str(), auth_token, None, Some(jwt)).await?;

	let list: Vec<ListGroups> = handle_server_response(res.as_str())?;

	Ok(list)
}

//__________________________________________________________________________________________________
//invite

pub async fn invite_user(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	user_to_invite_id: &str,
	key_count: i32,
	admin_rank: i32,
	auto_invite: bool,
	#[cfg(not(feature = "rust"))] user_public_key: &str,
	#[cfg(feature = "rust")] user_public_key: &sentc_crypto_common::user::UserPublicKeyData,
	#[cfg(not(feature = "rust"))] group_keys: &str,
	#[cfg(feature = "rust")] group_keys: &[&sentc_crypto::util::SymKeyFormat],
) -> SessionRes
{
	sentc_crypto::group::check_make_invite_req(admin_rank)?;

	let endpoint = if auto_invite { "invite_auto" } else { "invite" };

	let url = base_url + "/api/v1/group/" + id + "/" + endpoint + "/" + user_to_invite_id;

	let key_session = key_count > 50;

	let invite = sentc_crypto::group::prepare_group_keys_for_new_member(user_public_key, group_keys, key_session)?;

	//insert the invite and check for more keys in the sdk impl and call the other fn!
	let res = make_req(HttpMethod::PUT, url.as_str(), auth_token, Some(invite), Some(jwt)).await?;

	let session: GroupInviteServerOutput = handle_server_response(res.as_str())?;

	Ok(session.session_id)
}

pub fn invite_user_session<'a>(
	base_url: String,
	auth_token: &'a str,
	jwt: &'a str,
	group_id: &'a str,
	session_id: &'a str,
	auto: bool,
	#[cfg(not(feature = "rust"))] user_public_key: &'a str,
	#[cfg(feature = "rust")] user_public_key: &'a sentc_crypto_common::user::UserPublicKeyData,
	#[cfg(not(feature = "rust"))] group_keys: &'a str,
	#[cfg(feature = "rust")] group_keys: &'a [&'a sentc_crypto::util::SymKeyFormat],
) -> impl Future<Output = VoidRes> + 'a
{
	//use the join session for auto invited user
	let kind = match auto {
		true => SessionKind::Join,
		false => SessionKind::Invite,
	};

	insert_session_keys(
		base_url,
		auth_token,
		jwt,
		group_id,
		kind,
		session_id,
		user_public_key,
		group_keys,
	)
}

pub async fn get_invites_for_user(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	last_fetched_time: &str,
	last_fetched_group_id: &str,
) -> InviteListRes
{
	let url = base_url + "/api/v1/group/invite/" + last_fetched_time + "/" + last_fetched_group_id;

	let res = make_req(HttpMethod::GET, url.as_str(), auth_token, None, Some(jwt)).await?;

	let invites: Vec<GroupInviteReqList> = handle_server_response(res.as_str())?;

	Ok(invites)
}

pub async fn accept_invite(base_url: String, auth_token: &str, jwt: &str, group_id: &str) -> VoidRes
{
	let url = base_url + "/api/v1/group/" + group_id + "/invite";

	let res = make_req(HttpMethod::PATCH, url.as_str(), auth_token, None, Some(jwt)).await?;

	Ok(handle_general_server_response(res.as_str())?)
}

pub async fn reject_invite(base_url: String, auth_token: &str, jwt: &str, group_id: &str) -> VoidRes
{
	let url = base_url + "/api/v1/group/" + group_id + "/invite";

	let res = make_req(HttpMethod::DELETE, url.as_str(), auth_token, None, Some(jwt)).await?;

	Ok(handle_general_server_response(res.as_str())?)
}

//__________________________________________________________________________________________________

pub async fn join_req(base_url: String, auth_token: &str, jwt: &str, group_id: &str) -> VoidRes
{
	let url = base_url + "/api/v1/group/" + group_id + "/join_req";

	let res = make_req(HttpMethod::PATCH, url.as_str(), auth_token, None, Some(jwt)).await?;

	Ok(handle_general_server_response(res.as_str())?)
}

pub async fn get_join_reqs(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: &str,
	admin_rank: i32,
	last_fetched_time: &str,
	last_fetched_id: &str,
) -> JoinReqListRes
{
	sentc_crypto::group::check_get_join_reqs(admin_rank)?;

	let url = base_url + "/api/v1/group/" + group_id + "/join_req/" + last_fetched_time + "/" + last_fetched_id;

	let res = make_req(HttpMethod::GET, url.as_str(), auth_token, None, Some(jwt)).await?;

	let join_reqs: Vec<GroupJoinReqList> = handle_server_response(res.as_str())?;

	Ok(join_reqs)
}

pub async fn reject_join_req(base_url: String, auth_token: &str, jwt: &str, group_id: &str, admin_rank: i32, rejected_user_id: &str) -> VoidRes
{
	sentc_crypto::group::check_get_join_reqs(admin_rank)?;

	let url = base_url + "/api/v1/group/" + group_id + "/join_req/" + rejected_user_id;

	let res = make_req(HttpMethod::DELETE, url.as_str(), auth_token, None, Some(jwt)).await?;

	Ok(handle_general_server_response(res.as_str())?)
}

pub async fn accept_join_req(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: &str,
	user_id: &str,
	key_count: i32,
	admin_rank: i32,
	#[cfg(not(feature = "rust"))] user_public_key: &str,
	#[cfg(feature = "rust")] user_public_key: &sentc_crypto_common::user::UserPublicKeyData,
	#[cfg(not(feature = "rust"))] group_keys: &str,
	#[cfg(feature = "rust")] group_keys: &[&sentc_crypto::util::SymKeyFormat],
) -> SessionRes
{
	sentc_crypto::group::check_get_join_reqs(admin_rank)?;

	let url = base_url + "/api/v1/group/" + group_id + "/join_req/" + user_id;

	let key_session = key_count > 50;

	let join = sentc_crypto::group::prepare_group_keys_for_new_member(user_public_key, group_keys, key_session)?;

	//insert the invite and check for more keys in the sdk impl and call the other fn!
	let res = make_req(HttpMethod::PUT, url.as_str(), auth_token, Some(join), Some(jwt)).await?;

	let out: GroupAcceptJoinReqServerOutput = handle_server_response(res.as_str())?;

	Ok(out.session_id)
}

pub fn join_user_session<'a>(
	base_url: String,
	auth_token: &'a str,
	jwt: &'a str,
	group_id: &'a str,
	session_id: &'a str,
	#[cfg(not(feature = "rust"))] user_public_key: &'a str,
	#[cfg(feature = "rust")] user_public_key: &'a sentc_crypto_common::user::UserPublicKeyData,
	#[cfg(not(feature = "rust"))] group_keys: &'a str,
	#[cfg(feature = "rust")] group_keys: &'a [&'a sentc_crypto::util::SymKeyFormat],
) -> impl Future<Output = VoidRes> + 'a
{
	insert_session_keys(
		base_url,
		auth_token,
		jwt,
		group_id,
		SessionKind::Join,
		session_id,
		user_public_key,
		group_keys,
	)
}

pub async fn stop_group_invites(base_url: String, auth_token: &str, jwt: &str, group_id: &str, admin_rank: i32) -> VoidRes
{
	sentc_crypto::group::check_create_sub_group(admin_rank)?;

	let url = base_url + "/api/v1/group/" + group_id + "/change_invite";

	let res = make_req(HttpMethod::PATCH, url.as_str(), auth_token, None, Some(jwt)).await?;

	Ok(handle_general_server_response(res.as_str())?)
}

//__________________________________________________________________________________________________

pub async fn leave_group(base_url: String, auth_token: &str, jwt: &str, group_id: &str) -> VoidRes
{
	let url = base_url + "/api/v1/group/" + group_id + "/leave";

	let res = make_req(HttpMethod::DELETE, url.as_str(), auth_token, None, Some(jwt)).await?;

	Ok(handle_general_server_response(res.as_str())?)
}

//__________________________________________________________________________________________________

#[inline(never)]
pub async fn key_rotation(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: &str,
	#[cfg(not(feature = "rust"))] public_key: &str,
	#[cfg(feature = "rust")] public_key: &sentc_crypto::util::PublicKeyFormat,
	#[cfg(not(feature = "rust"))] pre_group_key: &str,
	#[cfg(feature = "rust")] pre_group_key: &sentc_crypto::util::SymKeyFormat,
	user_group: bool,
) -> Res
{
	let url = match user_group {
		true => base_url + "/api/v1/user/user_keys/rotation",
		false => base_url + "/api/v1/group/" + group_id + "/key_rotation",
	};

	let input = sentc_crypto::group::key_rotation(pre_group_key, public_key, user_group)?;

	let res = make_req(HttpMethod::POST, url.as_str(), auth_token, Some(input), Some(jwt)).await?;

	let out: KeyRotationStartServerOutput = handle_server_response(res.as_str())?;

	Ok(out.key_id)
}

/**
Get the keys for the key rotation for this group

call with this arr the done key rotation fn for each key with the pre group key
*/
#[inline(never)]
pub async fn prepare_done_key_rotation(base_url: String, auth_token: &str, jwt: &str, group_id: &str, user_group: bool) -> KeyRotationRes
{
	let url = match user_group {
		true => base_url + "/api/v1/user/user_keys/rotation",
		false => base_url + "/api/v1/group/" + group_id + "/key_rotation",
	};

	let res = make_req(HttpMethod::GET, url.as_str(), auth_token, None, Some(jwt)).await?;

	let out: Vec<KeyRotationInput> = handle_server_response(res.as_str())?;

	//prepare the keys for done_key_rotation.
	// call for each key the done key rotation fn with the key id and the server output
	#[cfg(not(feature = "rust"))]
	let out = {
		let mut out_vec = Vec::with_capacity(out.len());

		for key in out {
			out_vec.push(KeyRotationGetOut {
				server_output: serde_json::to_string(&key).map_err(|_| sentc_crypto::SdkError::JsonToStringFailed)?,
				pre_group_key_id: key.previous_group_key_id,
				new_group_key_id: key.new_group_key_id,
				encrypted_eph_key_key_id: key.encrypted_eph_key_key_id,
			});
		}

		out_vec
	};

	Ok(out)
}

/**
Call this fn for each key.

In two fn because we don't know yet if the user got the pre group key or must fetch it.
*/
#[inline(never)]
pub async fn done_key_rotation(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: &str,
	#[cfg(not(feature = "rust"))] server_output: &str,
	#[cfg(feature = "rust")] server_output: &KeyRotationInput,
	#[cfg(not(feature = "rust"))] pre_group_key: &str,
	#[cfg(feature = "rust")] pre_group_key: &sentc_crypto::util::SymKeyFormat,
	#[cfg(not(feature = "rust"))] public_key: &str,
	#[cfg(feature = "rust")] public_key: &sentc_crypto::util::PublicKeyFormat,
	#[cfg(not(feature = "rust"))] private_key: &str,
	#[cfg(feature = "rust")] private_key: &sentc_crypto::util::PrivateKeyFormat,
	user_group: bool,
) -> VoidRes
{
	#[cfg(not(feature = "rust"))]
	let key_id = serde_json::from_str::<KeyRotationInput>(server_output)
		.map_err(|_| sentc_crypto::SdkError::JsonToStringFailed)?
		.new_group_key_id;
	#[cfg(not(feature = "rust"))]
	let key_id = key_id.as_str();

	#[cfg(feature = "rust")]
	let key_id = server_output.new_group_key_id.as_str();

	let url = match user_group {
		false => base_url + "/api/v1/group/" + group_id + "/key_rotation/" + key_id,
		true => base_url + "/api/v1/user/user_keys/rotation/" + key_id,
	};

	let input = sentc_crypto::group::done_key_rotation(private_key, public_key, pre_group_key, server_output)?;

	let res = make_req(HttpMethod::PUT, url.as_str(), auth_token, Some(input), Some(jwt)).await?;

	Ok(handle_general_server_response(res.as_str())?)
}

//__________________________________________________________________________________________________
//group admin fn

pub async fn update_rank(base_url: String, auth_token: &str, jwt: &str, group_id: &str, user_id: &str, rank: i32, admin_rank: i32) -> VoidRes
{
	let url = base_url + "/api/v1/group/" + group_id + "/change_rank";

	let input = sentc_crypto::group::prepare_change_rank(user_id, rank, admin_rank)?;

	let res = make_req(HttpMethod::PUT, url.as_str(), auth_token, Some(input), Some(jwt)).await?;

	Ok(handle_general_server_response(res.as_str())?)
}

pub async fn kick_user(base_url: String, auth_token: &str, jwt: &str, group_id: &str, user_id: &str, admin_rank: i32) -> VoidRes
{
	let url = base_url + "/api/v1/group/" + group_id + "/kick/" + user_id;

	sentc_crypto::group::check_delete_user_rank(admin_rank)?;

	let res = make_req(HttpMethod::DELETE, url.as_str(), auth_token, None, Some(jwt)).await?;

	Ok(handle_general_server_response(res.as_str())?)
}

#[inline(never)]
pub async fn get_sent_join_req(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: Option<&str>,
	admin_rank: Option<i32>,
	last_fetched_time: &str,
	last_fetched_id: &str,
) -> InviteListRes
{
	//the join req the group or user sent

	let url = match (group_id, admin_rank) {
		(Some(id), Some(rank)) => {
			sentc_crypto::group::check_sent_join_req_list(rank)?;
			base_url + "/api/v1/group/" + id + "/joins/" + last_fetched_time + "/" + last_fetched_id
		},
		_ => base_url + "/api/v1/group/joins/" + last_fetched_time + "/" + last_fetched_id,
	};

	let res = make_req(HttpMethod::GET, &url, auth_token, None, Some(jwt)).await?;

	let out: Vec<GroupInviteReqList> = handle_server_response(&res)?;

	Ok(out)
}

#[inline(never)]
pub async fn delete_sent_join_req(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: Option<&str>,
	admin_rank: Option<i32>,
	join_req_group_id: &str,
) -> VoidRes
{
	let url = match (group_id, admin_rank) {
		(Some(id), Some(rank)) => {
			sentc_crypto::group::check_sent_join_req_list(rank)?;
			base_url + "/api/v1/group/" + id + "/joins/" + join_req_group_id
		},
		_ => base_url + "/api/v1/group/joins/" + join_req_group_id,
	};

	let res = make_req(HttpMethod::DELETE, &url, auth_token, None, Some(jwt)).await?;

	Ok(handle_general_server_response(&res)?)
}

//__________________________________________________________________________________________________

pub async fn delete_group(base_url: String, auth_token: &str, jwt: &str, group_id: &str, admin_rank: i32) -> VoidRes
{
	sentc_crypto::group::check_group_delete(admin_rank)?;

	let url = base_url + "/api/v1/group/" + group_id;

	let res = make_req(HttpMethod::DELETE, url.as_str(), auth_token, None, Some(jwt)).await?;

	Ok(handle_general_server_response(res.as_str())?)
}

//__________________________________________________________________________________________________

pub(crate) enum SessionKind
{
	Invite,
	Join,
	UserGroup,
}

#[inline(never)]
pub(crate) async fn insert_session_keys(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: &str,
	kind: SessionKind,
	session_id: &str,
	#[cfg(not(feature = "rust"))] user_public_key: &str,
	#[cfg(feature = "rust")] user_public_key: &sentc_crypto_common::user::UserPublicKeyData,
	#[cfg(not(feature = "rust"))] group_keys: &str,
	#[cfg(feature = "rust")] group_keys: &[&sentc_crypto::util::SymKeyFormat],
) -> VoidRes
{
	let input = sentc_crypto::group::prepare_group_keys_for_new_member_via_session(user_public_key, group_keys)?;

	let url = match kind {
		SessionKind::Join => base_url + "/api/v1/group/" + group_id + "/join_req/session/" + session_id,
		SessionKind::Invite => base_url + "/api/v1/group/" + group_id + "/invite/session/" + session_id,
		SessionKind::UserGroup => base_url + "/api/v1/user/user_keys/session/" + session_id,
	};

	let res = make_req(HttpMethod::PUT, url.as_str(), auth_token, Some(input), Some(jwt)).await?;

	Ok(handle_general_server_response(res.as_str())?)
}

//__________________________________________________________________________________________________
