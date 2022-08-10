#[cfg(not(feature = "rust"))]
mod non_rust;
#[cfg(feature = "rust")]
mod rust;

use alloc::string::String;
use alloc::vec::Vec;
use core::future::Future;

use sentc_crypto::util::public::{handle_general_server_response, handle_server_response};
use sentc_crypto_common::group::{GroupAcceptJoinReqServerOutput, GroupCreateOutput, GroupInviteReqList, GroupInviteServerOutput, GroupJoinReqList};

#[cfg(not(feature = "rust"))]
pub(crate) use self::non_rust::{DataRes, InviteListRes, JoinReqListRes, KeyRes, Res, SessionRes, VoidRes};
#[cfg(feature = "rust")]
pub(crate) use self::rust::{DataRes, InviteListRes, JoinReqListRes, KeyRes, Res, SessionRes, VoidRes};
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

pub async fn create_child_group<'a>(
	base_url: String,
	auth_token: &'a str,
	jwt: &'a str,
	parent_group_id: &'a str,
	#[cfg(not(feature = "rust"))] parent_public_key: &'a str,
	#[cfg(feature = "rust")] parent_public_key: &'a sentc_crypto::util::PublicKeyFormat,
) -> impl Future<Output = Res> + 'a
{
	create_group(base_url, auth_token, jwt, Some(parent_group_id), parent_public_key)
}

//__________________________________________________________________________________________________

pub async fn get_group(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	#[cfg(not(feature = "rust"))] private_key: &str,
	#[cfg(feature = "rust")] private_key: &sentc_crypto::util::PrivateKeyFormat,
) -> DataRes
{
	let url = base_url + "/api/v1/group/" + id;

	let res = make_req(HttpMethod::GET, url.as_str(), auth_token, None, Some(jwt)).await?;

	let out = sentc_crypto::group::get_group_data(private_key, res.as_str())?;

	Ok(out)
}

pub async fn get_group_keys(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	last_fetched_time: &str,
	last_fetched_key_id: &str,
	#[cfg(not(feature = "rust"))] private_key: &str,
	#[cfg(feature = "rust")] private_key: &sentc_crypto::util::PrivateKeyFormat,
) -> KeyRes
{
	let url = base_url + "/api/v1/group/" + id + "/keys" + last_fetched_time + "/" + last_fetched_key_id;

	let res = make_req(HttpMethod::GET, url.as_str(), auth_token, None, Some(jwt)).await?;

	let group_keys = sentc_crypto::group::get_group_keys_from_pagination(private_key, res.as_str())?;

	Ok(group_keys)
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
	#[cfg(not(feature = "rust"))] user_public_key: &str,
	#[cfg(feature = "rust")] user_public_key: &sentc_crypto_common::user::UserPublicKeyData,
	#[cfg(not(feature = "rust"))] group_keys: &str,
	#[cfg(feature = "rust")] group_keys: &[&sentc_crypto::util::SymKeyFormat],
) -> SessionRes
{
	let url = base_url + "/api/v1/group/" + id + "/invite/" + user_to_invite_id;

	let key_session = if key_count > 50 { true } else { false };

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
		SessionKind::Invite,
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

	#[cfg(not(feature = "rust"))]
	let invites = serde_json::to_string(&invites).map_err(|_| sentc_crypto::SdkError::JsonToStringFailed)?;

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
	last_fetched_time: &str,
	last_fetched_id: &str,
) -> JoinReqListRes
{
	let url = base_url + "/api/v1/group/" + group_id + "/join_req/" + last_fetched_time + "/" + last_fetched_id;

	let res = make_req(HttpMethod::GET, url.as_str(), auth_token, None, Some(jwt)).await?;

	let join_reqs: Vec<GroupJoinReqList> = handle_server_response(res.as_str())?;

	#[cfg(not(feature = "rust"))]
	let join_reqs = serde_json::to_string(&join_reqs).map_err(|_| sentc_crypto::SdkError::JsonToStringFailed)?;

	Ok(join_reqs)
}

pub async fn reject_join_req(base_url: String, auth_token: &str, jwt: &str, group_id: &str, rejected_user_id: &str) -> VoidRes
{
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
	#[cfg(not(feature = "rust"))] user_public_key: &str,
	#[cfg(feature = "rust")] user_public_key: &sentc_crypto_common::user::UserPublicKeyData,
	#[cfg(not(feature = "rust"))] group_keys: &str,
	#[cfg(feature = "rust")] group_keys: &[&sentc_crypto::util::SymKeyFormat],
) -> SessionRes
{
	let url = base_url + "/api/v1/group/" + group_id + "/join_req/" + user_id;

	let key_session = if key_count > 50 { true } else { false };

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

//__________________________________________________________________________________________________

pub async fn leave_group(base_url: String, auth_token: &str, jwt: &str, group_id: &str) -> VoidRes
{
	let url = base_url + "/api/v1/group/" + group_id + "/leave";

	let res = make_req(HttpMethod::DELETE, url.as_str(), auth_token, None, Some(jwt)).await?;

	Ok(handle_general_server_response(res.as_str())?)
}

//__________________________________________________________________________________________________

enum SessionKind
{
	Invite,
	Join,
}

async fn insert_session_keys(
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
	};

	let res = make_req(HttpMethod::PUT, url.as_str(), auth_token, Some(input), Some(jwt)).await?;

	Ok(handle_general_server_response(res.as_str())?)
}

//__________________________________________________________________________________________________
