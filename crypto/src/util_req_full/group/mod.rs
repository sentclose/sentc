#![allow(clippy::too_many_arguments)]

#[cfg(feature = "export")]
mod group_export;
use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "export")]
pub use group_export::*;
use sentc_crypto_common::group::{
	GroupAcceptJoinReqServerOutput,
	GroupChildrenList,
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
use sentc_crypto_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto_common::UserId;
use sentc_crypto_core::cryptomat::{SearchableKeyGen, SortableKeyGen};
use sentc_crypto_utils::cryptomat::{
	PkFromUserKeyWrapper,
	PkWrapper,
	SearchableKeyComposerWrapper,
	SignComposerWrapper,
	SignKeyPairWrapper,
	SkWrapper,
	SortableKeyComposerWrapper,
	StaticKeyComposerWrapper,
	StaticKeyPairWrapper,
	SymKeyComposerWrapper,
	SymKeyGenWrapper,
	SymKeyWrapper,
	VerifyKFromUserKeyWrapper,
};
use sentc_crypto_utils::http::{make_req, HttpMethod};
use sentc_crypto_utils::{handle_general_server_response, handle_server_response};

use crate::group::{
	check_create_sub_group,
	check_delete_user_rank,
	get_group_data,
	get_group_key_from_server_output,
	get_group_keys_from_server_output,
	get_group_light_data,
	Group,
};
use crate::util_req_full::SessionKind;
use crate::SdkError;

impl<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>
	Group<SGen, StGen, SignGen, SearchGen, SortGen, SC, StC, SignC, SearchC, SortC, PC, VC>
where
	SGen: SymKeyGenWrapper,
	StGen: StaticKeyPairWrapper,
	SignGen: SignKeyPairWrapper,
	SearchGen: SearchableKeyGen,
	SortGen: SortableKeyGen,
	SC: SymKeyComposerWrapper,
	StC: StaticKeyComposerWrapper,
	SignC: SignComposerWrapper,
	SearchC: SearchableKeyComposerWrapper,
	SortC: SortableKeyComposerWrapper,
	PC: PkFromUserKeyWrapper,
	VC: VerifyKFromUserKeyWrapper,
{
	async fn create_group(
		base_url: String,
		auth_token: &str,
		jwt: &str,
		parent_group_id: Option<&str>,
		connected_group_id: Option<&str>,
		public_key: &impl PkWrapper,
		group_as_member: Option<&str>,
	) -> Result<String, SdkError>
	{
		let url = match (parent_group_id, connected_group_id) {
			(None, Some(id)) => base_url + "/api/v1/group/" + id + "/connected",
			(Some(id), None) => base_url + "/api/v1/group/" + id + "/child",
			_ => base_url + "/api/v1/group", //(None, None) or both set
		};

		let input = Self::prepare_create(public_key)?;

		let res = make_req(
			HttpMethod::POST,
			url.as_str(),
			auth_token,
			Some(input),
			Some(jwt),
			group_as_member,
		)
		.await?;

		let group_id: GroupCreateOutput = handle_server_response(&res)?;

		Ok(group_id.group_id)
	}

	pub async fn create(
		base_url: String,
		auth_token: &str,
		jwt: &str,
		creators_public_key: &impl PkWrapper,
		group_as_member: Option<&str>,
	) -> Result<String, SdkError>
	{
		Self::create_group(
			base_url,
			auth_token,
			jwt,
			None,
			None,
			creators_public_key,
			group_as_member,
		)
		.await
	}

	pub async fn create_child_group(
		base_url: String,
		auth_token: &str,
		jwt: &str,
		parent_group_id: &str,
		admin_rank: i32,
		parent_public_key: &impl PkWrapper,
		group_as_member: Option<&str>,
	) -> Result<String, SdkError>
	{
		check_create_sub_group(admin_rank)?;

		Self::create_group(
			base_url,
			auth_token,
			jwt,
			Some(parent_group_id),
			None,
			parent_public_key,
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
		parent_public_key: &impl PkWrapper,
		group_as_member: Option<&str>,
	) -> Result<String, SdkError>
	{
		check_create_sub_group(admin_rank)?;

		Self::create_group(
			base_url,
			auth_token,
			jwt,
			None,
			Some(connected_group_id),
			parent_public_key,
			group_as_member,
		)
		.await
	}

	//______________________________________________________________________________________________
	//invite

	pub async fn invite_user(
		base_url: String,
		auth_token: &str,
		jwt: &str,
		id: &str,
		user_to_invite_id: &str,
		key_count: i32,
		rank: Option<i32>,
		admin_rank: i32,
		auto_invite: bool,
		group_invite: bool,
		re_invite: bool,
		user_public_key: &UserPublicKeyData,
		group_keys: &[&impl SymKeyWrapper],
		group_as_member: Option<&str>,
	) -> Result<Option<String>, SdkError>
	{
		crate::group::check_make_invite_req(admin_rank)?;

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

		let url = base_url + "/api/v1/group/" + id + "/" + endpoint + "/" + user_to_invite_id;

		let key_session = key_count > 50;

		let invite = Self::prepare_group_keys_for_new_member(user_public_key, group_keys, key_session, rank)?;

		//insert the invite and check for more keys in the sdk impl and call the other fn!
		let res = make_req(
			HttpMethod::PUT,
			url.as_str(),
			auth_token,
			Some(invite),
			Some(jwt),
			group_as_member,
		)
		.await?;

		let session: GroupInviteServerOutput = handle_server_response(res.as_str())?;

		Ok(session.session_id)
	}

	pub async fn invite_user_session(
		base_url: String,
		auth_token: &str,
		jwt: &str,
		group_id: &str,
		session_id: &str,
		auto: bool,
		user_public_key: &UserPublicKeyData,
		group_keys: &[&impl SymKeyWrapper],
		group_as_member: Option<&str>,
	) -> Result<(), SdkError>
	{
		//use the join session for auto invited user
		let kind = match auto {
			true => SessionKind::Join,
			false => SessionKind::Invite,
		};

		Self::insert_session_keys(
			base_url,
			auth_token,
			jwt,
			group_id,
			kind,
			session_id,
			user_public_key,
			group_keys,
			group_as_member,
		)
		.await
	}

	pub(super) async fn insert_session_keys(
		base_url: String,
		auth_token: &str,
		jwt: &str,
		group_id: &str,
		kind: SessionKind,
		session_id: &str,
		user_public_key: &UserPublicKeyData,
		group_keys: &[&impl SymKeyWrapper],
		group_as_member: Option<&str>,
	) -> Result<(), SdkError>
	{
		let input = Self::prepare_group_keys_for_new_member_via_session(user_public_key, group_keys)?;

		let url = match kind {
			SessionKind::Join => base_url + "/api/v1/group/" + group_id + "/join_req/session/" + session_id,
			SessionKind::Invite => base_url + "/api/v1/group/" + group_id + "/invite/session/" + session_id,
			SessionKind::UserGroup => base_url + "/api/v1/user/user_keys/session/" + session_id,
		};

		let res = make_req(
			HttpMethod::PUT,
			url.as_str(),
			auth_token,
			Some(input),
			Some(jwt),
			group_as_member,
		)
		.await?;

		Ok(handle_general_server_response(res.as_str())?)
	}

	//______________________________________________________________________________________________
	//join req

	pub async fn accept_join_req(
		base_url: String,
		auth_token: &str,
		jwt: &str,
		group_id: &str,
		user_id: &str,
		key_count: i32,
		rank: Option<i32>,
		admin_rank: i32,
		user_public_key: &UserPublicKeyData,
		group_keys: &[&impl SymKeyWrapper],
		group_as_member: Option<&str>,
	) -> Result<Option<String>, SdkError>
	{
		crate::group::check_get_join_reqs(admin_rank)?;

		let url = base_url + "/api/v1/group/" + group_id + "/join_req/" + user_id;

		let key_session = key_count > 50;

		let join = Self::prepare_group_keys_for_new_member(user_public_key, group_keys, key_session, rank)?;

		//insert the invite and check for more keys in the sdk impl and call the other fn!
		let res = make_req(
			HttpMethod::PUT,
			&url,
			auth_token,
			Some(join),
			Some(jwt),
			group_as_member,
		)
		.await?;

		let out: GroupAcceptJoinReqServerOutput = handle_server_response(&res)?;

		Ok(out.session_id)
	}

	pub async fn join_user_session(
		base_url: String,
		auth_token: &str,
		jwt: &str,
		group_id: &str,
		session_id: &str,
		user_public_key: &UserPublicKeyData,
		group_keys: &[&impl SymKeyWrapper],
		group_as_member: Option<&str>,
	) -> Result<(), SdkError>
	{
		Self::insert_session_keys(
			base_url,
			auth_token,
			jwt,
			group_id,
			SessionKind::Join,
			session_id,
			user_public_key,
			group_keys,
			group_as_member,
		)
		.await
	}

	//______________________________________________________________________________________________

	pub async fn key_rotation_req(
		base_url: String,
		auth_token: &str,
		jwt: &str,
		group_id: &str,
		public_key: &impl PkWrapper,
		pre_group_key: &impl SymKeyWrapper,
		user_group: bool,
		sign_key: Option<&SignC::SignKWrapper>,
		starter: UserId,
		group_as_member: Option<&str>,
	) -> Result<String, SdkError>
	{
		let url = match user_group {
			true => base_url + "/api/v1/user/user_keys/rotation",
			false => base_url + "/api/v1/group/" + group_id + "/key_rotation",
		};

		let input = Self::key_rotation(pre_group_key, public_key, user_group, sign_key, starter)?;

		let res = make_req(
			HttpMethod::POST,
			&url,
			auth_token,
			Some(input),
			Some(jwt),
			group_as_member,
		)
		.await?;

		let out: KeyRotationStartServerOutput = handle_server_response(&res)?;

		Ok(out.key_id)
	}

	/**
	Call this fn for each key.

	In two fn because we don't know yet if the user got the pre group key or must fetch it.
	 */
	pub async fn done_key_rotation_req(
		base_url: String,
		auth_token: &str,
		jwt: &str,
		group_id: &str,
		server_output: KeyRotationInput,
		pre_group_key: &impl SymKeyWrapper,
		public_key: &impl PkWrapper,
		private_key: &impl SkWrapper,
		user_group: bool,
		verify_key: Option<&UserVerifyKeyData>,
		group_as_member: Option<&str>,
	) -> Result<(), SdkError>
	{
		let key_id = &server_output.new_group_key_id;

		let url = match user_group {
			false => base_url + "/api/v1/group/" + group_id + "/key_rotation/" + key_id,
			true => base_url + "/api/v1/user/user_keys/rotation/" + key_id,
		};

		let input = Self::done_key_rotation(private_key, public_key, pre_group_key, server_output, verify_key)?;

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
}

//__________________________________________________________________________________________________

#[cfg(feature = "export")]
type DataRes = Result<crate::entities::group::GroupOutDataExport, String>;
#[cfg(not(feature = "export"))]
type DataRes = Result<crate::entities::group::GroupOutData, SdkError>;

#[cfg(feature = "export")]
type DataLightRes = Result<crate::entities::group::GroupOutDataLightExport, String>;
#[cfg(not(feature = "export"))]
pub type DataLightRes = Result<sentc_crypto_utils::group::GroupOutDataLight, SdkError>;

pub async fn get_group(base_url: String, auth_token: &str, jwt: &str, id: &str, group_as_member: Option<&str>) -> DataRes
{
	let url = base_url + "/api/v1/group/" + id;

	let res = make_req(HttpMethod::GET, &url, auth_token, None, Some(jwt), group_as_member).await?;

	get_group_data(&res)
}

pub async fn get_group_light(base_url: String, auth_token: &str, jwt: &str, id: &str, group_as_member: Option<&str>) -> DataLightRes
{
	let url = base_url + "/api/v1/group/" + id + "/light";

	let res = make_req(HttpMethod::GET, &url, auth_token, None, Some(jwt), group_as_member).await?;

	get_group_light_data(&res)
}

//__________________________________________________________________________________________________

#[cfg(feature = "export")]
type KeyFetchRes = crate::entities::group::GroupOutDataKeyExport;

#[cfg(not(feature = "export"))]
type KeyFetchRes = sentc_crypto_common::group::GroupKeyServerOutput;

pub async fn get_group_keys(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	last_fetched_time: &str,
	last_fetched_key_id: &str,
	group_as_member: Option<&str>,
) -> Result<Vec<KeyFetchRes>, SdkError>
{
	let url = base_url + "/api/v1/group/" + id + "/keys/" + last_fetched_time + "/" + last_fetched_key_id;

	let res = make_req(HttpMethod::GET, &url, auth_token, None, Some(jwt), group_as_member).await?;

	get_group_keys_from_server_output(&res)
}

pub async fn get_group_key(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	key_id: &str,
	group_as_member: Option<&str>,
) -> Result<KeyFetchRes, SdkError>
{
	let url = base_url + "/api/v1/group/" + id + "/key/" + key_id;

	let res = make_req(HttpMethod::GET, &url, auth_token, None, Some(jwt), group_as_member).await?;

	get_group_key_from_server_output(&res)
}

//__________________________________________________________________________________________________

pub async fn get_member(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	last_fetched_time: &str,
	last_fetched_id: &str,
	group_as_member: Option<&str>,
) -> Result<Vec<GroupUserListItem>, SdkError>
{
	let url = base_url + "/api/v1/group/" + id + "/member/" + last_fetched_time + "/" + last_fetched_id;

	let res = make_req(HttpMethod::GET, &url, auth_token, None, Some(jwt), group_as_member).await?;

	Ok(handle_server_response(&res)?)
}

pub async fn get_group_updates(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	group_as_member: Option<&str>,
) -> Result<GroupDataCheckUpdateServerOutput, SdkError>
{
	let url = base_url + "/api/v1/group/" + id + "/update_check";

	let res = make_req(HttpMethod::GET, &url, auth_token, None, Some(jwt), group_as_member).await?;

	Ok(handle_server_response(&res)?)
}

pub async fn get_groups_for_user(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	last_fetched_time: &str,
	last_fetched_group_id: &str,
	group_id: Option<&str>,
) -> Result<Vec<ListGroups>, SdkError>
{
	//not needed group as member id because
	// the user can only enter groups which are directly connected to this group not connected by a connected group

	let url = match group_id {
		Some(id) => base_url + "/api/v1/group/" + id + "/all/" + last_fetched_time + "/" + last_fetched_group_id,
		None => base_url + "/api/v1/group/all/" + last_fetched_time + "/" + last_fetched_group_id,
	};

	let res = make_req(HttpMethod::GET, &url, auth_token, None, Some(jwt), None).await?;

	Ok(handle_server_response(&res)?)
}

pub async fn get_all_first_level_children(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: &str,
	last_fetched_time: &str,
	last_fetched_group_id: &str,
	group_as_member: Option<&str>,
) -> Result<Vec<GroupChildrenList>, SdkError>
{
	let url = base_url + "/api/v1/group/" + group_id + "/children/" + last_fetched_time + "/" + last_fetched_group_id;

	let res = make_req(HttpMethod::GET, &url, auth_token, None, Some(jwt), group_as_member).await?;

	Ok(handle_server_response(&res)?)
}

//__________________________________________________________________________________________________

pub async fn get_invites_for_user(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	last_fetched_time: &str,
	last_fetched_group_id: &str,
	group_id: Option<&str>,
	group_as_member: Option<&str>,
) -> Result<Vec<GroupInviteReqList>, SdkError>
{
	//get invites for user and group as member

	let url = match group_id {
		Some(id) => base_url + "/api/v1/group/" + id + "/invite/" + last_fetched_time + "/" + last_fetched_group_id,
		None => base_url + "/api/v1/group/invite/" + last_fetched_time + "/" + last_fetched_group_id,
	};

	let res = make_req(HttpMethod::GET, &url, auth_token, None, Some(jwt), group_as_member).await?;

	Ok(handle_server_response(&res)?)
}

pub async fn accept_invite(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id_to_accept: &str,
	group_id: Option<&str>,
	group_as_member: Option<&str>,
) -> Result<(), SdkError>
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
) -> Result<(), SdkError>
{
	let url = match group_id {
		Some(id) => base_url + "/api/v1/group/" + id + "/" + group_id_to_reject + "/invite",
		None => base_url + "/api/v1/group/" + group_id_to_reject + "/invite",
	};

	let res = make_req(HttpMethod::DELETE, &url, auth_token, None, Some(jwt), group_as_member).await?;

	Ok(handle_general_server_response(&res)?)
}

//__________________________________________________________________________________________________

pub async fn join_req(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id_to_join: &str,
	group_id: Option<&str>,
	group_as_member: Option<&str>,
) -> Result<(), SdkError>
{
	let url = match group_id {
		Some(id) => base_url + "/api/v1/group/" + id + "/join_req/" + group_id_to_join,
		None => base_url + "/api/v1/group/" + group_id_to_join + "/join_req",
	};

	let res = make_req(HttpMethod::PATCH, &url, auth_token, None, Some(jwt), group_as_member).await?;

	Ok(handle_general_server_response(&res)?)
}

pub async fn get_join_reqs(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: &str,
	admin_rank: i32,
	last_fetched_time: &str,
	last_fetched_id: &str,
	group_as_member: Option<&str>,
) -> Result<Vec<GroupJoinReqList>, SdkError>
{
	crate::group::check_get_join_reqs(admin_rank)?;

	let url = base_url + "/api/v1/group/" + group_id + "/join_req/" + last_fetched_time + "/" + last_fetched_id;

	let res = make_req(HttpMethod::GET, &url, auth_token, None, Some(jwt), group_as_member).await?;

	Ok(handle_server_response(&res)?)
}

pub async fn reject_join_req(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: &str,
	admin_rank: i32,
	rejected_user_id: &str,
	group_as_member: Option<&str>,
) -> Result<(), SdkError>
{
	crate::group::check_get_join_reqs(admin_rank)?;

	let url = base_url + "/api/v1/group/" + group_id + "/join_req/" + rejected_user_id;

	let res = make_req(HttpMethod::DELETE, &url, auth_token, None, Some(jwt), group_as_member).await?;

	Ok(handle_general_server_response(&res)?)
}

pub async fn stop_group_invites(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: &str,
	admin_rank: i32,
	group_as_member: Option<&str>,
) -> Result<(), SdkError>
{
	check_create_sub_group(admin_rank)?;

	let url = base_url + "/api/v1/group/" + group_id + "/change_invite";

	let res = make_req(HttpMethod::PATCH, &url, auth_token, None, Some(jwt), group_as_member).await?;

	Ok(handle_general_server_response(&res)?)
}

//__________________________________________________________________________________________________

pub async fn leave_group(base_url: String, auth_token: &str, jwt: &str, group_id: &str, group_as_member: Option<&str>) -> Result<(), SdkError>
{
	let url = base_url + "/api/v1/group/" + group_id + "/leave";

	let res = make_req(HttpMethod::DELETE, &url, auth_token, None, Some(jwt), group_as_member).await?;

	Ok(handle_general_server_response(&res)?)
}

//__________________________________________________________________________________________________

#[cfg(feature = "export")]
pub(super) type KeyRotationRes = Result<Vec<KeyRotationGetOut>, String>;

#[cfg(feature = "export")]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct KeyRotationGetOut
{
	pub pre_group_key_id: String,
	pub new_group_key_id: String,
	pub encrypted_eph_key_key_id: sentc_crypto_common::EncryptionKeyPairId,
	pub server_output: String,

	pub signed_by_user_id: Option<String>,
	pub signed_by_user_sign_key_id: Option<String>,
	pub signed_by_user_sign_key_alg: Option<String>,
}

#[cfg(not(feature = "export"))]
pub(super) type KeyRotationRes = Result<Vec<KeyRotationInput>, SdkError>;

/**
Get the keys for the key rotation for this group

call with this arr the done key rotation fn for each key with the pre group key
 */
pub async fn prepare_done_key_rotation(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: &str,
	user_group: bool,
	group_as_member: Option<&str>,
) -> KeyRotationRes
{
	let url = match user_group {
		true => base_url + "/api/v1/user/user_keys/rotation",
		false => base_url + "/api/v1/group/" + group_id + "/key_rotation",
	};

	let res = make_req(HttpMethod::GET, &url, auth_token, None, Some(jwt), group_as_member).await?;

	let out: Vec<KeyRotationInput> = handle_server_response(&res)?;

	// prepare the keys for done_key_rotation.
	// call for each key the done key rotation fn with the key id and the server output
	#[cfg(feature = "export")]
	let out = {
		let mut out_vec = Vec::with_capacity(out.len());

		for key in out {
			out_vec.push(KeyRotationGetOut {
				server_output: serde_json::to_string(&key).map_err(|_| SdkError::JsonToStringFailed)?,
				pre_group_key_id: key.previous_group_key_id,
				new_group_key_id: key.new_group_key_id,
				encrypted_eph_key_key_id: key.encrypted_eph_key_key_id,

				signed_by_user_id: key.signed_by_user_id,
				signed_by_user_sign_key_id: key.signed_by_user_sign_key_id,
				signed_by_user_sign_key_alg: key.signed_by_user_sign_key_alg,
			});
		}

		out_vec
	};

	Ok(out)
}

//__________________________________________________________________________________________________
//group admin fn

pub async fn update_rank(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: &str,
	user_id: &str,
	rank: i32,
	admin_rank: i32,
	group_as_member: Option<&str>,
) -> Result<(), SdkError>
{
	let url = base_url + "/api/v1/group/" + group_id + "/change_rank";

	let input = crate::group::group::prepare_change_rank(user_id, rank, admin_rank)?;

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
) -> Result<(), SdkError>
{
	let url = base_url + "/api/v1/group/" + group_id + "/kick/" + user_id;

	check_delete_user_rank(admin_rank)?;

	let res = make_req(HttpMethod::DELETE, &url, auth_token, None, Some(jwt), group_as_member).await?;

	Ok(handle_general_server_response(&res)?)
}

pub async fn get_sent_join_req(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: Option<&str>,
	admin_rank: Option<i32>,
	last_fetched_time: &str,
	last_fetched_id: &str,
	group_as_member: Option<&str>,
) -> Result<Vec<GroupInviteReqList>, SdkError>
{
	//the join req the group or user sent

	let url = match (group_id, admin_rank) {
		(Some(id), Some(rank)) => {
			crate::group::check_sent_join_req_list(rank)?;
			base_url + "/api/v1/group/" + id + "/joins/" + last_fetched_time + "/" + last_fetched_id
		},
		_ => base_url + "/api/v1/group/joins/" + last_fetched_time + "/" + last_fetched_id,
	};

	let res = make_req(HttpMethod::GET, &url, auth_token, None, Some(jwt), group_as_member).await?;

	Ok(handle_server_response(&res)?)
}

pub async fn delete_sent_join_req(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: Option<&str>,
	admin_rank: Option<i32>,
	join_req_group_id: &str,
	group_as_member: Option<&str>,
) -> Result<(), SdkError>
{
	let url = match (group_id, admin_rank) {
		(Some(id), Some(rank)) => {
			crate::group::check_sent_join_req_list(rank)?;
			base_url + "/api/v1/group/" + id + "/joins/" + join_req_group_id
		},
		_ => base_url + "/api/v1/group/joins/" + join_req_group_id,
	};

	let res = make_req(HttpMethod::DELETE, &url, auth_token, None, Some(jwt), group_as_member).await?;

	Ok(handle_general_server_response(&res)?)
}

//__________________________________________________________________________________________________

pub async fn delete_group(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: &str,
	admin_rank: i32,
	group_as_member: Option<&str>,
) -> Result<(), SdkError>
{
	crate::group::check_group_delete(admin_rank)?;

	let url = base_url + "/api/v1/group/" + group_id;

	let res = make_req(HttpMethod::DELETE, &url, auth_token, None, Some(jwt), group_as_member).await?;

	Ok(handle_general_server_response(&res)?)
}

//__________________________________________________________________________________________________

#[cfg(feature = "export")]
type UserPublicKeyRes = Result<(String, sentc_crypto_common::EncryptionKeyPairId), String>;

#[cfg(not(feature = "export"))]
type UserPublicKeyRes = Result<UserPublicKeyData, SdkError>;

pub async fn get_public_key_data(base_url: String, auth_token: &str, group_id: &str) -> UserPublicKeyRes
{
	let url = base_url + "/api/v1/group/" + group_id + "/public_key";

	let res = make_req(HttpMethod::GET, &url, auth_token, None, None, None).await?;

	#[cfg(not(feature = "export"))]
	{
		crate::util::public::import_public_key_from_string_into_format(&res)
	}

	#[cfg(feature = "export")]
	{
		let public_data = crate::util::public::import_public_key_from_string_into_export_string(&res)?;
		Ok((public_data.0, public_data.1))
	}
}

//__________________________________________________________________________________________________
