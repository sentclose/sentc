#![allow(clippy::too_many_arguments)]

use alloc::string::String;

use sentc_crypto_common::UserId;
use sentc_crypto_std_keys::util::{PublicKey, SignKey, SymmetricKey};

use crate::group::{get_done_key_rotation_server_input, prepare_prepare_group_keys_for_new_member};
use crate::keys::std::StdGroup;

pub async fn create(base_url: String, auth_token: &str, jwt: &str, creators_public_key: &str, group_as_member: Option<&str>)
	-> Result<String, String>
{
	let key: PublicKey = creators_public_key.parse()?;

	Ok(StdGroup::create(base_url, auth_token, jwt, &key, group_as_member).await?)
}

pub async fn create_child_group(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	parent_group_id: &str,
	admin_rank: i32,
	parent_public_key: &str,
	group_as_member: Option<&str>,
) -> Result<String, String>
{
	let key: PublicKey = parent_public_key.parse()?;

	Ok(StdGroup::create_child_group(
		base_url,
		auth_token,
		jwt,
		parent_group_id,
		admin_rank,
		&key,
		group_as_member,
	)
	.await?)
}

pub async fn create_connected_group(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	connected_group_id: &str,
	admin_rank: i32,
	parent_public_key: &str,
	group_as_member: Option<&str>,
) -> Result<String, String>
{
	let key: PublicKey = parent_public_key.parse()?;

	Ok(StdGroup::create_connected_group(
		base_url,
		auth_token,
		jwt,
		connected_group_id,
		admin_rank,
		&key,
		group_as_member,
	)
	.await?)
}

//__________________________________________________________________________________________________

pub async fn key_rotation(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: &str,
	public_key: &str,
	pre_group_key: &str,
	user_group: bool,
	sign_key: Option<&str>,
	starter: UserId,
	group_as_member: Option<&str>,
) -> Result<String, String>
{
	let sign_key: Option<SignKey> = if let Some(k) = sign_key { Some(k.parse()?) } else { None };
	let previous_group_key: SymmetricKey = pre_group_key.parse()?;
	let invoker_public_key: PublicKey = public_key.parse()?;

	Ok(StdGroup::key_rotation_req(
		base_url,
		auth_token,
		jwt,
		group_id,
		&invoker_public_key,
		&previous_group_key,
		user_group,
		sign_key.as_ref(),
		starter,
		group_as_member,
	)
	.await?)
}

pub async fn done_key_rotation(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: &str,
	server_output: &str,
	pre_group_key: &str,
	public_key: &str,
	private_key: &str,
	user_group: bool,
	verify_key: Option<&str>,
	group_as_member: Option<&str>,
) -> Result<(), String>
{
	let server_output = get_done_key_rotation_server_input(server_output)?;

	let (verify_key, private_key, public_key, previous_group_key) =
		crate::group::prepare_done_key_rotation(private_key, public_key, pre_group_key, verify_key)?;

	Ok(StdGroup::done_key_rotation_req(
		base_url,
		auth_token,
		jwt,
		group_id,
		server_output,
		&previous_group_key,
		&public_key,
		&private_key,
		user_group,
		verify_key.as_ref(),
		group_as_member,
	)
	.await?)
}

//__________________________________________________________________________________________________

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
	user_public_key: &str,
	group_keys: &str,
	group_as_member: Option<&str>,
) -> Result<Option<String>, String>
{
	prepare_prepare_group_keys_for_new_member!(
		user_public_key,
		group_keys,
		|requester_public_key, split_group_keys| {
			Ok(StdGroup::invite_user(
				base_url,
				auth_token,
				jwt,
				id,
				user_to_invite_id,
				key_count,
				rank,
				admin_rank,
				auto_invite,
				group_invite,
				re_invite,
				&requester_public_key,
				&split_group_keys,
				group_as_member,
			)
			.await?)
		}
	)
}

pub async fn invite_user_session(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: &str,
	session_id: &str,
	auto: bool,
	user_public_key: &str,
	group_keys: &str,
	group_as_member: Option<&str>,
) -> Result<(), String>
{
	prepare_prepare_group_keys_for_new_member!(
		user_public_key,
		group_keys,
		|requester_public_key, split_group_keys| {
			Ok(StdGroup::invite_user_session(
				base_url,
				auth_token,
				jwt,
				group_id,
				session_id,
				auto,
				&requester_public_key,
				&split_group_keys,
				group_as_member,
			)
			.await?)
		}
	)
}

//__________________________________________________________________________________________________

pub async fn accept_join_req(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: &str,
	user_id: &str,
	key_count: i32,
	rank: Option<i32>,
	admin_rank: i32,
	user_public_key: &str,
	group_keys: &str,
	group_as_member: Option<&str>,
) -> Result<Option<String>, String>
{
	prepare_prepare_group_keys_for_new_member!(
		user_public_key,
		group_keys,
		|requester_public_key, split_group_keys| {
			Ok(StdGroup::accept_join_req(
				base_url,
				auth_token,
				jwt,
				group_id,
				user_id,
				key_count,
				rank,
				admin_rank,
				&requester_public_key,
				&split_group_keys,
				group_as_member,
			)
			.await?)
		}
	)
}

pub async fn join_user_session(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	group_id: &str,
	session_id: &str,
	user_public_key: &str,
	group_keys: &str,
	group_as_member: Option<&str>,
) -> Result<(), String>
{
	prepare_prepare_group_keys_for_new_member!(
		user_public_key,
		group_keys,
		|requester_public_key, split_group_keys| {
			Ok(StdGroup::join_user_session(
				base_url,
				auth_token,
				jwt,
				group_id,
				session_id,
				&requester_public_key,
				&split_group_keys,
				group_as_member,
			)
			.await?)
		}
	)
}
