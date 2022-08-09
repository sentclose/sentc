#[cfg(not(feature = "rust"))]
mod non_rust;
#[cfg(feature = "rust")]
mod rust;

use alloc::string::String;
use core::future::Future;

use sentc_crypto::util::public::handle_server_response;
use sentc_crypto_common::group::GroupCreateOutput;

#[cfg(not(feature = "rust"))]
pub(crate) use self::non_rust::{BoolRes, DataRes, Res, VoidRes};
#[cfg(feature = "rust")]
pub(crate) use self::rust::{BoolRes, DataRes, Res, VoidRes};
use crate::util::{make_req, HttpMethod};

async fn create_group(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	refresh_token: &str,
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

	let res = make_req(
		HttpMethod::POST,
		url.as_str(),
		auth_token,
		Some(input),
		Some(jwt),
		Some(refresh_token),
	)
	.await?;

	let group_id: GroupCreateOutput = handle_server_response(res.as_str())?;

	Ok(group_id.group_id)
}

pub fn create<'a>(
	base_url: String,
	auth_token: &'a str,
	jwt: &'a str,
	refresh_token: &'a str,
	#[cfg(not(feature = "rust"))] creators_public_key: &'a str,
	#[cfg(feature = "rust")] creators_public_key: &'a sentc_crypto::util::PublicKeyFormat,
) -> impl Future<Output = Res> + 'a
{
	create_group(base_url, auth_token, jwt, refresh_token, None, creators_public_key)
}

pub async fn create_child_group<'a>(
	base_url: String,
	auth_token: &'a str,
	jwt: &'a str,
	refresh_token: &'a str,
	parent_group_id: &'a str,
	#[cfg(not(feature = "rust"))] parent_public_key: &'a str,
	#[cfg(feature = "rust")] parent_public_key: &'a sentc_crypto::util::PublicKeyFormat,
) -> impl Future<Output = Res> + 'a
{
	create_group(
		base_url,
		auth_token,
		jwt,
		refresh_token,
		Some(parent_group_id),
		parent_public_key,
	)
}

pub async fn get_group(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	refresh_token: &str,
	id: &str,
	#[cfg(not(feature = "rust"))] private_key: &str,
	#[cfg(feature = "rust")] private_key: &sentc_crypto::util::PrivateKeyFormat,
) -> DataRes
{
	let url = base_url + "/api/v1/group/" + id;

	let res = make_req(
		HttpMethod::GET,
		url.as_str(),
		auth_token,
		None,
		Some(jwt),
		Some(refresh_token),
	)
	.await?;

	let out = sentc_crypto::group::get_group_data(private_key, res.as_str())?;

	Ok(out)
}
