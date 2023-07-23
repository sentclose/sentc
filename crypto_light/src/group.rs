use alloc::string::{String, ToString};

use sentc_crypto_common::group::{GroupChangeRankServerInput, GroupLightServerData, GroupUserAccessBy};
use sentc_crypto_common::GroupId;
use sentc_crypto_utils::group::GroupOutDataLight;
use sentc_crypto_utils::handle_server_response;

use crate::error::SdkLightError;

#[cfg(not(feature = "rust"))]
pub fn get_group_light_data(server_output: &str) -> Result<sentc_crypto_utils::group::GroupOutDataLightExport, String>
{
	let out = get_group_light_data_internally(server_output)?;

	Ok(out.into())
}

#[cfg(feature = "rust")]
pub fn get_group_light_data(server_output: &str) -> Result<GroupOutDataLight, SdkLightError>
{
	get_group_light_data_internally(server_output)
}

fn get_access_by(access_by: GroupUserAccessBy) -> (Option<GroupId>, Option<GroupId>)
{
	match access_by {
		GroupUserAccessBy::User => (None, None),
		GroupUserAccessBy::Parent(id) => (None, Some(id)),
		GroupUserAccessBy::GroupAsUser(id) => (Some(id), None),
		GroupUserAccessBy::GroupAsUserAsParent {
			parent,
			group_as_user,
		} => (Some(group_as_user), Some(parent)),
	}
}

fn get_group_light_data_internally(server_output: &str) -> Result<GroupOutDataLight, SdkLightError>
{
	let server_output: GroupLightServerData = handle_server_response(server_output)?;

	let (access_by_group_as_member, access_by_parent_group) = get_access_by(server_output.access_by);

	Ok(GroupOutDataLight {
		group_id: server_output.group_id,
		parent_group_id: server_output.parent_group_id,
		rank: server_output.rank,
		created_time: server_output.created_time,
		joined_time: server_output.joined_time,
		is_connected_group: server_output.is_connected_group,
		access_by_group_as_member,
		access_by_parent_group,
	})
}

//__________________________________________________________________________________________________

#[cfg(not(feature = "rust"))]
pub fn prepare_change_rank(user_id: &str, new_rank: i32, admin_rank: i32) -> Result<String, String>
{
	Ok(prepare_change_rank_internally(user_id, new_rank, admin_rank)?)
}

#[cfg(feature = "rust")]
pub fn prepare_change_rank(user_id: &str, new_rank: i32, admin_rank: i32) -> Result<String, SdkError>
{
	prepare_change_rank_internally(user_id, new_rank, admin_rank)
}

fn prepare_change_rank_internally(user_id: &str, new_rank: i32, admin_rank: i32) -> Result<String, SdkLightError>
{
	#[allow(clippy::manual_range_contains)]
	if new_rank < 1 || new_rank > 4 {
		return Err(SdkLightError::GroupRank);
	}

	if admin_rank > 1 {
		return Err(SdkLightError::GroupPermission);
	}

	GroupChangeRankServerInput {
		changed_user_id: user_id.to_string(),
		new_rank,
	}
	.to_string()
	.map_err(|_| SdkLightError::JsonToStringFailed)
}
