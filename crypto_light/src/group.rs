use alloc::string::{String, ToString};

use sentc_crypto_common::group::{GroupChangeRankServerInput, GroupLightServerData};
use sentc_crypto_utils::group::GroupOutDataLight;
use sentc_crypto_utils::handle_server_response;

use crate::error::SdkLightError;

#[cfg(feature = "export")]
pub fn get_group_light_data(server_output: &str) -> Result<sentc_crypto_utils::group::GroupOutDataLightExport, String>
{
	let out = get_group_light_data_internally(server_output)?;

	Ok(out.into())
}

#[cfg(not(feature = "export"))]
pub fn get_group_light_data(server_output: &str) -> Result<GroupOutDataLight, SdkLightError>
{
	get_group_light_data_internally(server_output)
}

fn get_group_light_data_internally(server_output: &str) -> Result<GroupOutDataLight, SdkLightError>
{
	let server_output: GroupLightServerData = handle_server_response(server_output)?;

	let (access_by_group_as_member, access_by_parent_group) = sentc_crypto_utils::group::get_access_by(server_output.access_by);

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

#[cfg(feature = "export")]
pub fn prepare_change_rank(user_id: &str, new_rank: i32, admin_rank: i32) -> Result<String, String>
{
	Ok(prepare_change_rank_internally(user_id, new_rank, admin_rank)?)
}

#[cfg(not(feature = "export"))]
pub fn prepare_change_rank(user_id: &str, new_rank: i32, admin_rank: i32) -> Result<String, SdkLightError>
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
