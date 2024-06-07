use alloc::string::String;

use sentc_crypto_common::group::GroupUserAccessBy;
use sentc_crypto_common::GroupId;
use serde::{Deserialize, Serialize};

pub fn get_access_by(access_by: GroupUserAccessBy) -> (Option<GroupId>, Option<GroupId>)
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

pub struct GroupOutDataLight
{
	pub group_id: GroupId,
	pub parent_group_id: Option<GroupId>,
	pub rank: i32,
	pub created_time: u128,
	pub joined_time: u128,
	pub access_by_group_as_member: Option<GroupId>,
	pub access_by_parent_group: Option<GroupId>,
	pub is_connected_group: bool,
}

//__________________________________________________________________________________________________

#[derive(Serialize, Deserialize)]
pub struct GroupOutDataLightExport
{
	pub group_id: String,
	pub parent_group_id: Option<GroupId>,
	pub rank: i32,
	pub created_time: u128,
	pub joined_time: u128,
	pub access_by_group_as_member: Option<GroupId>,
	pub access_by_parent_group: Option<GroupId>,
	pub is_connected_group: bool,
}

impl From<GroupOutDataLight> for GroupOutDataLightExport
{
	fn from(value: GroupOutDataLight) -> Self
	{
		Self {
			group_id: value.group_id,
			parent_group_id: value.parent_group_id,
			rank: value.rank,
			created_time: value.created_time,
			joined_time: value.joined_time,
			access_by_group_as_member: value.access_by_group_as_member,
			access_by_parent_group: value.access_by_parent_group,
			is_connected_group: value.is_connected_group,
		}
	}
}
