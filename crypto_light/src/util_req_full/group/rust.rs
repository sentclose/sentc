use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::group::{GroupChildrenList, GroupInviteReqList, GroupJoinReqList, GroupUserListItem, ListGroups};
use sentc_crypto_utils::group::GroupOutDataLight;

use crate::error::SdkLightError;

pub type Res = Result<String, SdkLightError>;
pub type VoidRes = Result<(), SdkLightError>;
pub type DataRes = Result<GroupOutDataLight, SdkLightError>;
pub type MemberRes = Result<Vec<GroupUserListItem>, SdkLightError>;
pub type UserUpdateCheckRes = Result<i32, SdkLightError>;
pub type InviteListRes = Result<Vec<GroupInviteReqList>, SdkLightError>;
pub type JoinReqListRes = Result<Vec<GroupJoinReqList>, SdkLightError>;
pub type GroupListRes = Result<Vec<ListGroups>, SdkLightError>;
pub type ChildrenRes = Result<Vec<GroupChildrenList>, SdkLightError>;
