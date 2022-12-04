use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto::group::{GroupKeyData, GroupOutData, GroupOutDataLight};
use sentc_crypto_common::group::{
	GroupChildrenList,
	GroupDataCheckUpdateServerOutput,
	GroupInviteReqList,
	GroupJoinReqList,
	GroupKeyServerOutput,
	GroupUserListItem,
	KeyRotationInput,
	ListGroups,
};

use crate::error::SdkFullError;

pub type Res = Result<String, SdkFullError>;
pub type VoidRes = Result<(), SdkFullError>;
pub type DataRes = Result<GroupOutData, SdkFullError>;
pub type DataLightRes = Result<GroupOutDataLight, SdkFullError>;
pub type KeyRes = Result<GroupKeyData, SdkFullError>;
pub type KeyFetchRes = Result<Vec<GroupKeyServerOutput>, SdkFullError>;
pub type SingleKeyRes = Result<GroupKeyServerOutput, SdkFullError>;
pub type GroupListRes = Result<Vec<ListGroups>, SdkFullError>;
pub type ChildrenRes = Result<Vec<GroupChildrenList>, SdkFullError>;
pub type SessionRes = Result<Option<String>, SdkFullError>;
pub type InviteListRes = Result<Vec<GroupInviteReqList>, SdkFullError>;
pub type JoinReqListRes = Result<Vec<GroupJoinReqList>, SdkFullError>;
pub type KeyRotationRes = Result<Vec<KeyRotationInput>, SdkFullError>;
pub type MemberRes = Result<Vec<GroupUserListItem>, SdkFullError>;
pub type UserUpdateCheckRes = Result<GroupDataCheckUpdateServerOutput, SdkFullError>;
