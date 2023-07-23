use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto::entities::group::{GroupKeyData, GroupOutData, GroupOutDataLight};
use sentc_crypto::SdkError;
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
use sentc_crypto_common::user::UserPublicKeyData;

pub type Res = Result<String, SdkError>;
pub type VoidRes = Result<(), SdkError>;
pub type DataRes = Result<GroupOutData, SdkError>;
pub type DataLightRes = Result<GroupOutDataLight, SdkError>;
pub type KeyRes = Result<GroupKeyData, SdkError>;
pub type KeyFetchRes = Result<Vec<GroupKeyServerOutput>, SdkError>;
pub type SingleKeyRes = Result<GroupKeyServerOutput, SdkError>;
pub type GroupListRes = Result<Vec<ListGroups>, SdkError>;
pub type ChildrenRes = Result<Vec<GroupChildrenList>, SdkError>;
pub type SessionRes = Result<Option<String>, SdkError>;
pub type InviteListRes = Result<Vec<GroupInviteReqList>, SdkError>;
pub type JoinReqListRes = Result<Vec<GroupJoinReqList>, SdkError>;
pub type KeyRotationRes = Result<Vec<KeyRotationInput>, SdkError>;
pub type MemberRes = Result<Vec<GroupUserListItem>, SdkError>;
pub type UserUpdateCheckRes = Result<GroupDataCheckUpdateServerOutput, SdkError>;
pub type UserPublicKeyRes = Result<UserPublicKeyData, SdkError>;
