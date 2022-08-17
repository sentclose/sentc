use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto::group::{GroupKeyData, GroupOutData};
use sentc_crypto_common::group::{
	GroupDataCheckUpdateServerOutput,
	GroupInviteReqList,
	GroupJoinReqList,
	GroupKeyServerOutput,
	GroupUserListItem,
	KeyRotationInput,
};

use crate::error::SdkFullError;

pub type Res = Result<String, SdkFullError>;
pub type VoidRes = Result<(), SdkFullError>;
pub type DataRes = Result<GroupOutData, SdkFullError>;
pub type KeyRes = Result<GroupKeyData, SdkFullError>;
pub type KeyFetchRes = Result<Vec<GroupKeyServerOutput>, SdkFullError>;
pub type SessionRes = Result<Option<String>, SdkFullError>;
pub type InviteListRes = Result<Vec<GroupInviteReqList>, SdkFullError>;
pub type JoinReqListRes = Result<Vec<GroupJoinReqList>, SdkFullError>;
pub type KeyRotationRes = Result<Vec<KeyRotationInput>, SdkFullError>;
pub type MemberRes = Result<Vec<GroupUserListItem>, SdkFullError>;
pub type UserUpdateCheckRes = Result<GroupDataCheckUpdateServerOutput, SdkFullError>;
