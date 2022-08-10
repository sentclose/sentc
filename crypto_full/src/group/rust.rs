use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto::group::{GroupKeyData, GroupOutData};
use sentc_crypto_common::group::{GroupInviteReqList, GroupJoinReqList};

use crate::error::SdkFullError;

pub type Res = Result<String, SdkFullError>;
pub type VoidRes = Result<(), SdkFullError>;
pub type DataRes = Result<GroupOutData, SdkFullError>;
pub type KeyRes = Result<Vec<GroupKeyData>, SdkFullError>;
pub type SessionRes = Result<Option<String>, SdkFullError>;
pub type InviteListRes = Result<Vec<GroupInviteReqList>, SdkFullError>;
pub type JoinReqListRes = Result<Vec<GroupJoinReqList>, SdkFullError>;
