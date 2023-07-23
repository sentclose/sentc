use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::group::{GroupInviteReqList, GroupJoinReqList, GroupUserListItem};
use sentc_crypto_utils::group::GroupOutDataLightExport;

pub type Res = Result<String, String>;
pub type VoidRes = Result<(), String>;
pub type DataRes = Result<GroupOutDataLightExport, String>;
pub type MemberRes = Result<Vec<GroupUserListItem>, String>;
pub type UserUpdateCheckRes = Result<i32, String>;
pub type InviteListRes = Result<Vec<GroupInviteReqList>, String>;
pub type JoinReqListRes = Result<Vec<GroupJoinReqList>, String>;
