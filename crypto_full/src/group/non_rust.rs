use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto::group::{GroupKeyData, GroupOutData};
use sentc_crypto_common::group::{GroupInviteReqList, GroupJoinReqList};
use serde::{Deserialize, Serialize};

pub type Res = Result<String, String>;
pub type VoidRes = Result<(), String>;
pub type DataRes = Result<GroupOutData, String>;
pub type KeyRes = Result<Vec<GroupKeyData>, String>;
pub type SessionRes = Result<Option<String>, String>;
pub type InviteListRes = Result<Vec<GroupInviteReqList>, String>;
pub type JoinReqListRes = Result<Vec<GroupJoinReqList>, String>;
pub type KeyRotationRes = Result<Vec<KeyRotationGetOut>, String>;

#[derive(Serialize, Deserialize)]
pub struct KeyRotationGetOut
{
	pub pre_group_key_id: String,
	pub server_output: String,
}
